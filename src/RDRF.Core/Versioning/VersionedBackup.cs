using RDRF.Core.Abstractions;
using RDRF.Core.Logging;
using System.Diagnostics;
using System.IO.Hashing;
using System.Security.Cryptography;
using RDRF.Core.Compression;
using RDRF.Core.Diff;
using RDRF.Core.Encryption;
using RDRF.Core.FragmentEngine;
using RDRF.Core.Index;
using RDRF.Core.DSAA;

namespace RDRF.Core.Versioning;

/// <summary>
/// Incremental versioned backup pipeline: dedup, diff, index merge, optional GC cleanup.
/// Default (gcMode=false) uses real-incremental: each version self-contained, permanent files, independent salt.
/// gcMode=true uses legacy GC: orphan cleanup, SynCVersionHistory, inherited salt.
/// </summary>

public static class VersionedBackup
{
    public static async Task<string> BackupAsync(
        string filePath,
        DSAAAdapter storage,
        byte[] password,
        string userMessage,
        string fssStrategy = "FSS3",
        int fragmentSize = 0,
        string? customName = null,
        List<string>? auxiliaryStrategies = null,
        IProgress<RdrfProgressReport>? progress = null,
        CancellationToken ct = default,
        Func<byte[], DSAAAdapter, byte[], BackupOrchestrator>? orchestratorFactory = null,
        string? compressionMethod = null,
        string? compressionOptions = null,
        bool gcMode = false)
    {
        string? existingFingerprint = FindExistingIndex(storage);

        if (existingFingerprint == null)
            return await FreshBackupAsync(filePath, storage, password, userMessage, fssStrategy, progress, ct, fragmentSize, customName, auxiliaryStrategies, orchestratorFactory, compressionMethod, compressionOptions, gcMode).ConfigureAwait(false);

        return await IncrementalBackupAsync(filePath, storage, existingFingerprint, password, userMessage, fssStrategy, progress, ct, fragmentSize, customName, auxiliaryStrategies, orchestratorFactory, compressionMethod, compressionOptions, gcMode).ConfigureAwait(false);
    }

    private static string? FindExistingIndex(DSAAAdapter storage)
        => storage.FindLatestIndex();

    private static async Task<string> FreshBackupAsync(
        string filePath, DSAAAdapter storage,
        byte[] password, string userMessage, string fssStrategy,
        IProgress<RdrfProgressReport>? progress, CancellationToken ct,
        int fragmentSize = 0, string? customName = null,
        List<string>? auxiliaryStrategies = null,
        Func<byte[], DSAAAdapter, byte[], BackupOrchestrator>? orchestratorFactory = null,
        string? compressionMethod = null,
        string? compressionOptions = null,
        bool gcMode = false)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(Constants.SaltPrefixLength);
        using var orchestrator = orchestratorFactory?.Invoke((byte[])password.Clone(), storage, (byte[])salt.Clone())
            ?? new BackupOrchestrator((byte[])password.Clone(), storage, (byte[])salt.Clone());
        string fingerprint = await orchestrator.BackupFileAsync(filePath, fssStrategy,
            fragmentSize: fragmentSize, customName: customName, auxiliaryStrategies: auxiliaryStrategies,
            progress: progress, cancellationToken: ct,
            compressionMethod: compressionMethod, compressionOptions: compressionOptions).ConfigureAwait(false);

        string filePrefix = customName ?? fingerprint;
        AppendVersionRecord(storage, filePrefix, password, salt, 1, userMessage, string.Empty);
        return filePrefix;
    }

    private static string HashKey(byte[] hash) => Hex.EncodeLower(hash);

private static async Task<string> IncrementalBackupAsync(
    string filePath, DSAAAdapter storage, string prevFingerprint,
    byte[] password, string userMessage, string fssStrategy,
    IProgress<RdrfProgressReport>? progress, CancellationToken ct,
    int fragmentSize = 0, string? customName = null,
    List<string>? auxiliaryStrategies = null,
    Func<byte[], DSAAAdapter, byte[], BackupOrchestrator>? orchestratorFactory = null,
    string? compressionMethod = null,
    string? compressionOptions = null,
    bool gcMode = false)
{
    byte[]? prevIndexBytes = null;
    try { prevIndexBytes = storage.ReadIndex(prevFingerprint); }
    catch (Exception ex) { throw new RdrfException(ErrorCode.IndexCorrupted, $"Previous index not found: {prevFingerprint}", ex); }

    int prevVersion = 0;
    List<VersionRecord>? oldVersions = null;
    List<byte[]>? prevRawHashes = null;
    RdrfIndex? prevIdx = null;
    try
    {
        (_, byte[] prevCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(prevIndexBytes, password);
        prevIdx = IndexManager.DeserializeIndex(prevCbor);
        prevVersion = prevIdx.VersionNumber ?? 0;
        oldVersions = prevIdx.Versions;
        prevRawHashes = prevIdx.RawFragmentHashes;
    }
    catch (Exception ex) { throw new CryptographicException("Failed to decrypt previous index. Wrong password or corrupted backup.", ex); }

    // Load existing dedup map from previous index
    var dedupMap = prevIdx?.DedupMap ?? new Dictionary<string, DedupEntry>();

    byte[] salt;
    if (gcMode)
    {
        salt = new byte[Constants.SaltPrefixLength];
        Buffer.BlockCopy(prevIndexBytes, 0, salt, 0, Constants.SaltPrefixLength);
    }
    else
    {
        salt = RandomNumberGenerator.GetBytes(Constants.SaltPrefixLength);
    }

    // Stream file -> hash(sample) -> split raw + Adler32 fast-check
    int fragSize = Constants.ComputeFragmentSize(new FileInfo(filePath).Length, fragmentSize > 0 ? fragmentSize : null);
    var rawFragments = new List<byte[]>();
    var adler32Sums = new List<uint>();
    string fileFingerprint;
    long newFileSize;

    using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
        FileShare.Read, Math.Clamp(fragSize * 2, 256 * 1024, 2 * 1024 * 1024), FileOptions.SequentialScan | FileOptions.Asynchronous))
    using (var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
    {
        var fragBuf = new byte[fragSize];
        int fragOff = 0;
        long totalRead = 0;
        int bytesRead;
        uint adler = Adler32.Init;

        while ((bytesRead = await fs.ReadAsync(fragBuf.AsMemory(fragOff, fragSize - fragOff), ct).ConfigureAwait(false)) > 0)
        {
            hasher.AppendData(fragBuf.AsSpan(fragOff, bytesRead));
            adler = Adler32.Update(adler, fragBuf.AsSpan(fragOff, bytesRead));
            fragOff += bytesRead;
            totalRead += bytesRead;

            if (fragOff < fragSize)
                continue;

            byte[] frag = new byte[fragSize];
            Buffer.BlockCopy(fragBuf, 0, frag, 0, fragSize);
            rawFragments.Add(frag);
            adler32Sums.Add(adler);
            adler = Adler32.Init;
            fragOff = 0;
        }

        // Last partial fragment
        if (fragOff > 0)
        {
            byte[] frag = new byte[fragOff];
            Buffer.BlockCopy(fragBuf, 0, frag, 0, fragOff);
            rawFragments.Add(frag);
            adler32Sums.Add(adler);
        }

        newFileSize = totalRead;
        fileFingerprint = Hex.EncodeLower(hasher.GetHashAndReset());
    }

    // Same fingerprint -> file unchanged -> just update commit message
    if (prevRawHashes != null && (fileFingerprint == prevFingerprint
        || fileFingerprint == prevIdx?.OriginalHash))
    {
        AppendVersionRecord(storage, prevFingerprint, password, salt, prevVersion + 1, userMessage, string.Empty, oldVersions);
        return prevFingerprint;
    }

    // Compute diff for display (on uncompressed data, sample head only)
    long sampleSize = rawFragments.Count > 0 ? Math.Min(rawFragments[0].Length, 64 * 1024) : 0;
    if (rawFragments.Count == 1 && rawFragments[0].Length <= 256 * 1024)
        sampleSize = 0; // use full data
    byte[] newSample;
    if (sampleSize > 0)
    {
        newSample = new byte[sampleSize];
        Buffer.BlockCopy(rawFragments[0], 0, newSample, 0, (int)sampleSize);
    }
    else
    {
        // Reconstruct full file from fragments for small files
        using var ms = new MemoryStream();
        foreach (var f in rawFragments) ms.Write(f);
        newSample = ms.ToArray();
    }

    byte[] oldData = ReadDecryptedOriginal(storage, prevFingerprint, password, newSample.Length > 256 * 1024 ? 64 * 1024 : newSample.Length);
    var diffResult = new DiffEngine().ComputeDiff(oldData, newSample);

    var fileEntries = new List<FileEntry>
    {
        new FileEntry
        {
            Path = Path.GetFileName(filePath),
            ChangeType = diffResult.IsBinary ? "modified (binary)" : "modified",
            Diff = diffResult.HumanDiff,
        }
    };

    // Compute raw fragment hashes (on UNCOMPRESSED data) — GPU if available, then CPU dedup
    var newRawHashes = new List<byte[]>(rawFragments.Count);
    var sourceVersion = new string?[rawFragments.Count];
    var sourceIndex = new int?[rawFragments.Count];
    bool[] changedFlags = new bool[rawFragments.Count];
    bool anyChanged = false;

    if (RDRF.Core.Device.GpuContext.IsAvailable)
    {
        var gpuHashes = RDRF.Core.Device.GpuHasher.HashXXH128(rawFragments);
        for (int i = 0; i < rawFragments.Count; i++)
        {
            newRawHashes.Add(gpuHashes[i]);

            bool adlerMismatch = prevIdx?.Adler32Sums != null && i < adler32Sums.Count
                && i < prevIdx.Adler32Sums.Count && adler32Sums[i] != prevIdx.Adler32Sums[i];

            if (!adlerMismatch && dedupMap.TryGetValue(HashKey(gpuHashes[i]), out var entry))
            {
                sourceVersion[i] = entry.SourceFingerprint;
                sourceIndex[i] = entry.SourceIndex;
                entry.RefCount++;
                changedFlags[i] = false;
            }
            else
            {
                changedFlags[i] = true;
                anyChanged = true;
            }
        }
    }
    else
    {
        for (int i = 0; i < rawFragments.Count; i++)
        {
            byte[] hash = XxHash128.Hash(rawFragments[i].AsSpan());
            newRawHashes.Add(hash);

            bool adlerMismatch = prevIdx?.Adler32Sums != null && i < adler32Sums.Count
                && i < prevIdx.Adler32Sums.Count && adler32Sums[i] != prevIdx.Adler32Sums[i];

            if (!adlerMismatch && dedupMap.TryGetValue(HashKey(hash), out var entry))
            {
                sourceVersion[i] = entry.SourceFingerprint;
                sourceIndex[i] = entry.SourceIndex;
                entry.RefCount++;
                changedFlags[i] = false;
            }
            else
            {
                changedFlags[i] = true;
                anyChanged = true;
            }
        }
    }

    if (!anyChanged)
    {
        AppendVersionRecord(storage, prevFingerprint, password, salt, prevVersion + 1, userMessage,
            diffResult.HumanDiff, oldVersions, fileEntries);
        return prevFingerprint;
    }

    // Build set of old hash keys for refCount cleanup
    var oldHashKeys = new HashSet<string>();
    if (prevRawHashes != null)
        foreach (var h in prevRawHashes)
            oldHashKeys.Add(HashKey(h));
    var newHashKeys = new HashSet<string>(newRawHashes.Select(HashKey));

    // For 1:1 strategies (FSS1, FSS6.1, FSS6.2), only process changed raw fragments
    bool isOneToOne = fssStrategy == Constants.FssLevel1
        || fssStrategy == Constants.FssLevel61
        || fssStrategy == Constants.FssLevel62;

    if (isOneToOne)
    {
        string actualFingerprint = fileFingerprint;
        string filePrefix = customName ?? actualFingerprint;
        var (aesKey, cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(prevIndexBytes, password);

        using var orchestrator = orchestratorFactory?.Invoke((byte[])password.Clone(), storage, (byte[])salt.Clone())
            ?? new BackupOrchestrator((byte[])password.Clone(), storage, (byte[])salt.Clone());

        // Pass raw fragments directly to BuildChangedFragmentsIndex (compression happens inside)
        var changedRaw = new List<byte[]>();
        var changedIdxMap = new List<int>();
        for (int i = 0; i < rawFragments.Count; i++)
        {
            if (changedFlags[i])
            {
                changedRaw.Add(rawFragments[i]);
                changedIdxMap.Add(i);
            }
        }

        // Update dedup map: add entries for NEW fragments
        for (int i = 0; i < rawFragments.Count; i++)
        {
            if (changedFlags[i])
            {
                string key = HashKey(newRawHashes[i]);
                dedupMap[key] = new DedupEntry
                {
                    SourceFingerprint = filePrefix,
                    SourceIndex = i,
                    RefCount = 1,
                };
            }
        }

        // Decrement refCount for old hashes no longer present (never delete prev version's files)
        foreach (string oldKey in oldHashKeys)
        {
            if (!newHashKeys.Contains(oldKey) && dedupMap.TryGetValue(oldKey, out var entry))
            {
                // Don't delete fragments owned by the version we're replacing - still needed by its index
                if (entry.SourceFingerprint == prevFingerprint) continue;
                entry.RefCount--;
                if (entry.RefCount <= 0)
                {
                    string oldPrefix = entry.SourceFingerprint;
                    string fragName = Frags.FragmentFilename(oldPrefix, entry.SourceIndex);
                    try { storage.DeleteFragment(fragName); } catch { RdrfLogger.Default.Debug("",$"Failed to delete {fragName}"); }
                    dedupMap.Remove(oldKey);
                }
            }
        }

        // Pad raw fragments to fragSize for FSS encode (required equal-size input)
        var paddedFrags = rawFragments.Select(r =>
        {
            byte[] p = new byte[Constants.ComputeFragmentSize(r.Length, null)];
            Buffer.BlockCopy(r, 0, p, 0, Math.Min(r.Length, p.Length));
            return p;
        }).ToList();

        // Build the full index (compression happens inside after FSS/ETN/repair)
        var rawSizes = rawFragments.Select(f => f.Length).ToList();
        await orchestrator.BuildChangedFragmentsIndex(
            paddedFrags, changedRaw, changedIdxMap, changedFlags,
            actualFingerprint, fileFingerprint, Path.GetFileName(filePath),
            newFileSize, fssStrategy, fragmentSize, customName, prevFingerprint,
            prevRawHashes, progress, ct,
            compressionMethod: compressionMethod ?? Constants.CompressionLz4,
            rawFragmentSizes: rawSizes)
            .ConfigureAwait(false);

        // Patch index with correct RawFragmentHashes + OriginalFragmentSizes + SourceVersion
        byte[] newEncIdx = storage.ReadIndex(filePrefix);
        (_, byte[] newCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(newEncIdx, password);
        var newIdx = IndexManager.DeserializeIndex(newCbor);
        newIdx.RawFragmentHashes = newRawHashes;
        newIdx.Adler32Sums = adler32Sums;
        newIdx.OriginalFragmentSizes = rawFragments.Select(f => f.Length).ToList();
        if (newIdx.Fragments != null)
        {
            for (int i = 0; i < newIdx.Fragments.Count && i < rawFragments.Count; i++)
            {
                if (sourceVersion[i] != null)
                {
                    newIdx.Fragments[i].SourceVersion = sourceVersion[i];
                    newIdx.Fragments[i].SourceIndex = sourceIndex[i];
                }
            }
        }
        // DedupMap GC: remove entries no longer referenced by any version
        var gcKeys = dedupMap.Where(kv => kv.Value.RefCount <= 0
            && kv.Value.SourceFingerprint != filePrefix
            && kv.Value.SourceFingerprint != prevFingerprint).Select(kv => kv.Key).ToList();
        foreach (var k in gcKeys) dedupMap.Remove(k);

        newIdx.DedupMap = dedupMap;
        byte[] updatedCbor = IndexManager.SerializeIndex(newIdx);
        byte[] updatedIndex = EncryptionLayer.EncryptIndexWithSaltPrefix(updatedCbor, password, salt);
        storage.WriteIndex(filePrefix, updatedIndex);

        if (gcMode)
        {
            CleanupOrphanedIndexes(storage, filePrefix, prevFingerprint, dedupMap);
            SyncVersionHistory(storage, filePrefix, prevFingerprint, password, salt);
        }

        AppendVersionRecord(storage, filePrefix, password, salt, prevVersion + 1, userMessage,
            diffResult.HumanDiff, oldVersions, fileEntries);
        TouchIndexFile(storage, filePrefix);
        return filePrefix;
    }
    else
    {
        // Cross-encoding strategies: full pipeline (old behavior)
        string actualFingerprint;
        using var orchestrator = orchestratorFactory?.Invoke((byte[])password.Clone(), storage, (byte[])salt.Clone())
            ?? new BackupOrchestrator((byte[])password.Clone(), storage, (byte[])salt.Clone());
        {
            actualFingerprint = await orchestrator.BackupFileAsync(filePath, fssStrategy,
                auxiliaryStrategies, Path.GetFileName(filePath), fragmentSize, customName,
                progress, ct).ConfigureAwait(false);
        }

        string filePrefix = customName ?? actualFingerprint;

        // Apply dedup: mark unchanged fragments as references
        byte[] encIdx = storage.ReadIndex(filePrefix);
        (_, byte[] idxCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encIdx, password);
        var index = IndexManager.DeserializeIndex(idxCbor);
        string prefix = index.CustomName ?? filePrefix;

        for (int i = 0; i < newRawHashes.Count && i < index.Fragments?.Count; i++)
        {
            string key = HashKey(newRawHashes[i]);
            if (dedupMap.TryGetValue(key, out var entry))
            {
                index.Fragments[i].SourceVersion = entry.SourceFingerprint;
                index.Fragments[i].SourceIndex = entry.SourceIndex;
                entry.RefCount++;
                string fragName = Frags.FragmentFilename(prefix, i);
                try { storage.DeleteFragment(fragName); } catch (Exception ex_dd) { RdrfLogger.Default.Debug("",$"Failed to delete {fragName}: {ex_dd.Message}"); }
            }
            else
            {
                dedupMap[key] = new DedupEntry
                {
                    SourceFingerprint = filePrefix,
                    SourceIndex = i,
                    RefCount = 1,
                };
            }
        }

        // Decrement refCount for old hashes no longer present (never delete prev version's files)
        foreach (string oldKey in oldHashKeys)
        {
            if (!newHashKeys.Contains(oldKey) && dedupMap.TryGetValue(oldKey, out var entry))
            {
                if (entry.SourceFingerprint == prevFingerprint) continue;
                entry.RefCount--;
                if (entry.RefCount <= 0)
                {
                    string oldPrefix = entry.SourceFingerprint;
                    string fragName = Frags.FragmentFilename(oldPrefix, entry.SourceIndex);
                    try { storage.DeleteFragment(fragName); } catch (Exception ex_dd) { RdrfLogger.Default.Debug("",$"Failed to delete {fragName}: {ex_dd.Message}"); }
                    dedupMap.Remove(oldKey);
                }
            }
        }

        // DedupMap GC: remove entries no longer referenced by any version
        var gcKeys = dedupMap.Where(kv => kv.Value.RefCount <= 0
            && kv.Value.SourceFingerprint != filePrefix
            && kv.Value.SourceFingerprint != prevFingerprint).Select(kv => kv.Key).ToList();
        foreach (var k in gcKeys) dedupMap.Remove(k);

        index.DedupMap = dedupMap;
        byte[] finalCbor = IndexManager.SerializeIndex(index);
        byte[] finalIndex = EncryptionLayer.EncryptIndexWithSaltPrefix(finalCbor, password, salt);
        storage.WriteIndex(filePrefix, finalIndex);

        if (gcMode)
        {
            CleanupOrphanedIndexes(storage, filePrefix, prevFingerprint, dedupMap);
            SyncVersionHistory(storage, filePrefix, prevFingerprint, password, salt);
        }

        AppendVersionRecord(storage, filePrefix, password, salt, prevVersion + 1, userMessage,
            diffResult.HumanDiff, oldVersions, fileEntries);
        TouchIndexFile(storage, filePrefix);
        return filePrefix;
    }
}

    private static void TouchIndexFile(DSAAAdapter storage, string fingerprint)
    {
        if (storage is LocalDSAAAdapter local)
        {
            string path = Path.Combine(local.GetBasePath(), fingerprint + Constants.IndexFileSuffix);
            if (File.Exists(path))
                File.SetLastWriteTime(path, DateTime.Now);
        }
    }

    private static void CleanupOrphanedIndexes(DSAAAdapter storage, string currentFp, string prevFp, Dictionary<string, DedupEntry> dedupMap)
    {
        if (storage is not LocalDSAAAdapter local) return;
        string dir = local.GetBasePath();
        if (!Directory.Exists(dir)) return;

        var referenced = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { currentFp, prevFp };
        foreach (var entry in dedupMap.Values)
            referenced.Add(entry.SourceFingerprint);

        foreach (string f in Directory.GetFiles(dir, "*" + Constants.IndexFileSuffix))
        {
            string fp = Path.GetFileNameWithoutExtension(f);
            if (!referenced.Contains(fp))
            {
                try { File.Delete(f); } catch (Exception ex_gc) { RdrfLogger.Default.Debug("",$"Failed to delete orphaned index {f}: {ex_gc.Message}"); }
            }
        }
    }

    private static byte[] ReadDecryptedOriginal(DSAAAdapter storage, string fingerprint,
        byte[] password, long sampleSize = 0)
    {
        byte[] encryptedIndex = storage.ReadIndex(fingerprint);
        (byte[] aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
        var index = IndexManager.DeserializeIndex(cbor);
        string prefix = index.CustomName ?? fingerprint;

        int fragCount = index.FragmentCount;
        int origCount = index.OriginalFragmentCount > 0 ? index.OriginalFragmentCount : fragCount;

        int fragsToRead = fragCount;
        if (sampleSize > 0)
        {
            long total = 0;
            for (int i = 0; i < origCount && i < (index.OriginalFragmentSizes?.Count ?? 0); i++)
            {
                total += index.OriginalFragmentSizes[i];
                if (total >= sampleSize) { fragsToRead = i + 1; break; }
            }
            if (fragsToRead < fragCount)
                fragsToRead = Math.Min(fragCount, fragsToRead + 1);
        }

        var sourcePrefixes = new Dictionary<string, string>();
        var rawFragments = new List<byte[]>(fragsToRead);
        for (int i = 0; i < fragsToRead; i++)
        {
            string svFp = fingerprint;
            int svIdx = i;
            if (index.Fragments?.Count > i && index.Fragments[i].SourceVersion != null)
            {
                svFp = index.Fragments[i].SourceVersion;
                svIdx = index.Fragments[i].SourceIndex ?? i;
            }
            string svPrefix;
            if (svFp != fingerprint && !sourcePrefixes.TryGetValue(svFp, out svPrefix))
            {
                var srcIdx = storage.ReadIndex(svFp);
                (_, var srcCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(srcIdx, password);
                var srcIndex = IndexManager.DeserializeIndex(srcCbor);
                svPrefix = srcIndex.CustomName ?? svFp;
                sourcePrefixes[svFp] = svPrefix;
            }
            else
            {
                svPrefix = svFp == fingerprint ? prefix : sourcePrefixes[svFp];
            }
            string fragName = FragmentEngine.Frags.FragmentFilename(svPrefix, svIdx);
            byte[] encrypted = storage.ReadFragment(fragName);
            byte[] raw = EncryptionLayer.DecryptAndStripFragment(encrypted, aesKey);
            if (!string.IsNullOrEmpty(index.Compression))
                raw = Compressor.Decompress(raw, index.Compression);
            rawFragments.Add(raw);
        }

        var fssEngine = new FSS.FSSEngine();
        var decoded = new Dictionary<int, byte[]>();
        for (int i = 0; i < origCount && i < rawFragments.Count; i++)
            decoded[i] = rawFragments[i];

        var stripped = fssEngine.Strip(decoded, index.FssStrategy, origCount, index.OriginalFragmentSizes);
        byte[] result = FragmentEngine.Frags.MergeFragments(stripped);

        if (sampleSize > 0 && result.Length > sampleSize)
            return result.AsSpan(0, (int)sampleSize).ToArray();
        return result;
    }

    private static void AppendVersionRecord(
        DSAAAdapter storage, string fingerprint, byte[] password, byte[] salt,
        int versionNumber, string userMessage, string systemDiff,
        List<VersionRecord>? existingVersions = null,
        List<FileEntry>? fileEntries = null)
    {
        byte[] encryptedIndex = storage.ReadIndex(fingerprint);
        (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
        var index = IndexManager.DeserializeIndex(cbor);

        var existing = existingVersions != null
            ? new List<VersionRecord>(existingVersions)
            : new List<VersionRecord>();

        existing.Add(new VersionRecord
        {
            Version = versionNumber,
            UserMessage = userMessage,
            SystemDiff = systemDiff,
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            FileFingerprint = fingerprint,
            Salt = (byte[])salt.Clone(),
            Files = fileEntries,
        });

        index.VersionNumber = versionNumber;
        index.Versions = existing;

        byte[] newCbor = IndexManager.SerializeIndex(index);
        byte[] saltedIndex = EncryptionLayer.EncryptIndexWithSaltPrefix(newCbor, password, salt);
        storage.WriteIndex(fingerprint, saltedIndex);
    }

    private static void SyncVersionHistory(DSAAAdapter storage, string sourceFp, string targetFp,
        byte[] password, byte[] salt)
    {
        if (string.Equals(sourceFp, targetFp, StringComparison.OrdinalIgnoreCase)) return;
        try
        {
            byte[] srcEnc = storage.ReadIndex(sourceFp);
            (_, byte[] srcCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(srcEnc, password);
            var srcIdx = IndexManager.DeserializeIndex(srcCbor);
            if (srcIdx.Versions == null || srcIdx.Versions.Count == 0) return;

            byte[] tgtEnc = storage.ReadIndex(targetFp);
            byte[] tgtSalt = tgtEnc.AsSpan(0, Constants.SaltPrefixLength).ToArray();
            (_, byte[] tgtCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(tgtEnc, password);
            var tgtIdx = IndexManager.DeserializeIndex(tgtCbor);

            tgtIdx.VersionNumber = srcIdx.VersionNumber;
            tgtIdx.Versions = srcIdx.Versions;

            byte[] newCbor = IndexManager.SerializeIndex(tgtIdx);
            byte[] saltedIndex = EncryptionLayer.EncryptIndexWithSaltPrefix(newCbor, password, tgtSalt);
            storage.WriteIndex(targetFp, saltedIndex);
        }
        catch { /* non-critical: old index may already be cleaned up */ }
    }
}




