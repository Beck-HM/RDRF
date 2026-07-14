using RDRF.Core.Abstractions;
using RDRF.Core.Logging;using System.Diagnostics;
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
/// Incremental versioned backup pipeline: dedup, diff, index merge, refCount GC, orphan cleanup.
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
        Func<byte[], DSAAAdapter, byte[], BackupOrchestrator>? orchestratorFactory = null)
    {
        string? existingFingerprint = FindExistingIndex(storage);

        if (existingFingerprint == null)
            return await FreshBackupAsync(filePath, storage, password, userMessage, fssStrategy, progress, ct, fragmentSize, customName, auxiliaryStrategies, orchestratorFactory).ConfigureAwait(false);

        return await IncrementalBackupAsync(filePath, storage, existingFingerprint, password, userMessage, fssStrategy, progress, ct, fragmentSize, customName, auxiliaryStrategies, orchestratorFactory).ConfigureAwait(false);
    }

    private static string? FindExistingIndex(DSAAAdapter storage)
        => storage.FindLatestIndex();

    private static async Task<string> FreshBackupAsync(
        string filePath, DSAAAdapter storage,
        byte[] password, string userMessage, string fssStrategy,
        IProgress<RdrfProgressReport>? progress, CancellationToken ct,
        int fragmentSize = 0, string? customName = null,
        List<string>? auxiliaryStrategies = null,
        Func<byte[], DSAAAdapter, byte[], BackupOrchestrator>? orchestratorFactory = null)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(Constants.SaltPrefixLength);
        using var orchestrator = orchestratorFactory?.Invoke((byte[])password.Clone(), storage, (byte[])salt.Clone())
            ?? new BackupOrchestrator((byte[])password.Clone(), storage, (byte[])salt.Clone());
        string fingerprint = await orchestrator.BackupFileAsync(filePath, fssStrategy,
            fragmentSize: fragmentSize, customName: customName, auxiliaryStrategies: auxiliaryStrategies,
            progress: progress, cancellationToken: ct).ConfigureAwait(false);

        AppendVersionRecord(storage, fingerprint, password, salt, 0, userMessage, string.Empty);
        return fingerprint;
    }

    private static string HashKey(byte[] hash) => Hex.EncodeLower(hash);

private static async Task<string> IncrementalBackupAsync(
    string filePath, DSAAAdapter storage, string prevFingerprint,
    byte[] password, string userMessage, string fssStrategy,
    IProgress<RdrfProgressReport>? progress, CancellationToken ct,
    int fragmentSize = 0, string? customName = null,
    List<string>? auxiliaryStrategies = null,
    Func<byte[], DSAAAdapter, byte[], BackupOrchestrator>? orchestratorFactory = null)
{
    byte[]? prevIndexBytes = null;
    try { prevIndexBytes = storage.ReadIndex(prevFingerprint); }
    catch { throw new InvalidOperationException($"Previous index not found: {prevFingerprint}"); }

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
    catch { throw new CryptographicException("Failed to decrypt previous index. Wrong password or corrupted backup."); }

    // Load existing dedup map from previous index
    var dedupMap = prevIdx?.DedupMap ?? new Dictionary<string, DedupEntry>();

    byte[] salt = new byte[Constants.SaltPrefixLength];
    Buffer.BlockCopy(prevIndexBytes, 0, salt, 0, Constants.SaltPrefixLength);

    // Stream file -> hash(sample) -> split raw
    int fragSize = fragmentSize > 0 ? fragmentSize : 1024 * 1024;
    var rawFragments = new List<byte[]>();
    string fileFingerprint;
    long newFileSize;

    using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
        FileShare.Read, 65536, FileOptions.SequentialScan))
    using (var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
    {
        var fragBuf = new byte[fragSize];
        int fragOff = 0;
        long totalRead = 0;
        int bytesRead;

        while ((bytesRead = await fs.ReadAsync(fragBuf.AsMemory(fragOff, fragSize - fragOff), ct).ConfigureAwait(false)) > 0)
        {
            hasher.AppendData(fragBuf.AsSpan(fragOff, bytesRead));
            fragOff += bytesRead;
            totalRead += bytesRead;

            if (fragOff < fragSize)
                continue;

            byte[] frag = new byte[fragSize];
            Buffer.BlockCopy(fragBuf, 0, frag, 0, fragSize);
            rawFragments.Add(frag);
            fragOff = 0;
        }

        // Last partial fragment
        if (fragOff > 0)
        {
            byte[] frag = new byte[fragOff];
            Buffer.BlockCopy(fragBuf, 0, frag, 0, fragOff);
            rawFragments.Add(frag);
        }

        newFileSize = totalRead;
        fileFingerprint = Hex.EncodeLower(hasher.GetHashAndReset());
    }

    // Same fingerprint -> file unchanged -> just update commit message
    if (prevRawHashes != null && fileFingerprint == prevFingerprint)
    {
        AppendVersionRecord(storage, prevFingerprint, password, salt, prevVersion, userMessage, string.Empty, oldVersions);
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

    // Compute raw fragment hashes (on UNCOMPRESSED data) and query dedup map
    var newRawHashes = new List<byte[]>(rawFragments.Count);
    var sourceVersion = new string?[rawFragments.Count];
    var sourceIndex = new int?[rawFragments.Count];
    bool[] changedFlags = new bool[rawFragments.Count];
    bool anyChanged = false;

    for (int i = 0; i < rawFragments.Count; i++)
    {
        byte[] hash = XxHash128.Hash(rawFragments[i].AsSpan());
        newRawHashes.Add(hash);
        string key = HashKey(hash);
        if (dedupMap.TryGetValue(key, out var entry))
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

    if (!anyChanged)
    {
        AppendVersionRecord(storage, prevFingerprint, password, salt, prevVersion, userMessage,
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

        // LZ4 compress raw fragments -> keep only if smaller -> pad -> pass to BuildChangedFragmentsIndex
        var compressedFrags = new List<byte[]>();
        var originalSizes = new List<int>();
        foreach (var raw in rawFragments)
        {
            byte[] compressed = Compressor.AlwaysCompress(raw);
            byte[] stored = compressed.Length < raw.Length ? compressed : raw;
            originalSizes.Add(stored.Length);
            byte[] padded = new byte[fragSize > 0 ? fragSize : 1024 * 1024];
            Buffer.BlockCopy(stored, 0, padded, 0, Math.Min(stored.Length, padded.Length));
            compressedFrags.Add(padded);
        }

        // Select only changed compressed fragments
        var changedRaw = new List<byte[]>();
        var changedIdxMap = new List<int>();
        for (int i = 0; i < compressedFrags.Count; i++)
        {
            if (changedFlags[i])
            {
                changedRaw.Add(compressedFrags[i]);
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
                    SourceFingerprint = actualFingerprint,
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

        // Build the full index (FSS-encodes compressed+padded fragments)
        await orchestrator.BuildChangedFragmentsIndex(
            compressedFrags, changedRaw, changedIdxMap, changedFlags,
            actualFingerprint, fileFingerprint, Path.GetFileName(filePath),
            newFileSize, fssStrategy, fragmentSize, customName, prevFingerprint,
            prevRawHashes, progress, ct,
            compressionMethod: Constants.CompressionLz4)
            .ConfigureAwait(false);

        // Patch index with correct RawFragmentHashes + OriginalFragmentSizes + SourceVersion
        byte[] newEncIdx = storage.ReadIndex(actualFingerprint);
        (_, byte[] newCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(newEncIdx, password);
        var newIdx = IndexManager.DeserializeIndex(newCbor);
        newIdx.RawFragmentHashes = newRawHashes;
        newIdx.OriginalFragmentSizes = originalSizes;
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
            && kv.Value.SourceFingerprint != actualFingerprint
            && kv.Value.SourceFingerprint != prevFingerprint).Select(kv => kv.Key).ToList();
        foreach (var k in gcKeys) dedupMap.Remove(k);

        newIdx.DedupMap = dedupMap;
        byte[] updatedCbor = IndexManager.SerializeIndex(newIdx);
        byte[] updatedIndex = EncryptionLayer.EncryptIndexWithSaltPrefix(updatedCbor, password, salt);
        storage.WriteIndex(actualFingerprint, updatedIndex);

        CleanupOrphanedIndexes(storage, actualFingerprint, prevFingerprint, dedupMap);

        AppendVersionRecord(storage, actualFingerprint, password, salt, prevVersion, userMessage,
            diffResult.HumanDiff, oldVersions, fileEntries);
        return actualFingerprint;
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

        // Apply dedup: mark unchanged fragments as references
        byte[] encIdx = storage.ReadIndex(actualFingerprint);
        (_, byte[] idxCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encIdx, password);
        var index = IndexManager.DeserializeIndex(idxCbor);
        string prefix = index.CustomName ?? actualFingerprint;

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
                    SourceFingerprint = actualFingerprint,
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
            && kv.Value.SourceFingerprint != actualFingerprint
            && kv.Value.SourceFingerprint != prevFingerprint).Select(kv => kv.Key).ToList();
        foreach (var k in gcKeys) dedupMap.Remove(k);

        index.DedupMap = dedupMap;
        byte[] finalCbor = IndexManager.SerializeIndex(index);
        byte[] finalIndex = EncryptionLayer.EncryptIndexWithSaltPrefix(finalCbor, password, salt);
        storage.WriteIndex(actualFingerprint, finalIndex);

        CleanupOrphanedIndexes(storage, actualFingerprint, prevFingerprint, dedupMap);

        AppendVersionRecord(storage, actualFingerprint, password, salt, prevVersion, userMessage,
            diffResult.HumanDiff, oldVersions, fileEntries);
        return actualFingerprint;
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

    private static void CleanupOldFragments(DSAAAdapter storage, string fingerprint)
    {
        try
        {
            storage.DeleteFragment(fingerprint + Constants.IndexFileSuffix);
            storage.DeleteFragment(fingerprint + Constants.RcFileSuffix);
            foreach (string fragFile in storage.ListFragments())
                if (fragFile.StartsWith(fingerprint + "_", StringComparison.OrdinalIgnoreCase))
                    storage.DeleteFragment(fragFile);
        }
        catch (Exception ex) { RdrfLogger.Default.Debug("",$"Fragment cleanup failed: {ex.Message}"); }
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
            string svPrefix = index.CustomName ?? svFp;
            string fragName = FragmentEngine.Frags.FragmentFilename(svPrefix, svIdx);
            byte[] encrypted = storage.ReadFragment(fragName);
            byte[] raw = EncryptionLayer.DecryptAndStripFragment(encrypted, aesKey);
            rawFragments.Add(raw);
        }

        var fssEngine = new FSS.FSSEngine();
        var decoded = new Dictionary<int, byte[]>();
        for (int i = 0; i < origCount && i < rawFragments.Count; i++)
            decoded[i] = rawFragments[i];

        var stripped = fssEngine.Strip(decoded, index.FssStrategy, origCount, index.OriginalFragmentSizes);

        byte[] result;
        if (index.Compression == Constants.CompressionLz4)
        {
            for (int i = 0; i < stripped.Count; i++)
            {
                byte[] frag = stripped[i];
                int storedSize = (index.OriginalFragmentSizes != null && i < index.OriginalFragmentSizes.Count)
                    ? index.OriginalFragmentSizes[i] : frag.Length;
                byte[] stored = frag.AsSpan(0, Math.Min(storedSize, frag.Length)).ToArray();
                stripped[i] = Compressor.IsLz4Frame(stored)
                    ? Compressor.Decompress(stored, Constants.CompressionLz4)
                    : stored;
            }
            result = FragmentEngine.Frags.MergeFragments(stripped);
        }
        else
            result = FragmentEngine.Frags.MergeFragments(stripped);

        if (sampleSize > 0 && result.Length > sampleSize)
            return result.AsSpan(0, (int)sampleSize).ToArray();
        return result;
    }

    private static void AppendVersionRecord(
        DSAAAdapter storage, string fingerprint, byte[] password, byte[] salt,
        int previousVersion, string userMessage, string systemDiff,
        List<VersionRecord>? inheritedVersions = null,
        List<FileEntry>? fileEntries = null)
    {
        byte[] encryptedIndex = storage.ReadIndex(fingerprint);
        (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
        var index = IndexManager.DeserializeIndex(cbor);

        int newVersion = previousVersion + 1;
        var existing = inheritedVersions ?? new List<VersionRecord>();

        if (existing.Count > 0)
            existing = existing.ToList();

        existing.Add(new VersionRecord
        {
            Version = newVersion,
            UserMessage = userMessage,
            SystemDiff = systemDiff,
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            FileFingerprint = fingerprint,
            Salt = (byte[])salt.Clone(),
            Files = fileEntries,
        });

        index.VersionNumber = newVersion;
        index.Versions = existing;

        byte[] newCbor = IndexManager.SerializeIndex(index);
        byte[] saltedIndex = EncryptionLayer.EncryptIndexWithSaltPrefix(newCbor, password, salt);
        storage.WriteIndex(fingerprint, saltedIndex);
    }
}




