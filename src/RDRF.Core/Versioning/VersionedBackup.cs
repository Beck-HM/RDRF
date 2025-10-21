using System.Diagnostics;
using System.IO.Hashing;
using System.Security.Cryptography;
using RDRF.Core.Compression;
using RDRF.Core.Diff;
using RDRF.Core.Encryption;
using RDRF.Core.FragmentEngine;
using RDRF.Core.Index;
using RDRF.Core.Dssa;

namespace RDRF.Core.Versioning;

public static class VersionedBackup
{
    public static async Task<string> BackupAsync(
        string filePath,
        DssaAdapter storage,
        byte[] password,
        string userMessage,
        string fssStrategy = "FSS3",
        int fragmentSize = 0,
        string? customName = null,
        List<string>? auxiliaryStrategies = null,
        IProgress<RdrfProgressReport>? progress = null,
        CancellationToken ct = default)
    {
        string? existingFingerprint = FindExistingIndex(storage);

        if (existingFingerprint == null)
            return await FreshBackupAsync(filePath, storage, password, userMessage, fssStrategy, progress, ct, fragmentSize, customName, auxiliaryStrategies).ConfigureAwait(false);

        return await IncrementalBackupAsync(filePath, storage, existingFingerprint, password, userMessage, fssStrategy, progress, ct, fragmentSize, customName, auxiliaryStrategies).ConfigureAwait(false);
    }

    private static string? FindExistingIndex(DssaAdapter storage)
    {
        if (storage is LocalDssaAdapter local)
        {
            string dir = local.GetBasePath();
            if (!Directory.Exists(dir)) return null;
            string? newest = null;
            DateTime newestTime = DateTime.MinValue;
            foreach (string f in Directory.GetFiles(dir, "*" + Constants.IndexFileSuffix))
            {
                DateTime ft = File.GetLastWriteTimeUtc(f);
                if (ft > newestTime)
                {
                    newestTime = ft;
                    newest = Path.GetFileName(f);
                }
            }
            return newest?[..^Constants.IndexFileSuffix.Length];
        }
        return null;
    }

    private static async Task<string> FreshBackupAsync(
        string filePath, DssaAdapter storage,
        byte[] password, string userMessage, string fssStrategy,
        IProgress<RdrfProgressReport>? progress, CancellationToken ct,
        int fragmentSize = 0, string? customName = null,
        List<string>? auxiliaryStrategies = null)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(Constants.SaltPrefixLength);
        using var orchestrator = new BackupOrchestrator((byte[])password.Clone(), storage, (byte[])salt.Clone());
        string fingerprint = await orchestrator.BackupFileAsync(filePath, fssStrategy,
            fragmentSize: fragmentSize, customName: customName, auxiliaryStrategies: auxiliaryStrategies,
            progress: progress, cancellationToken: ct).ConfigureAwait(false);

        AppendVersionRecord(storage, fingerprint, password, salt, 0, userMessage, string.Empty);
        return fingerprint;
    }

    private static string HashKey(byte[] hash) => Convert.ToHexString(hash).ToLowerInvariant();

private static async Task<string> IncrementalBackupAsync(
    string filePath, DssaAdapter storage, string prevFingerprint,
    byte[] password, string userMessage, string fssStrategy,
    IProgress<RdrfProgressReport>? progress, CancellationToken ct,
    int fragmentSize = 0, string? customName = null,
    List<string>? auxiliaryStrategies = null)
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

    // Read new file and split into raw fragments
    byte[] newData = await File.ReadAllBytesAsync(filePath, ct).ConfigureAwait(false);
    int fragSize = fragmentSize > 0 ? fragmentSize : 1024 * 1024;

    // Compute SHA256 fingerprint
    string fileFingerprint;
    using (var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
    {
        hasher.AppendData(newData);
        fileFingerprint = Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
    }

    // Same fingerprint -> file unchanged -> just update commit message
    if (prevRawHashes != null && fileFingerprint == prevFingerprint)
    {
        AppendVersionRecord(storage, prevFingerprint, password, salt, prevVersion, userMessage, string.Empty, oldVersions);
        return prevFingerprint;
    }

    // Compute diff for display (on uncompressed data, sample head only)
    long sampleSize = newData.Length > 256 * 1024 ? 64 * 1024 : 0;
    byte[] oldData = ReadDecryptedOriginal(storage, prevFingerprint, password, sampleSize);
    byte[] newSample = sampleSize > 0 ? newData.AsSpan(0, (int)sampleSize).ToArray() : newData;
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

    // Split raw (uncompressed) data into fragments, hash for dedup
    var rawFragments = new List<byte[]>();
    for (int off = 0; off < newData.Length; off += fragSize)
    {
        int len = Math.Min(fragSize, newData.Length - off);
        byte[] frag = new byte[len];
        Buffer.BlockCopy(newData, off, frag, 0, len);
        rawFragments.Add(frag);
    }

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

        using var orchestrator = new BackupOrchestrator((byte[])password.Clone(), storage, (byte[])salt.Clone());

        // LZ4 compress raw fragments → keep only if smaller → pad → pass to BuildChangedFragmentsIndex
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
                // Don't delete fragments owned by the version we're replacing — still needed by its index
                if (entry.SourceFingerprint == prevFingerprint) continue;
                entry.RefCount--;
                if (entry.RefCount <= 0)
                {
                    string oldPrefix = entry.SourceFingerprint;
                    string fragName = Frags.FragmentFilename(oldPrefix, entry.SourceIndex);
                    try { storage.DeleteFragment(fragName); } catch { Debug.WriteLine($"Failed to delete {fragName}"); }
                    dedupMap.Remove(oldKey);
                }
            }
        }

        // Build the full index (FSS-encodes compressed+padded fragments)
        orchestrator.BuildChangedFragmentsIndex(
            compressedFrags, changedRaw, changedIdxMap, changedFlags,
            actualFingerprint, fileFingerprint, Path.GetFileName(filePath),
            newData.Length, fssStrategy, fragmentSize, customName, prevFingerprint,
            prevRawHashes, progress, ct,
            compressionMethod: Constants.CompressionLz4)
            .GetAwaiter().GetResult();

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
        newIdx.DedupMap = dedupMap;
        byte[] updatedCbor = IndexManager.SerializeIndex(newIdx);
        byte[] updatedIndex = EncryptionLayer.EncryptIndexWithSaltPrefix(updatedCbor, password, salt);
        storage.WriteIndex(actualFingerprint, updatedIndex);

        AppendVersionRecord(storage, actualFingerprint, password, salt, prevVersion, userMessage,
            diffResult.HumanDiff, oldVersions, fileEntries);
        return actualFingerprint;
    }
    else
    {
        // Cross-encoding strategies: full pipeline (old behavior)
        string actualFingerprint;
        using (var orchestrator = new BackupOrchestrator((byte[])password.Clone(), storage, (byte[])salt.Clone()))
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
                try { storage.DeleteFragment(fragName); } catch { }
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
                    try { storage.DeleteFragment(fragName); } catch { }
                    dedupMap.Remove(oldKey);
                }
            }
        }

        index.DedupMap = dedupMap;
        byte[] finalCbor = IndexManager.SerializeIndex(index);
        byte[] finalIndex = EncryptionLayer.EncryptIndexWithSaltPrefix(finalCbor, password, salt);
        storage.WriteIndex(actualFingerprint, finalIndex);

        AppendVersionRecord(storage, actualFingerprint, password, salt, prevVersion, userMessage,
            diffResult.HumanDiff, oldVersions, fileEntries);
        return actualFingerprint;
    }
}

    private static void CleanupOldFragments(DssaAdapter storage, string fingerprint)
    {
        try
        {
            storage.DeleteFragment(fingerprint + Constants.IndexFileSuffix);
            storage.DeleteFragment(fingerprint + Constants.RcFileSuffix);
            foreach (string fragFile in storage.ListFragments())
                if (fragFile.StartsWith(fingerprint + "_", StringComparison.OrdinalIgnoreCase))
                    storage.DeleteFragment(fragFile);
        }
        catch (Exception ex) { Debug.WriteLine($"Fragment cleanup failed: {ex.Message}"); }
    }

    private static byte[] ReadDecryptedOriginal(DssaAdapter storage, string fingerprint,
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
        DssaAdapter storage, string fingerprint, byte[] password, byte[] salt,
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
