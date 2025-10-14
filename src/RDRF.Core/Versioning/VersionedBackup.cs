using System.Diagnostics;
using System.IO.Hashing;
using System.Security.Cryptography;
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
            foreach (string f in Directory.GetFiles(dir, "*" + Constants.IndexFileSuffix))
            {
                string name = Path.GetFileName(f);
                return name[..^Constants.IndexFileSuffix.Length];
            }
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
    try
    {
        (_, byte[] prevCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(prevIndexBytes, password);
        var prevIdx = IndexManager.DeserializeIndex(prevCbor);
        prevVersion = prevIdx.VersionNumber ?? 0;
        oldVersions = prevIdx.Versions;
        prevRawHashes = prevIdx.RawFragmentHashes;
    }
    catch { throw new CryptographicException("Failed to decrypt previous index. Wrong password or corrupted backup."); }

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

    // Same fingerprint 鈫?file unchanged 鈫?just update commit message
    if (prevRawHashes != null && fileFingerprint == prevFingerprint)
    {
        var newIndex = new RdrfIndex { FileFingerprint = fileFingerprint };
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

    // Compress data before splitting into fragments
    byte[] compressedData = RDRF.Core.Compression.Compressor.Compress(newData, Constants.CompressionLz4);
    bool dataCompressed = compressedData.Length < newData.Length;

    // Split compressed data into raw fragments
    var rawFragments = new List<byte[]>();
    for (int off = 0; off < compressedData.Length; off += fragSize)
    {
        int len = Math.Min(fragSize, compressedData.Length - off);
        byte[] frag = new byte[len];
        Buffer.BlockCopy(compressedData, off, frag, 0, len);
        rawFragments.Add(frag);
    }

    // Compute raw fragment hashes (on compressed data)
    var newRawHashes = new List<byte[]>(rawFragments.Count);
    foreach (var frag in rawFragments)
        newRawHashes.Add(System.IO.Hashing.XxHash128.Hash(frag.AsSpan()));

    // Determine which raw fragments changed
    bool[] changedFlags = new bool[rawFragments.Count];
    bool anyChanged = false;
    for (int i = 0; i < rawFragments.Count; i++)
    {
        bool changed = prevRawHashes == null || i >= prevRawHashes.Count ||
            !newRawHashes[i].AsSpan().SequenceEqual(prevRawHashes[i]);
        changedFlags[i] = changed;
        if (changed) anyChanged = true;
    }

    if (!anyChanged)
    {
        AppendVersionRecord(storage, prevFingerprint, password, salt, prevVersion, userMessage,
            diffResult.HumanDiff, oldVersions, fileEntries);
        return prevFingerprint;
    }

    // For 1:1 strategies (FSS1, FSS6.1), only process changed raw fragments
    bool isOneToOne = fssStrategy == Constants.FssLevel1 || fssStrategy == Constants.FssLevel61;

    if (isOneToOne)
    {
        string actualFingerprint = fileFingerprint;
        string filePrefix = customName ?? actualFingerprint;
        var (aesKey, cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(prevIndexBytes, password);

        using var orchestrator = new BackupOrchestrator((byte[])password.Clone(), storage, (byte[])salt.Clone());

        // Select only changed raw fragments for processing
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

        // Build the full index with all raw fragment hashes
        orchestrator.BuildChangedFragmentsIndex(
            rawFragments, changedRaw, changedIdxMap, changedFlags,
            actualFingerprint, fileFingerprint, Path.GetFileName(filePath),
            newData.Length, fssStrategy, fragmentSize, customName, prevFingerprint,
            prevRawHashes, progress, ct,
            compressionMethod: dataCompressed ? Constants.CompressionLz4 : null)
            .GetAwaiter().GetResult();

        CleanupOldFragments(storage, prevFingerprint);
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

        CleanupOldFragments(storage, prevFingerprint);
        DedupPostProcessing(storage, actualFingerprint, password, prevFingerprint, prevRawHashes, newRawHashes);
        AppendVersionRecord(storage, actualFingerprint, password, salt, prevVersion, userMessage,
            diffResult.HumanDiff, oldVersions, fileEntries);
        return actualFingerprint;
    }
}

private static void DedupPostProcessing(DssaAdapter storage, string actualFingerprint,
    byte[] password, string prevFingerprint,
    List<byte[]>? prevRawHashes, List<byte[]>? newRawHashes)
{
    if (prevRawHashes == null || newRawHashes == null) return;

    byte[] encryptedIndex = storage.ReadIndex(actualFingerprint);
    (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
    var index = IndexManager.DeserializeIndex(cbor);
    string prefix = index.CustomName ?? actualFingerprint;

    byte[] salt = new byte[Constants.SaltPrefixLength];
    Buffer.BlockCopy(encryptedIndex, 0, salt, 0, Constants.SaltPrefixLength);

    for (int i = 0; i < newRawHashes.Count && i < prevRawHashes.Count && i < index.Fragments?.Count; i++)
    {
        if (newRawHashes[i].AsSpan().SequenceEqual(prevRawHashes[i]))
        {
            index.Fragments[i].SourceVersion = prevFingerprint;
            string fragName = FragmentEngine.Frags.FragmentFilename(prefix, i);
            try { storage.DeleteFragment(fragName); } catch (Exception ex) { Debug.WriteLine($"Failed to delete old fragment '{fragName}': {ex.Message}"); }
        }
    }

    byte[] updatedCbor = IndexManager.SerializeIndex(index);
    byte[] updatedIndex = EncryptionLayer.EncryptIndexWithSaltPrefix(updatedCbor, password, salt);
    storage.WriteIndex(actualFingerprint, updatedIndex);
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

        // Determine how many fragments to read (partial read for sampling)
        int fragsToRead = fragCount;
        if (sampleSize > 0)
        {
            long total = 0;
            for (int i = 0; i < origCount && i < (index.OriginalFragmentSizes?.Count ?? 0); i++)
            {
                total += index.OriginalFragmentSizes[i];
                if (total >= sampleSize) { fragsToRead = i + 1; break; }
            }
            // FSS1 concatenation: encoded[i] = data[i] + data[(i+1)], need +1 for neighbor
            if (fragsToRead < fragCount)
                fragsToRead = Math.Min(fragCount, fragsToRead + 1);
        }

        var rawFragments = new List<byte[]>(fragsToRead);
        for (int i = 0; i < fragsToRead; i++)
        {
            string fragName = FragmentEngine.Frags.FragmentFilename(prefix, i);
            byte[] encrypted = storage.ReadFragment(fragName);
            byte[] raw = EncryptionLayer.DecryptAndStripFragment(encrypted, aesKey);
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
}

