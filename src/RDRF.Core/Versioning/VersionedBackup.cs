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
        string storageDir,
        byte[] password,
        string userMessage,
        string fssStrategy = "FSS3",
        int fragmentSize = 0,
        string? customName = null,
        List<string>? auxiliaryStrategies = null,
        IProgress<RdrfProgressReport>? progress = null,
        CancellationToken ct = default)
    {
        var storage = new LocalDssaAdapter(storageDir);
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
        using var orchestrator = new BackupOrchestrator((byte[])password.Clone(), (byte[])salt.Clone(), storage);
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

    // Same fingerprint → file unchanged → just update commit message
    if (prevRawHashes != null && fileFingerprint == prevFingerprint)
    {
        var newIndex = new RdrfIndex { FileFingerprint = fileFingerprint };
        AppendVersionRecord(storage, prevFingerprint, password, salt, prevVersion, userMessage, string.Empty, oldVersions);
        return prevFingerprint;
    }

    // Compute diff for display
    byte[] oldData = ReadDecryptedOriginal(storage, prevFingerprint, password);
    var diffResult = new DiffEngine().ComputeDiff(oldData, newData);

    var fileEntries = new List<FileEntry>
    {
        new FileEntry
        {
            Path = Path.GetFileName(filePath),
            ChangeType = diffResult.IsBinary ? "modified (binary)" : "modified",
            Diff = diffResult.HumanDiff,
        }
    };

    // Split new file into raw fragments
    var rawFragments = new List<byte[]>();
    for (int off = 0; off < newData.Length; off += fragSize)
    {
        int len = Math.Min(fragSize, newData.Length - off);
        byte[] frag = new byte[len];
        Buffer.BlockCopy(newData, off, frag, 0, len);
        rawFragments.Add(frag);
    }

    // Compute raw fragment hashes
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

        using var orchestrator = new BackupOrchestrator((byte[])password.Clone(), (byte[])salt.Clone(), storage);

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
        var embeddedIndex = orchestrator.BuildChangedFragmentsIndex(
            rawFragments, changedRaw, changedIdxMap, changedFlags,
            actualFingerprint, fileFingerprint, Path.GetFileName(filePath),
            newData.Length, fssStrategy, fragmentSize, customName, prevFingerprint,
            prevRawHashes, progress, ct).GetAwaiter().GetResult();

        byte[] indexCbor = IndexManager.SerializeIndex(embeddedIndex);
        byte[] saltedIndex = EncryptionLayer.EncryptIndexWithSaltPrefix(indexCbor, password, salt);
        storage.WriteIndex(actualFingerprint, saltedIndex);

        AppendVersionRecord(storage, actualFingerprint, password, salt, prevVersion, userMessage,
            diffResult.HumanDiff, oldVersions, fileEntries);
        return actualFingerprint;
    }
    else
    {
        // Cross-encoding strategies: full pipeline (old behavior)
        string actualFingerprint;
        using (var orchestrator = new BackupOrchestrator((byte[])password.Clone(), (byte[])salt.Clone(), storage))
        {
            actualFingerprint = await orchestrator.BackupFileAsync(filePath, fssStrategy,
                auxiliaryStrategies, Path.GetFileName(filePath), fragmentSize, customName,
                progress, ct).ConfigureAwait(false);
        }

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
            try { storage.DeleteFragment(fragName); } catch { }
        }
    }

    byte[] updatedCbor = IndexManager.SerializeIndex(index);
    byte[] updatedIndex = EncryptionLayer.EncryptIndexWithSaltPrefix(updatedCbor, password, salt);
    storage.WriteIndex(actualFingerprint, updatedIndex);
}

    private static byte[] ReadDecryptedOriginal(DssaAdapter storage, string fingerprint, byte[] password)
    {
        byte[] encryptedIndex = storage.ReadIndex(fingerprint);
        (byte[] aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
        var index = IndexManager.DeserializeIndex(cbor);
        string prefix = index.CustomName ?? fingerprint;

        var rawFragments = new List<byte[]>();
        for (int i = 0; i < index.FragmentCount; i++)
        {
            string fragName = FragmentEngine.Frags.FragmentFilename(prefix, i);
            byte[] encrypted = storage.ReadFragment(fragName);
            byte[] raw = EncryptionLayer.DecryptAndStripFragment(encrypted, aesKey);
            rawFragments.Add(raw);
        }

        var fssEngine = new FSS.FSSEngine();
        var decoded = new Dictionary<int, byte[]>();
        for (int i = 0; i < index.OriginalFragmentCount && i < rawFragments.Count; i++)
            decoded[i] = rawFragments[i];

        var stripped = fssEngine.Strip(decoded, index.FssStrategy, index.OriginalFragmentCount, index.OriginalFragmentSizes);
        return FragmentEngine.Frags.MergeFragments(stripped);
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
        catch { }
    }
}
