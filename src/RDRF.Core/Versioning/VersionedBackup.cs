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
        List<List<byte[]>>? prevBlockHashes = null;
        string prevPrefix;
        try
        {
            (_, byte[] prevCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(prevIndexBytes, password);
            var prevIdx = IndexManager.DeserializeIndex(prevCbor);
            prevVersion = prevIdx.VersionNumber ?? 0;
            oldVersions = prevIdx.Versions;
            prevBlockHashes = prevIdx.FragmentBlockHashes;
            prevPrefix = prevIdx.CustomName ?? prevFingerprint;
        }
        catch { throw new CryptographicException("Failed to decrypt previous index. Wrong password or corrupted backup."); }

        byte[] salt = new byte[Constants.SaltPrefixLength];
        Buffer.BlockCopy(prevIndexBytes, 0, salt, 0, Constants.SaltPrefixLength);

        byte[] oldData = ReadDecryptedOriginal(storage, prevFingerprint, password);
        byte[] newData = await File.ReadAllBytesAsync(filePath, ct).ConfigureAwait(false);
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

        string actualFingerprint;
        using (var orchestrator = new BackupOrchestrator((byte[])password.Clone(), (byte[])salt.Clone(), storage))
        {
            actualFingerprint = await orchestrator.BackupFileAsync(filePath, fssStrategy,
                fragmentSize: fragmentSize, customName: customName, auxiliaryStrategies: auxiliaryStrategies,
                progress: progress, cancellationToken: ct).ConfigureAwait(false);
        }

        // Dedup: compare block hashes, reference unchanged fragments from previous version
        byte[] newEncryptedIndex = storage.ReadIndex(actualFingerprint);
        (_, byte[] newCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(newEncryptedIndex, password);
        var newIndex = IndexManager.DeserializeIndex(newCbor);
        string newPrefix = newIndex.CustomName ?? actualFingerprint;

        if (prevBlockHashes != null && newIndex.FragmentBlockHashes != null)
        {
            for (int i = 0; i < newIndex.FragmentBlockHashes.Count && i < prevBlockHashes.Count; i++)
            {
                var newHashes = newIndex.FragmentBlockHashes[i];
                var prevHashes = prevBlockHashes[i];
                if (newHashes.Count != prevHashes.Count) continue;

                bool identical = true;
                for (int j = 0; j < newHashes.Count; j++)
                {
                    if (!newHashes[j].AsSpan().SequenceEqual(prevHashes[j]))
                    { identical = false; break; }
                }

                if (identical && i < newIndex.Fragments?.Count)
                {
                    // Reference previous version's fragment, delete the newly created one
                    newIndex.Fragments[i].SourceVersion = prevFingerprint;
                    string newFragName = Frags.FragmentFilename(newPrefix, i);
                    try { storage.DeleteFragment(newFragName); } catch { }
                }
            }

            // Re-serialize and save the updated index (same salt → same AES key)
            byte[] updatedCbor = IndexManager.SerializeIndex(newIndex);
            byte[] updatedIndex = EncryptionLayer.EncryptIndexWithSaltPrefix(updatedCbor, password, salt);
            storage.WriteIndex(actualFingerprint, updatedIndex);
        }

        AppendVersionRecord(storage, actualFingerprint, password, salt, prevVersion, userMessage,
            diffResult.HumanDiff, oldVersions, fileEntries);

        return actualFingerprint;
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
