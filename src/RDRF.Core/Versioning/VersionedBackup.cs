using System.Security.Cryptography;
using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Core.Storage;

namespace RDRF.Core.Versioning;

public static class VersionedBackup
{
    public static async Task<string> BackupAsync(
        string filePath,
        string storageDir,
        byte[] password,
        string userMessage,
        string fssStrategy = "FSS3",
        IProgress<RdrfProgressReport>? progress = null,
        CancellationToken ct = default)
    {
        string rollDir = Path.Combine(storageDir, ".rdr_version");

        if (!VersionChain.Exists(rollDir))
            return await FreshBackupAsync(filePath, storageDir, rollDir, password, userMessage, fssStrategy, progress, ct).ConfigureAwait(false);

        return await IncrementalBackupAsync(filePath, storageDir, rollDir, password, userMessage, fssStrategy, progress, ct).ConfigureAwait(false);
    }

    private static async Task<string> FreshBackupAsync(
        string filePath, string storageDir, string rollDir,
        byte[] password, string userMessage, string fssStrategy,
        IProgress<RdrfProgressReport>? progress, CancellationToken ct)
    {
        var chain = VersionChain.Init(rollDir);
        byte[] chainSalt = (byte[])chain.Config.Salt.Clone();
        var storage = new LocalFileAdapter(storageDir);

        string fingerprint;
        using (var orchestrator = new BackupOrchestrator((byte[])password.Clone(), (byte[])chainSalt.Clone(), storage))
        {
            fingerprint = await orchestrator.BackupFileAsync(filePath, fssStrategy, progress: progress, cancellationToken: ct).ConfigureAwait(false);
        }

        AppendVersionRecord(storage, fingerprint, password, chainSalt, 0, userMessage, string.Empty);
        chain.WriteHead(1, fingerprint);
        return fingerprint;
    }

    private static async Task<string> IncrementalBackupAsync(
        string filePath, string storageDir, string rollDir,
        byte[] password, string userMessage, string fssStrategy,
        IProgress<RdrfProgressReport>? progress, CancellationToken ct)
    {
        var chain = VersionChain.Load(rollDir);
        byte[] chainSalt = (byte[])chain.Config.Salt.Clone();
        int prevVersion = chain.ReadHeadVersion();
        string prevFingerprint = chain.ReadHeadFingerprint();
        var storage = new LocalFileAdapter(storageDir);

        byte[] oldData = ReadDecryptedOriginal(storage, prevFingerprint, password);

        byte[] newData = await File.ReadAllBytesAsync(filePath, ct).ConfigureAwait(false);

        var (humanDiff, _, _) = DiffEngine.ComputeDiff(oldData, newData);

        string actualFingerprint;
        using (var orchestrator = new BackupOrchestrator((byte[])password.Clone(), (byte[])chainSalt.Clone(), storage))
        {
            actualFingerprint = await orchestrator.BackupFileAsync(filePath, fssStrategy, progress: progress, cancellationToken: ct).ConfigureAwait(false);
        }

        AppendVersionRecord(storage, actualFingerprint, password, chainSalt, prevVersion, userMessage, humanDiff);

        CleanupOldFragments(storage, prevFingerprint);

        chain.WriteHead(prevVersion + 1, actualFingerprint);
        return actualFingerprint;
    }

    private static byte[] ReadDecryptedOriginal(StorageAdapter storage, string fingerprint, byte[] password)
    {
        byte[] encryptedIndex = storage.ReadIndex(fingerprint);
        (byte[] aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
        var index = IndexManager.DeserializeIndex(cbor);
        string prefix = index.CustomName ?? fingerprint;

        var rawFragments = new List<byte[]>();
        for (int i = 0; i < index.FragentCount; i++)
        {
            string fragName = FragmentEngine.Frags.FragentFilename(prefix, i);
            byte[] encrypted = storage.ReadFragment(fragName);
            bool hasHeader = FragmentFileHeader.HasHeader(encrypted);
            int hdrOff = hasHeader ? FragmentFileHeader.GetTotalHeaderSize(encrypted) : 0;
            byte[] raw = EncryptionLayer.DecryptFragmentCtrWithKey(encrypted, hdrOff, aesKey);
            if (hasHeader && raw.Length >= 4)
            {
                int idxLen = BitConverter.ToInt32(raw.AsSpan(0, 4));
                if (idxLen > 4 && idxLen <= raw.Length - 4)
                    raw = raw[(4 + idxLen)..];
            }
            rawFragments.Add(raw);
        }

        // FSS strip
        var fssStrategy = index.FssStrategy;
        var fssEngine = new FSS.FSSEngine();
        var decoded = new Dictionary<int, byte[]>();
        for (int i = 0; i < index.OriginalFragentCount && i < rawFragments.Count; i++)
            decoded[i] = rawFragments[i];

        var stripped = fssEngine.Strip(decoded, fssStrategy, index.OriginalFragentCount, index.OriginalFragentSizes);

        return FragmentEngine.Frags.MergeFragents(stripped);
    }

    private static void AppendVersionRecord(
        StorageAdapter storage, string fingerprint, byte[] password, byte[] salt,
        int previousVersion, string userMessage, string systemDiff)
    {
        byte[] encryptedIndex = storage.ReadIndex(fingerprint);
        (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
        var index = IndexManager.DeserializeIndex(cbor);

        int newVersion = previousVersion + 1;
        var existing = index.Versions ?? new List<VersionRecord>();

        if (previousVersion > 0 && existing.Count > 0)
        {
            existing = existing.ToList();
        }

        existing.Add(new VersionRecord
        {
            Version = newVersion,
            UserMessage = userMessage,
            SystemDiff = systemDiff,
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            FileFingerprint = fingerprint
        });

        index.VersionNumber = newVersion;
        index.Versions = existing;

        byte[] newCbor = IndexManager.SerializeIndex(index);
        byte[] saltedIndex = EncryptionLayer.EncryptIndexWithSaltPrefix(newCbor, password, salt);
        storage.WriteIndex(fingerprint, saltedIndex);
    }

    private static void CleanupOldFragments(StorageAdapter storage, string fingerprint)
    {
        try
        {
            storage.DeleteFragment(fingerprint + Constants.IndexFileSuffix);
            foreach (string fragFile in storage.ListFragments())
            {
                if (fragFile.StartsWith(fingerprint + "_", StringComparison.OrdinalIgnoreCase))
                    storage.DeleteFragment(fragFile);
            }
        }
        catch { }
    }

    private static async Task<string> ComputeSha256Async(string filePath, CancellationToken ct)
    {
        using var sha = SHA256.Create();
        await using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan);
        byte[] hash = await sha.ComputeHashAsync(stream, ct).ConfigureAwait(false);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
