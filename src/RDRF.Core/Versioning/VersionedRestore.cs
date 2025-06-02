using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Core.Storage;

namespace RDRF.Core.Versioning;

public static class VersionedRestore
{
    public static Task<bool> RestoreAsync(
        string outputPath,
        string storageDir,
        byte[] password,
        bool allowFssRecovery = true,
        IProgress<RdrfProgressReport>? progress = null,
        CancellationToken ct = default)
    {
        string rollDir = Path.Combine(storageDir, ".rdr_version");
        if (!VersionChain.Exists(rollDir))
            throw new InvalidOperationException($"No version chain found at: {storageDir}");

        var chain = VersionChain.Load(rollDir);
        string fingerprint = chain.ReadHeadFingerprint();
        if (string.IsNullOrEmpty(fingerprint))
            throw new InvalidOperationException("Version chain has no fingerprint recorded.");

        var storage = new LocalFileAdapter(storageDir);
        using var restore = new RestoreOrchestrator(password, storage);
        bool result = restore.RestoreFile(fingerprint, outputPath, allowFssRecovery, progress: progress);
        return Task.FromResult(result);
    }

    public static List<VersionRecord> GetVersionHistory(string storageDir, byte[] password)
    {
        string rollDir = Path.Combine(storageDir, ".rdr_version");
        if (!VersionChain.Exists(rollDir))
            return new List<VersionRecord>();

        var chain = VersionChain.Load(rollDir);
        string fingerprint = chain.ReadHeadFingerprint();
        if (string.IsNullOrEmpty(fingerprint))
            return new List<VersionRecord>();

        var storage = new LocalFileAdapter(storageDir);
        if (!storage.IndexExists(fingerprint))
            return new List<VersionRecord>();

        byte[] encryptedIndex = storage.ReadIndex(fingerprint);
        (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
        var index = IndexManager.DeserializeIndex(cbor);
        return index.Versions ?? new List<VersionRecord>();
    }
}
