using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Core.Storage;

namespace RDRF.Core.Versioning;

public static class VersionedRestore
{
    public static bool Restore(
        string outputPath,
        string indexFilePath,
        byte[] password,
        bool allowFssRecovery = true,
        IProgress<RdrfProgressReport>? progress = null)
    {
        string storageDir = Path.GetDirectoryName(indexFilePath) ?? ".";
        var storage = new LocalFileAdapter(storageDir);
        string fingerprint = Path.GetFileNameWithoutExtension(indexFilePath);

        using var restore = new RestoreOrchestrator(password, storage);
        return restore.RestoreFile(fingerprint, outputPath, allowFssRecovery, progress: progress);
    }

    public static List<VersionRecord> GetVersionHistory(string indexFilePath, byte[] password)
    {
        if (!File.Exists(indexFilePath))
            return new List<VersionRecord>();

        byte[] encryptedIndex = File.ReadAllBytes(indexFilePath);
        try
        {
            (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
            var index = IndexManager.DeserializeIndex(cbor);
            return index.Versions ?? new List<VersionRecord>();
        }
        catch
        {
            return new List<VersionRecord>();
        }
    }
}
