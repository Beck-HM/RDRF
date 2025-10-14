using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Core.Dssa;

namespace RDRF.App.Tests.Fixtures;

public class TempDir : IDisposable
{
    public string Path { get; }

    public TempDir()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"RDRF_AppTest_{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path);
    }

    public string this[string relative] => System.IO.Path.Combine(Path, relative);

    public string CreateFile(string name, long size)
    {
        var filePath = this[name];
        using var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write);
        var rng = RandomNumberGenerator.GetBytes(65536);
        long written = 0;
        while (written < size)
        {
            int chunk = (int)Math.Min(65536, size - written);
            fs.Write(rng, 0, chunk);
            written += chunk;
        }
        return filePath;
    }

    public string CreateTextFile(string name, string content)
    {
        var filePath = this[name];
        File.WriteAllText(filePath, content);
        return filePath;
    }

    public void Dispose()
    {
        try { Directory.Delete(Path, true); } catch { }
    }
}

public static class BackupHelpers
{
    public static string Backup(byte[] password, string inputFile, string storageDir,
        string strategy = "FSS1", int? fragmentSize = null)
    {
        var storage = new LocalDssaAdapter(storageDir);
        using var engine = new RDRFEngine(password, storage);
        return engine.BackupFile(inputFile, strategy,
            fragmentSize: fragmentSize ?? 256 * 1024);
    }

    public static string BackupWithSalt(byte[] password, byte[] salt, string inputFile, string storageDir,
        string strategy = "FSS1", int? fragmentSize = null)
    {
        var storage = new LocalDssaAdapter(storageDir);
        using var engine = new BackupOrchestrator(password, storage, salt);
        return engine.BackupFile(inputFile, strategy,
            fragmentSize: fragmentSize ?? 256 * 1024);
    }

    public static BackupLoadResult LoadIndex(byte[] password, string storageDir, string fingerprint)
    {
        var storage = new LocalDssaAdapter(storageDir);
        byte[] encIdx = storage.ReadIndex(fingerprint);
        (byte[] aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encIdx, password);
        var index = IndexManager.DeserializeIndex(cbor);
        return ToResult(index);
    }

    public static BackupLoadResult ToResult(RdrfIndex index)
    {
        bool hasFss6 = index.Fss6FragmentBlockMaps != null || index.Fss6RcBlockMap != null;
        return new BackupLoadResult
        {
            Fingerprint = index.FileFingerprint,
            FilePrefix = index.CustomName ?? index.FileFingerprint,
            OriginalName = index.OriginalName,
            FileSize = index.FileSize,
            FssStrategy = index.FssStrategy,
            StrategyDisplay = hasFss6 && index.FssStrategy != "FSS6"
                ? index.FssStrategy + " + FSS6"
                : index.FssStrategy,
            FragmentCount = index.FragmentCount,
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(index.CreatedAt).LocalDateTime,
        };
    }

    public static bool Restore(byte[] password, string storageDir, string fingerprint, string outputPath)
    {
        var storage = new LocalDssaAdapter(storageDir);
        using var engine = new RDRFEngine(password, storage);
        return engine.RestoreFile(fingerprint, outputPath);
    }

    public static byte[] ReadAllBytes(string path) => File.ReadAllBytes(path);
}

public class BackupLoadResult
{
    public string Fingerprint { get; init; } = "";
    public string FilePrefix { get; init; } = "";
    public string OriginalName { get; init; } = "";
    public long FileSize { get; init; }
    public string FssStrategy { get; init; } = "";
    public string StrategyDisplay { get; init; } = "";
    public int FragmentCount { get; init; }
    public DateTime CreatedAt { get; init; }
}
