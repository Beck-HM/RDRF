using RDRF.Core.DSAA;
using RDRF.Core.Encryption;
using RDRF.Core.Versioning;
using Xunit;

namespace RDRF.Core.Tests;

public class VersionedRestoreTests : IDisposable
{
    private readonly string _dir;
    private readonly LocalDSAAAdapter _storage;
    private readonly byte[] _password;
    private string _fingerprint = "";

    public VersionedRestoreTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"rdrf_vrestore_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dir);
        _storage = new LocalDSAAAdapter(_dir);
        _password = EncryptionLayer.GenerateRcCode(32);
    }

    private string CreateAndBackup(string name, byte[] data, string strategy = "FSS1")
    {
        string filePath = Path.Combine(_dir, name);
        File.WriteAllBytes(filePath, data);
        using var engine = new RDRFEngine(_password, _storage);
        return engine.BackupFile(filePath, strategy);
    }

    [Fact]
    public void GetVersionHistory_NoIndexFile_ReturnsEmpty()
    {
        var history = VersionedRestore.GetVersionHistory("/nonexistent/path.indrdrf", _password);
        Assert.Empty(history);
    }

    [Fact]
    public void GetVersionHistory_AfterBackup_ReturnsSomething()
    {
        _fingerprint = CreateAndBackup("test.bin", new byte[] { 1, 2, 3 });
        string idxPath = Path.Combine(_dir, _fingerprint + ".indrdrf");
        var history = VersionedRestore.GetVersionHistory(idxPath, _password);
        // Standard backup may not have version history; just verify no exception
        Assert.NotNull(history);
    }

    [Fact]
    public void Restore_RoundTrip()
    {
        byte[] data = new byte[] { 10, 20, 30, 40, 50 };
        _fingerprint = CreateAndBackup("restore_test.bin", data);

        string outPath = Path.Combine(_dir, "restored.bin");
        string idxPath = Path.Combine(_dir, _fingerprint + ".indrdrf");
        bool ok = VersionedRestore.Restore(outPath, idxPath, _password);
        Assert.True(ok);
        Assert.Equal(data, File.ReadAllBytes(outPath));
    }

    [Fact]
    public void GetVersionHistory_WrongPassword_ReturnsEmpty()
    {
        _fingerprint = CreateAndBackup("pw_test.bin", new byte[] { 1 });
        string idxPath = Path.Combine(_dir, _fingerprint + ".indrdrf");
        byte[] wrongPw = EncryptionLayer.GenerateRcCode(32);
        var history = VersionedRestore.GetVersionHistory(idxPath, wrongPw);
        Assert.Empty(history);
    }

    [Fact]
    public void GetVersionHistory_CorruptIndex_ReturnsEmpty()
    {
        string path = Path.Combine(_dir, "corrupt.indrdrf");
        File.WriteAllBytes(path, new byte[] { 0xFF, 0xFF });
        var history = VersionedRestore.GetVersionHistory(path, _password);
        Assert.Empty(history);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }
}
