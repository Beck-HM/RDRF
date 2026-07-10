using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using RDRF.Core;
using RDRF.Core.Abstractions;
using RDRF.Core.Composition;
using RDRF.Core.Dssa;
using RDRF.Core.Encryption;
using RDRF.Core.FSS;
using RDRF.Core.Index;
using Xunit;

namespace RDRF.Core.Tests;

public class OrchestratorTests : IDisposable
{
    private readonly string _dir;
    private readonly LocalDssaAdapter _storage;
    private readonly byte[] _rcCode;
    private readonly byte[] _aesKey;
    private readonly ServiceProvider _provider;

    public OrchestratorTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"rdrf_orch_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dir);
        _storage = new LocalDssaAdapter(_dir);
        _rcCode = EncryptionLayer.GenerateRcCode(32);
        _aesKey = EncryptionLayer.DeriveKeyLegacy(_rcCode);

        var services = new ServiceCollection();
        services.AddRdrfCore();
        _provider = services.BuildServiceProvider();
    }

    [Fact]
    public void Constructor_NullAesKey_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new BackupOrchestrator(null!, _rcCode, _storage));
    }

    [Fact]
    public void Constructor_NullStorage_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new BackupOrchestrator(_aesKey, _rcCode, null!));
    }

    [Fact]
    public void Constructor_AcceptsInterfacesFromDi()
    {
        var fss = _provider.GetRequiredService<IFSSEngine>();
        var fsa = _provider.GetRequiredService<IFsaEngine>();
        var meta = _provider.GetRequiredService<IMetadataManager>();

        var bo = new BackupOrchestrator(_aesKey, _rcCode, _storage, fss, fsa, meta);
        Assert.NotNull(bo);
        bo.Dispose();
    }

    [Fact]
    public void RestoreFile_NonexistentFingerprint_Throws()
    {
        using var ro = new RestoreOrchestrator(_aesKey, _rcCode, _storage);
        Assert.Throws<FileNotFoundException>(() =>
            ro.RestoreFile("nonexistent_fp", Path.Combine(_dir, "out.bin")));
    }

    [Fact]
    public void RDRFEngine_BackupAndRestore_RoundTrip()
    {
        string testFile = Path.Combine(_dir, "test.bin");
        byte[] data = new byte[1024];
        RandomNumberGenerator.Fill(data);
        File.WriteAllBytes(testFile, data);

        using var engine = new RDRFEngine(_rcCode, _storage);
        string fp = engine.BackupFile(testFile, "FSS1");

        string restored = Path.Combine(_dir, "restored.bin");
        bool ok = engine.RestoreFile(fp, restored);
        Assert.True(ok);

        byte[] restoredData = File.ReadAllBytes(restored);
        Assert.Equal(data, restoredData);
    }

    [Fact]
    public void RDRFEngine_BackupAndRestore_Fss3_RoundTrip()
    {
        string testFile = Path.Combine(_dir, "test_fss3.bin");
        byte[] data = new byte[4096];
        RandomNumberGenerator.Fill(data);
        File.WriteAllBytes(testFile, data);

        using var engine = new RDRFEngine(_rcCode, _storage);
        string fp = engine.BackupFile(testFile, "FSS3");

        string restored = Path.Combine(_dir, "restored_fss3.bin");
        bool ok = engine.RestoreFile(fp, restored);
        Assert.True(ok);

        byte[] restoredData = File.ReadAllBytes(restored);
        Assert.Equal(data, restoredData);
    }

    [Fact]
    public void RDRFEngine_BackupAndRestore_Fss6_RoundTrip()
    {
        string testFile = Path.Combine(_dir, "test_fss6.bin");
        byte[] data = new byte[8192];
        RandomNumberGenerator.Fill(data);
        File.WriteAllBytes(testFile, data);

        using var engine = new RDRFEngine(_rcCode, _storage);
        string fp = engine.BackupFile(testFile, "FSS6");

        string restored = Path.Combine(_dir, "restored_fss6.bin");
        bool ok = engine.RestoreFile(fp, restored);
        Assert.True(ok);

        byte[] restoredData = File.ReadAllBytes(restored);
        Assert.Equal(data, restoredData);
    }

    [Fact]
    public void RDRFEngine_WrongPassword_Throws()
    {
        string testFile = Path.Combine(_dir, "test_wp.bin");
        File.WriteAllBytes(testFile, new byte[] { 1, 2, 3 });

        using var engine = new RDRFEngine(_rcCode, _storage);
        string fp = engine.BackupFile(testFile, "FSS1");

        byte[] wrongPw = EncryptionLayer.GenerateRcCode(32);
        using var engine2 = new RDRFEngine(wrongPw, _storage);
        string restored = Path.Combine(_dir, "restored_wp.bin");
        Assert.Throws<CryptographicException>(() =>
            engine2.RestoreFile(fp, restored));
    }

    [Fact]
    public void RDRFEngine_Dispose_ZerosKeys()
    {
        var engine = new RDRFEngine(_rcCode, _storage);
        engine.Dispose();
        // No exception on double dispose
        engine.Dispose();
    }

    [Fact]
    public void BackupOrchestrator_BackupFile_Obsolete_StillWorks()
    {
        string testFile = Path.Combine(_dir, "obsolete_test.bin");
        File.WriteAllBytes(testFile, new byte[] { 10, 20, 30, 40, 50 });

        using var bo = new BackupOrchestrator(_aesKey, _rcCode, _storage);
        string fp = bo.BackupFile(testFile, "FSS1");
        Assert.False(string.IsNullOrEmpty(fp));
        Assert.True(_storage.IndexExists(fp));
    }

    [Fact]
    public void BuildChangedFragmentsIndex_ProducesValidIndex()
    {
        var raw = new List<byte[]>
        {
            new byte[] { 1, 2, 3, 4 },
            new byte[] { 5, 6, 7, 8 },
        };
        var changed = new List<byte[]>(raw);
        var indices = new List<int> { 0, 1 };
        var flags = new[] { true, true };

        string fp = "test_fp_" + Guid.NewGuid().ToString("N");
        string hash = Convert.ToHexString(SHA256.HashData(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 })).ToLowerInvariant();

        using var bo = new BackupOrchestrator(_aesKey, _rcCode, _storage);
        var task = bo.BuildChangedFragmentsIndex(
            raw, changed, indices, flags, fp, hash, "test.bin", 8, "FSS1", 1024, null, null, null, null, CancellationToken.None);
        var index = task.GetAwaiter().GetResult();

        Assert.NotNull(index);
        Assert.Equal(fp, index.FileFingerprint);
        Assert.Equal("FSS1", index.FssStrategy);
    }

    public void Dispose()
    {
        _provider.Dispose();
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }
}
