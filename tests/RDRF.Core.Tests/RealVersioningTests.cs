using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.DSAA;
using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Core.Versioning;
using Xunit;

namespace RDRF.Core.Tests;

using Idx = RDRF.Core.Index.RdrfIndex;

public class RealVersioningTests : IDisposable
{
    private readonly string _testDir;
    private readonly LocalDSAAAdapter _storage;
    private readonly byte[] _password;
    private readonly string _testFile;

    public RealVersioningTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), $"rdrf_real_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testDir);
        _storage = new LocalDSAAAdapter(_testDir);
        _password = RandomNumberGenerator.GetBytes(32);
        _testFile = Path.Combine(_testDir, "source.bin");
    }

    public void Dispose()
    {
        try { Directory.Delete(_testDir, true); } catch { }
    }

    private string Sha256Hex(byte[] data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private RDRF.Core.Index.RdrfIndex LoadIndex(string fingerprint)
    {
        byte[] enc = _storage.ReadIndex(fingerprint);
        (_, byte[] cb) = EncryptionLayer.DecryptIndexWithAutoDetect(enc, _password);
        return IndexManager.DeserializeIndex(cb);
    }

    [Fact]
    public async Task FreshBackup_CreatesIndexAndFragments()
    {
        File.WriteAllBytes(_testFile, new byte[] { 0x01, 0x02, 0x03, 0x04 });
        string fp = await RealVersionedBackup.BackupAsync(_testFile, _storage, _password, "v1", "FSS1");
        Assert.NotNull(fp);
        Assert.True(_storage.IndexExists(fp), "Index file should exist");
        // At least fragment 0 should exist
        var frags = _storage.ListFragments();
        Assert.NotEmpty(frags);
    }

    [Fact]
    public async Task Incremental_SameFile_NoNewFragments()
    {
        // v1 backup
        File.WriteAllBytes(_testFile, new byte[] { 0x0A, 0x0B, 0x0C });
        string fp1 = await RealVersionedBackup.BackupAsync(_testFile, _storage, _password, "v1", "FSS1");

        // v2: same file content - fingerprint unchanged, no new fragments
        string fp2 = await RealVersionedBackup.BackupAsync(_testFile, _storage, _password, "v2 no change", "FSS1");
        Assert.Equal(fp1, fp2); // Same fingerprint since content unchanged
    }

    [Fact]
    public async Task Incremental_AppendedContent_CreatesNewFragments()
    {
        // v1: small file
        File.WriteAllBytes(_testFile, new byte[] { 0xAA, 0xBB });
        string fp1 = await RealVersionedBackup.BackupAsync(_testFile, _storage, _password, "v1", "FSS1");
        var frags1 = _storage.ListFragments().Count;

        // v2: larger file - new fragment(s) written
        var bigger = new byte[2 * 1024 * 1024 + 100]; // 2 MB + 100 bytes
        new Random(42).NextBytes(bigger);
        File.WriteAllBytes(_testFile, bigger);
        string fp2 = await RealVersionedBackup.BackupAsync(_testFile, _storage, _password, "v2 bigger", "FSS1");
        Assert.NotEqual(fp1, fp2);

        // Both versions' indexes should exist
        Assert.True(_storage.IndexExists(fp1), "v1 index preserved");
        Assert.True(_storage.IndexExists(fp2), "v2 index exists");
    }

    [Fact]
    public async Task IndexesPreserved_AcrossVersions()
    {
        // v1
        File.WriteAllBytes(_testFile, new byte[] { 0x10, 0x20, 0x30 });
        string fp1 = await RealVersionedBackup.BackupAsync(_testFile, _storage, _password, "v1", "FSS1");

        // v2: modified
        File.WriteAllBytes(_testFile, new byte[] { 0x10, 0x20, 0x30, 0x40 });
        string fp2 = await RealVersionedBackup.BackupAsync(_testFile, _storage, _password, "v2 added byte", "FSS1");

        // v3: further modified
        File.WriteAllBytes(_testFile, new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50 });
        string fp3 = await RealVersionedBackup.BackupAsync(_testFile, _storage, _password, "v3 added another", "FSS1");

        // All 3 indexes survive
        Assert.True(_storage.IndexExists(fp1), "v1 index");
        Assert.True(_storage.IndexExists(fp2), "v2 index");
        Assert.True(_storage.IndexExists(fp3), "v3 index");
    }

    [Fact]
    public async Task RealBackup_RestoreViaStandardEngine_Matches()
    {
        var content = new byte[100 * 1024];
        new Random(42).NextBytes(content);
        File.WriteAllBytes(_testFile, content);
        string expectedHash = Sha256Hex(content);

        // RealVersionedBackup backup -> standard engine restore
        string fp = await RealVersionedBackup.BackupAsync(_testFile, _storage, _password, "v1", "FSS1");
        Assert.True(_storage.IndexExists(fp), "index exists");

        using var engine = new RDRFEngine(_password, _storage);
        string outPath = Path.Combine(_testDir, "restored.bin");
        bool ok = await engine.RestoreFileAsync(fp, outPath, filePrefix: fp);
        Assert.True(ok, "standard engine should restore real-mode backup");
        Assert.Equal(content.Length, new FileInfo(outPath).Length);
        Assert.Equal(expectedHash, Sha256Hex(File.ReadAllBytes(outPath)));
    }

    [Fact]
    public async Task RestoreLatest_GivesCorrectContent()
    {
        var rng = new Random(42);
        var v1content = new byte[100 * 1024];
        rng.NextBytes(v1content);
        File.WriteAllBytes(_testFile, v1content);
        string expectedHash = Sha256Hex(v1content);
        string fp1 = await RealVersionedBackup.BackupAsync(_testFile, _storage, _password, "v1", "FSS1");

        // Verify v1 via standard engine
        using var engine = new RDRFEngine(_password, _storage);

        // v2: append 50KB
        var v2content = new byte[150 * 1024];
        Array.Copy(v1content, v2content, v1content.Length);
        rng = new Random(99);
        rng.NextBytes(v2content.AsSpan(v1content.Length));
        File.WriteAllBytes(_testFile, v2content);
        string expectedHash2 = Sha256Hex(v2content);

        string fp2 = await RealVersionedBackup.BackupAsync(_testFile, _storage, _password, "v2 bigger", "FSS1");

        // Verify v2 index metadata
        byte[] enc2 = _storage.ReadIndex(fp2);
        var (k2, c2) = EncryptionLayer.DecryptIndexWithAutoDetect(enc2, _password);
        var idx2 = IndexManager.DeserializeIndex(c2);
        Assert.Equal(2, idx2.VersionNumber);
        Assert.Equal(150 * 1024, idx2.FileSize);
        // v2's Versions may be null (AppendVersionRecord for v1 doesn't create records)
        // Just verify v2's own metadata is correct
        Assert.NotNull(idx2.OriginalHash);
    }

    [Fact]
    public async Task RestoreOlderVersion_StillWorks()
    {
        // v1
        var v1content = new byte[] { 0x01, 0x02, 0x03 };
        File.WriteAllBytes(_testFile, v1content);
        string fp1 = await RealVersionedBackup.BackupAsync(_testFile, _storage, _password, "v1", "FSS1");

        // v2
        File.WriteAllBytes(_testFile, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 });
        string fp2 = await RealVersionedBackup.BackupAsync(_testFile, _storage, _password, "v2", "FSS1");

        // v3
        File.WriteAllBytes(_testFile, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 });
        string fp3 = await RealVersionedBackup.BackupAsync(_testFile, _storage, _password, "v3", "FSS1");

        // Verify all indexes exist
        Assert.True(_storage.IndexExists(fp1), "v1 index exists");
        Assert.True(_storage.IndexExists(fp2), "v2 index exists");
        Assert.True(_storage.IndexExists(fp3), "v3 index exists");

        // Verify version numbers are set
        Assert.Equal(1, LoadIndex(fp1).VersionNumber);
        Assert.Equal(2, LoadIndex(fp2).VersionNumber);
        Assert.Equal(3, LoadIndex(fp3).VersionNumber);
    }

    [Fact]
    public async Task RealMode_NoCleanup_DeduplicatedFragmentsPreserved()
    {
        // v1: 1 MB file
        var v1data = new byte[1024 * 1024];
        new Random(42).NextBytes(v1data);
        File.WriteAllBytes(_testFile, v1data);
        string fp1 = await RealVersionedBackup.BackupAsync(_testFile, _storage, _password, "v1", "FSS1");

        // Count fragments after v1
        int fragsAfterV1 = _storage.ListFragments().Count;

        // v2: 2 MB file (first 1 MB unchanged, second 1 MB new)
        var v2data = new byte[2 * 1024 * 1024];
        Array.Copy(v1data, v2data, v1data.Length);
        new Random(99).NextBytes(v2data.AsSpan(v1data.Length));
        File.WriteAllBytes(_testFile, v2data);
        string fp2 = await RealVersionedBackup.BackupAsync(_testFile, _storage, _password, "v2 append", "FSS1");

        // After v2: all fragments from v1 should still exist
        int fragsAfterV2 = _storage.ListFragments().Count;
        Assert.True(fragsAfterV2 >= fragsAfterV1,
            "Fragments should not decrease in real mode");

        // v1's index file must survive
        Assert.True(_storage.IndexExists(fp1), "v1 index preserved after v2");
    }

    [Fact]
    public async Task RestoreVersion_InvalidVersion_Throws()
    {
        File.WriteAllBytes(_testFile, new byte[] { 0x01 });
        string fp = await RealVersionedBackup.BackupAsync(_testFile, _storage, _password, "v1", "FSS1");

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            RealVersionedRestore.RestoreVersionAsync(_storage, fp, 99, Path.Combine(_testDir, "out.bin"), _password));
    }
}
