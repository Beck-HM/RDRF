using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Core.Storage;
using Xunit;

namespace RDRF.App.Tests;

public class DecryptTests
{
    [Fact]
    public void LoadFromIndex_ReturnsCorrectFields()
    {
        using var dir = new Fixtures.TempDir();
        byte[] password = RandomNumberGenerator.GetBytes(32);
        string originalName = "test_doc.txt";
        string input = dir.CreateTextFile(originalName, "Load index test content.");
        string fp = Fixtures.BackupHelpers.Backup(password, input, dir.Path, "FSS1");

        var storage = new LocalFileAdapter(dir.Path);
        byte[] encIdx = storage.ReadIndex(fp);
        (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encIdx, password);
        var index = IndexManager.DeserializeIndex(cbor);

        Assert.Equal(originalName, index.OriginalName);
        Assert.True(index.FileSize > 0);
        Assert.Equal("FSS1", index.FssStrategy);
        Assert.True(index.FragmentCount > 0);
    }

    [Fact]
    public void ScanFragments_AllAvailable()
    {
        using var dir = new Fixtures.TempDir();
        byte[] password = RandomNumberGenerator.GetBytes(32);
        string input = dir.CreateFile("test.bin", 1_000_000);
        string fp = Fixtures.BackupHelpers.Backup(password, input, dir.Path, "FSS3");

        var storage = new LocalFileAdapter(dir.Path);
        byte[] encIdx = storage.ReadIndex(fp);
        (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encIdx, password);
        var index = IndexManager.DeserializeIndex(cbor);

        int available = 0;
        string prefix = index.CustomName ?? fp;
        for (int i = 0; i < index.FragmentCount; i++)
        {
            if (storage.FragmentExists($"{prefix}_{i}.rdrf"))
                available++;
        }
        Assert.Equal(index.FragmentCount, available);
    }

    [Theory]
    [InlineData("FSS1")]
    [InlineData("FSS3")]
    [InlineData("FSS5")]
    public void RestoreFromFragments_Works(string strategy)
    {
        using var dir = new Fixtures.TempDir();
        byte[] password = RandomNumberGenerator.GetBytes(32);
        string input = dir.CreateFile("test.bin", 500_000);
        var storage = new LocalFileAdapter(dir.Path);

        using var engine = new RDRFEngine(password, storage);
        string fp = engine.BackupFile(input, strategy);

        byte[] encIdx = storage.ReadIndex(fp);
        (byte[] aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encIdx, password);
        var index = IndexManager.DeserializeIndex(cbor);
        string prefix = index.CustomName ?? fp;

        // Recreate engine with preDerived key (like DecryptService does)
        using var restoreEngine = new RDRFEngine(aesKey, storage, preDerived: true, recoveryCode: password);

        string output = dir["restored.bin"];
        bool ok = restoreEngine.RestoreFileFromIndexData(encIdx, prefix, output);
        Assert.True(ok);
        Assert.Equal(Fixtures.BackupHelpers.ReadAllBytes(input), Fixtures.BackupHelpers.ReadAllBytes(output));
    }

    [Fact]
    public void WrongPassword_Fails()
    {
        using var dir = new Fixtures.TempDir();
        byte[] password = RandomNumberGenerator.GetBytes(32);
        byte[] wrongPwd = RandomNumberGenerator.GetBytes(32);
        string input = dir.CreateTextFile("test.txt", "Wrong password test.");
        string fp = Fixtures.BackupHelpers.Backup(password, input, dir.Path, "FSS1");

        var storage = new LocalFileAdapter(dir.Path);
        byte[] encIdx = storage.ReadIndex(fp);
        Assert.ThrowsAny<CryptographicException>(() =>
            EncryptionLayer.DecryptIndexWithAutoDetect(encIdx, wrongPwd));
    }

    [Fact]
    public void MissingFragments_Fails()
    {
        using var dir = new Fixtures.TempDir();
        byte[] password = RandomNumberGenerator.GetBytes(32);
        string input = dir.CreateFile("test.bin", 500_000);
        string fp = Fixtures.BackupHelpers.Backup(password, input, dir.Path, "FSS3");

        // Delete one fragment
        var storage = new LocalFileAdapter(dir.Path);
        byte[] encIdx = storage.ReadIndex(fp);
        (byte[] aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encIdx, password);
        var index = IndexManager.DeserializeIndex(cbor);
        string prefix = index.CustomName ?? fp;

        // Delete the first fragment
        string frag0 = $"{prefix}_0.rdrf";
        if (storage.FragmentExists(frag0))
            storage.DeleteFragment(frag0);

        using var restoreEngine = new RDRFEngine(aesKey, storage, preDerived: true, recoveryCode: password);
        string output = dir["restored_fail.bin"];
        bool ok = restoreEngine.RestoreFileFromIndexData(encIdx, prefix, output, allowFssRecovery: false);
        Assert.False(ok);
    }

    [Fact]
    public void CorruptedIndex_Throws()
    {
        using var dir = new Fixtures.TempDir();
        byte[] password = RandomNumberGenerator.GetBytes(32);
        string input = dir.CreateTextFile("test.txt", "Corrupted index test.");
        string fp = Fixtures.BackupHelpers.Backup(password, input, dir.Path, "FSS1");

        var storage = new LocalFileAdapter(dir.Path);
        byte[] encIdx = storage.ReadIndex(fp);
        // Corrupt the salt prefix (first 32 bytes) so PBKDF2 key derivation changes
        encIdx[15] ^= 0xFF;

        Assert.ThrowsAny<CryptographicException>(() =>
            EncryptionLayer.DecryptIndexWithAutoDetect(encIdx, password));
    }
}
