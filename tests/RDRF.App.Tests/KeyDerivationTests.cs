using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Core.Dssa;
using Xunit;

namespace RDRF.App.Tests;

public class KeyDerivationTests
{
    [Fact]
    public void DeriveKey_WithSalt_ReturnsPbkdf2Key()
    {
        var password = RandomNumberGenerator.GetBytes(32);
        var salt = RandomNumberGenerator.GetBytes(32);
        var key = EncryptionLayer.DeriveKey(password, salt);
        Assert.Equal(32, key.Length);
    }

    [Fact]
    public void DeriveKey_WithoutSalt_ReturnsSha256()
    {
        var password = RandomNumberGenerator.GetBytes(32);
        var legacy = EncryptionLayer.DeriveKey(password);
        byte[] expected = System.Security.Cryptography.SHA256.HashData(password);
        Assert.Equal(expected, legacy);
    }

    [Fact]
    public void DecryptIndexWithAutoDetect_NewFormat_Succeeds()
    {
        using var dir = new Fixtures.TempDir();
        byte[] password = RandomNumberGenerator.GetBytes(32);
        byte[] salt = RandomNumberGenerator.GetBytes(32);
        var storage = new LocalDssaAdapter(dir.Path);

        using var orchestrator = new BackupOrchestrator(password, salt, storage);
        string input = dir.CreateTextFile("test.txt", "Auto-detect new format test content.");
        string fp = orchestrator.BackupFile(input, "FSS1");

        byte[] encIdx = storage.ReadIndex(fp);
        var (aesKey, cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encIdx, password);
        var index = IndexManager.DeserializeIndex(cbor);

        Assert.Equal(fp, index.FileFingerprint);
        Assert.NotNull(aesKey);
        Assert.True(cbor.Length > 0);
    }

    [Fact]
    public void DecryptIndexWithAutoDetect_LegacyFormat_Succeeds()
    {
        using var dir = new Fixtures.TempDir();
        byte[] password = RandomNumberGenerator.GetBytes(32);
        var storage = new LocalDssaAdapter(dir.Path);

        using var engine = new RDRFEngine(password, storage);
        string input = dir.CreateTextFile("test.txt", "Auto-detect legacy format test.");
        string fp = engine.BackupFile(input, "FSS1");

        byte[] encIdx = storage.ReadIndex(fp);
        var (aesKey, cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encIdx, password);
        var index = IndexManager.DeserializeIndex(cbor);

        Assert.Equal(fp, index.FileFingerprint);
        Assert.NotNull(aesKey);
    }

    [Fact]
    public void DecryptIndexWithAutoDetect_WrongPassword_Throws()
    {
        using var dir = new Fixtures.TempDir();
        byte[] password = RandomNumberGenerator.GetBytes(32);
        byte[] wrongPwd = RandomNumberGenerator.GetBytes(32);
        var storage = new LocalDssaAdapter(dir.Path);

        using var engine = new RDRFEngine(password, storage);
        string input = dir.CreateTextFile("test.txt", "Wrong password test.");
        string fp = engine.BackupFile(input, "FSS1");

        byte[] encIdx = storage.ReadIndex(fp);
        Assert.ThrowsAny<CryptographicException>(() =>
            EncryptionLayer.DecryptIndexWithAutoDetect(encIdx, wrongPwd));
    }

    [Fact]
    public void AutoDetect_KnownSalt_MatchesDeriveKey()
    {
        using var dir = new Fixtures.TempDir();
        byte[] password = RandomNumberGenerator.GetBytes(32);
        byte[] salt = RandomNumberGenerator.GetBytes(32);
        var storage = new LocalDssaAdapter(dir.Path);

        using var orchestrator = new BackupOrchestrator(password, salt, storage);
        string input = dir.CreateTextFile("test.txt", "Salt match test.");
        string fp = orchestrator.BackupFile(input, "FSS1");

        byte[] encIdx = storage.ReadIndex(fp);
        byte[] saltFromPrefix = encIdx.AsSpan(0, 32).ToArray();
        byte[] aesKey = EncryptionLayer.DeriveKey(password, saltFromPrefix);

        // Decrypt with the derived key directly (without auto-detect)
        byte[] encrypted = encIdx[32..];
        byte[] cbor = EncryptionLayer.DecryptIndexWithKey(encrypted, aesKey);
        var index = IndexManager.DeserializeIndex(cbor);
        Assert.NotNull(index);
    }
}
