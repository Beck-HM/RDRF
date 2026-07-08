using System.Security.Cryptography;
using RDRF.Core.Dssa;
using RDRF.Core.Encryption;
using RDRF.Core.Index;
using Xunit;

namespace RDRF.Core.Tests;

public class EncryptionTests
{
    [Fact]
    public void GenerateRcCode_ShouldReturnCorrectLength()
    {
        byte[] rc = EncryptionLayer.GenerateRcCode(32);
        Assert.Equal(32, rc.Length);
    }

    [Fact]
    public void DeriveKey_ShouldReturn32Bytes()
    {
        byte[] rc = EncryptionLayer.GenerateRcCode(64);
        byte[] key = EncryptionLayer.DeriveKeyLegacy(rc);
        Assert.Equal(32, key.Length);
    }

    [Fact]
    public void EncryptDecryptFragment_ShouldRoundTrip()
    {
        byte[] rc = EncryptionLayer.GenerateRcCode(32);
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("Hello RDRF! This is a test.");

        byte[] encrypted = EncryptionLayer.EncryptFragmentWithKey(plaintext, rc);
        byte[] decrypted = EncryptionLayer.DecryptFragmentWithKey(encrypted, rc);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptDecryptIndex_ShouldRoundTrip()
    {
        byte[] rc = EncryptionLayer.GenerateRcCode(32);
        byte[] plaintext = [0x01, 0x02, 0x03, 0x04];

        byte[] encrypted = EncryptionLayer.EncryptIndex(plaintext, rc);
        byte[] decrypted = EncryptionLayer.DecryptIndex(encrypted, rc);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void WrongKey_ProducesDifferentData()
    {
        byte[] rc1 = EncryptionLayer.GenerateRcCode(32);
        byte[] rc2 = EncryptionLayer.GenerateRcCode(32);
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("Test data");

        byte[] encrypted = EncryptionLayer.EncryptFragmentWithKey(plaintext, rc1);
        byte[] decrypted = EncryptionLayer.DecryptFragmentWithKey(encrypted, rc2);

        Assert.NotEqual(plaintext, decrypted);
    }

    [Fact]
    public void DecryptAndStripFragment_WithHeader_RoundTrips()
    {
        byte[] aesKey = RandomNumberGenerator.GetBytes(32);
        byte[] plaintext = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];

        // Encrypt with embedded index header
        byte[] embeddedIndex = [0x0A, 0x0B, 0x0C, 0x0D];
        byte[] fileData = FragmentFileHeader.EncryptWithEmbeddedIndex(plaintext, embeddedIndex, aesKey);

        // DecryptAndStripFragment should strip both header and embedded index
        byte[] result = EncryptionLayer.DecryptAndStripFragment(fileData, aesKey);
        Assert.Equal(plaintext, result);
    }

    [Fact]
    public void DecryptAndStripFragment_WithoutHeader_PassThrough()
    {
        byte[] aesKey = RandomNumberGenerator.GetBytes(32);
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("No header test data.");

        // Encrypt without header (raw fragment)
        byte[] nonce = RandomNumberGenerator.GetBytes(Constants.NonceLength);
        byte[] encrypted = EncryptionLayer.EncryptFragmentCtrWithKey(plaintext, aesKey, nonce);

        // The encrypted output is just nonce + ciphertext, no file header
        byte[] result = EncryptionLayer.DecryptAndStripFragment(encrypted, aesKey);
        Assert.Equal(plaintext, result);
    }

    [Fact]
    public void DecryptAndStripFragment_LargeData()
    {
        byte[] aesKey = RandomNumberGenerator.GetBytes(32);
        var plaintext = new byte[100_000];
        RandomNumberGenerator.Fill(plaintext);

        byte[] embeddedIndex = [0x00, 0x01, 0x02, 0x03];
        byte[] fileData = FragmentFileHeader.EncryptWithEmbeddedIndex(plaintext, embeddedIndex, aesKey);

        byte[] result = EncryptionLayer.DecryptAndStripFragment(fileData, aesKey);
        Assert.Equal(plaintext, result);
    }

    // -- Auto-detect format switching tests --

    [Fact]
    public void DecryptIndexWithAutoDetect_SaltPrefixed_ReturnsKeyAndCbor()
    {
        byte[] rc = EncryptionLayer.GenerateRcCode(32);
        var index = IndexManager.BuildIndex(
            fileFingerprint: "fp123",
            originalFilename: "test.bin",
            originalSize: 100,
            fragmentHashes: new List<string> { "h1" },
            originalHash: "oh",
            fssStrategy: "FSS1",
            originalFragmentSizes: new List<int> { 100 },
            originalFragmentCount: 1);
        byte[] indexBytes = IndexManager.SerializeIndex(index);
        byte[] saltPrefixed = EncryptionLayer.EncryptIndexWithSaltPrefix(indexBytes, rc, out byte[] salt);
        Assert.NotNull(salt);
        Assert.Equal(Constants.SaltPrefixLength, salt.Length);

        var (aesKey, cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(saltPrefixed, rc);
        Assert.Equal(32, aesKey.Length);

        var deserialized = IndexManager.DeserializeIndex(cbor);
        Assert.Equal("fp123", deserialized.FileFingerprint);
        Assert.Equal("test.bin", deserialized.OriginalName);
    }

    [Fact]
    public void DecryptIndexWithAutoDetect_LegacyFormat_StillWorks()
    {
        byte[] rc = EncryptionLayer.GenerateRcCode(32);
        var index = IndexManager.BuildIndex(
            fileFingerprint: "legacy_fp",
            originalFilename: "legacy.bin",
            originalSize: 200,
            fragmentHashes: new List<string> { "h1" },
            originalHash: "oh",
            fssStrategy: "FSS1",
            originalFragmentSizes: new List<int> { 200 },
            originalFragmentCount: 1);
        byte[] indexBytes = IndexManager.SerializeIndex(index);
        byte[] aesKey = EncryptionLayer.DeriveKeyLegacy(rc);
        byte[] encrypted = EncryptionLayer.EncryptIndexWithKey(indexBytes, aesKey);

        var (decryptedKey, cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encrypted, rc);
        Assert.Equal(aesKey, decryptedKey);

        var deserialized = IndexManager.DeserializeIndex(cbor);
        Assert.Equal("legacy_fp", deserialized.FileFingerprint);
    }

    [Fact]
    public void DecryptIndexWithAutoDetect_WrongPassword_Throws()
    {
        byte[] rc = EncryptionLayer.GenerateRcCode(32);
        var index = IndexManager.BuildIndex(
            fileFingerprint: "fp_wrong",
            originalFilename: "secret.bin",
            originalSize: 50,
            fragmentHashes: new List<string> { "h1" },
            originalHash: "oh",
            fssStrategy: "FSS1",
            originalFragmentSizes: new List<int> { 50 },
            originalFragmentCount: 1);
        byte[] indexBytes = IndexManager.SerializeIndex(index);
        byte[] encrypted = EncryptionLayer.EncryptIndexWithSaltPrefix(indexBytes, rc, out _);

        byte[] wrongRc = EncryptionLayer.GenerateRcCode(32);
        Assert.Throws<CryptographicException>(() =>
            EncryptionLayer.DecryptIndexWithAutoDetect(encrypted, wrongRc));
    }
}


