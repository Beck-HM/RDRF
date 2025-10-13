using System.Security.Cryptography;
using RDRF.Core.Dssa;
using RDRF.Core.Encryption;
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
}


