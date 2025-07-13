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
        byte[] key = EncryptionLayer.DeriveKey(rc);
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
}
