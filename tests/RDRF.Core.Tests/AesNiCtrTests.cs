using System.Security.Cryptography;
using RDRF.Core.Encryption;
using Xunit;

namespace RDRF.Core.Tests;

public class AesNiCtrTests
{
    [Fact]
    public void CtrCrypt_EmptyData_ReturnsEmpty()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] result = AesNiCtr.CtrCrypt([], key, nonce);
        Assert.Empty(result);
    }

    [Fact]
    public void CtrCrypt_SmallData_RoundTrip()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] plaintext = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];

        byte[] encrypted = AesNiCtr.CtrCrypt(plaintext, key, nonce);
        Assert.NotEqual(plaintext, encrypted);

        // Decrypt with same key+nonce
        byte[] decrypted = AesNiCtr.CtrCrypt(encrypted, key, nonce);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void CtrCrypt_LargeData_RoundTrip()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        var plaintext = new byte[100_000];
        RandomNumberGenerator.Fill(plaintext);

        byte[] encrypted = AesNiCtr.CtrCrypt(plaintext, key, nonce);
        byte[] decrypted = AesNiCtr.CtrCrypt(encrypted, key, nonce);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void CtrCrypt_DifferentNonce_ProducesDifferentOutput()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonce1 = RandomNumberGenerator.GetBytes(12);
        byte[] nonce2 = RandomNumberGenerator.GetBytes(12);
        byte[] data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];

        byte[] enc1 = AesNiCtr.CtrCrypt(data, key, nonce1);
        byte[] enc2 = AesNiCtr.CtrCrypt(data, key, nonce2);
        Assert.NotEqual(enc1, enc2);
    }

    [Fact]
    public void CtrCrypt_WrongKey_Fails()
    {
        byte[] key1 = RandomNumberGenerator.GetBytes(32);
        byte[] key2 = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];

        byte[] encrypted = AesNiCtr.CtrCrypt(data, key1, nonce);
        byte[] decrypted = AesNiCtr.CtrCrypt(encrypted, key2, nonce);
        Assert.NotEqual(data, decrypted);
    }

    [Fact]
    public void CtrCrypt_ExactBlockSize()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        // Exactly 16 bytes = one AES block
        byte[] plaintext = RandomNumberGenerator.GetBytes(16);

        byte[] encrypted = AesNiCtr.CtrCrypt(plaintext, key, nonce);
        byte[] decrypted = AesNiCtr.CtrCrypt(encrypted, key, nonce);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void CtrCrypt_CounterWraparound()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        // Nonce with counter bytes set to max - forces wraparound on first increment
        byte[] nonce = new byte[12];
        nonce[11] = 0xFF;

        // Large data forces counter increment multiple times
        var plaintext = new byte[1000];
        RandomNumberGenerator.Fill(plaintext);

        byte[] encrypted = AesNiCtr.CtrCrypt(plaintext, key, nonce);
        byte[] decrypted = AesNiCtr.CtrCrypt(encrypted, key, nonce);
        Assert.Equal(plaintext, decrypted);
    }
}
