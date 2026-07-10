using System.Security.Cryptography;
using RDRF.Core.Encryption;
using Xunit;

namespace RDRF.Core.Tests;

public class CtrTransformStreamTests
{
    [Fact]
    public void CtrTransformStream_SmallData_RoundTrip()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] original = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

        using var input = new MemoryStream(original);
        using var encrypted = new MemoryStream();
        EncryptionLayer.CtrTransformStream(input, encrypted, key, nonce);

        // Decrypt (CTR is symmetric - same operation)
        encrypted.Position = 0;
        using var decrypted = new MemoryStream();
        EncryptionLayer.CtrTransformStream(encrypted, decrypted, key, nonce);

        Assert.Equal(original, decrypted.ToArray());
    }

    [Fact]
    public void CtrTransformStream_EmptyData_ProducesEmpty()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];

        using var input = new MemoryStream();
        using var output = new MemoryStream();
        EncryptionLayer.CtrTransformStream(input, output, key, nonce);
        Assert.Equal(0, output.Length);
    }

    [Fact]
    public void CtrTransformStream_LargeData_Succeeds()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] original = new byte[100000];
        RandomNumberGenerator.Fill(original);

        using var input = new MemoryStream(original);
        using var encrypted = new MemoryStream();
        EncryptionLayer.CtrTransformStream(input, encrypted, key, nonce);

        encrypted.Position = 0;
        using var decrypted = new MemoryStream();
        EncryptionLayer.CtrTransformStream(encrypted, decrypted, key, nonce);

        Assert.Equal(original, decrypted.ToArray());
    }

    [Fact]
    public void CtrTransformStream_DifferentNonce_ProducesDifferentOutput()
    {
        byte[] key = new byte[32];
        byte[] nonce1 = new byte[12];
        byte[] nonce2 = new byte[12];
        nonce2[0] = 1;
        byte[] data = new byte[] { 1, 2, 3, 4 };

        using var input1 = new MemoryStream(data);
        using var out1 = new MemoryStream();
        EncryptionLayer.CtrTransformStream(input1, out1, key, nonce1);

        using var input2 = new MemoryStream(data);
        using var out2 = new MemoryStream();
        EncryptionLayer.CtrTransformStream(input2, out2, key, nonce2);

        Assert.NotEqual(out1.ToArray(), out2.ToArray());
    }

    [Fact]
    public void CtrTransformStream_PartialRead_Works()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] original = new byte[50];
        RandomNumberGenerator.Fill(original);

        using var input = new MemoryStream(original);
        using var encrypted = new MemoryStream();
        EncryptionLayer.CtrTransformStream(input, encrypted, key, nonce);

        // Read only first 10 bytes
        byte[] partial = new byte[10];
        encrypted.Position = 0;
        encrypted.Read(partial, 0, 10);
        Assert.Equal(10, partial.Length);
    }
}
