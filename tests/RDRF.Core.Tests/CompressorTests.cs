using System.Security.Cryptography;
using System.Text;
using RDRF.Core.Compression;
using Xunit;

namespace RDRF.Core.Tests;

public class CompressorTests
{
    [Fact]
    public void RoundTrip_TextData()
    {
        // 500 bytes of repeated text (LZ4-friendly)
        var data = new byte[500];
        byte[] pattern = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog. ");
        for (int i = 0; i < data.Length; i++)
            data[i] = pattern[i % pattern.Length];
        byte[] compressed = Compressor.Compress(data, Constants.CompressionLz4);
        byte[] decompressed = Compressor.Decompress(compressed, Constants.CompressionLz4);
        Assert.Equal(data, decompressed);
    }

    [Fact]
    public void EmptyData()
    {
        byte[] data = [];
        byte[] compressed = Compressor.Compress(data, Constants.CompressionLz4);
        byte[] decompressed = Compressor.Decompress(compressed, Constants.CompressionLz4);
        Assert.Equal(data, decompressed);
    }

    [Fact]
    public void AlreadyCompressed_JpegMagic_SkipsLz4()
    {
        // FF D8 FF E0 = JPEG start marker
        byte[] data = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00];
        byte[] result = Compressor.Compress(data, Constants.CompressionLz4);
        Assert.Equal(data, result);
    }

    [Fact]
    public void AlreadyCompressed_ZipMagic_SkipsLz4()
    {
        // PK\x03\x04 = ZIP start
        byte[] data = [0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00];
        byte[] result = Compressor.Compress(data, Constants.CompressionLz4);
        Assert.Equal(data, result);
    }

    [Fact]
    public void AlreadyCompressed_GzipMagic_SkipsLz4()
    {
        // 1F 8B 08 = GZIP
        byte[] data = [0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
        byte[] result = Compressor.Compress(data, Constants.CompressionLz4);
        Assert.Equal(data, result);
    }

    [Fact]
    public void AntiExpansion_IncompressibleData_ReturnsOriginal()
    {
        // Truly random data should not expand; but if LZ4 output is larger,
        // Compress should return the original
        var data = new byte[1000];
        System.Random.Shared.NextBytes(data);
        byte[] result = Compressor.Compress(data, Constants.CompressionLz4);
        Assert.True(result.Length <= data.Length || result == data);
    }

    [Fact]
    public void NullMethod_ReturnsOriginal()
    {
        byte[] data = [1, 2, 3, 4, 5];
        byte[] result = Compressor.Compress(data, null);
        Assert.Equal(data, result);
    }

    [Fact]
    public void LargeData_RoundTrip()
    {
        // Highly compressible pattern (repeating sequence)
        var data = new byte[100_000];
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(i & 0xFF);
        byte[] compressed = Compressor.Compress(data, Constants.CompressionLz4);
        byte[] decompressed = Compressor.Decompress(compressed, Constants.CompressionLz4);
        Assert.Equal(data, decompressed);
    }

    [Fact]
    public void Decompress_NoCompression_ReturnsAsIs()
    {
        byte[] data = [10, 20, 30, 40, 50];
        byte[] result = Compressor.Decompress(data, null);
        Assert.Equal(data, result);
    }

    // -- AlwaysCompress + IsLz4Frame tests --

    [Fact]
    public void AlwaysCompress_Compressible_ReturnsLz4Frame()
    {
        var data = new byte[2000];
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(i % 256);
        byte[] compressed = Compressor.AlwaysCompress(data);
        Assert.True(compressed.Length < data.Length);
        Assert.True(Compressor.IsLz4Frame(compressed));
    }

    [Fact]
    public void AlwaysCompress_Incompressible_StillProducesLz4Frame()
    {
        // AlwaysCompress always runs LZ4, even if the output is larger than the input.
        // Use Compress() with the magic-byte check for anti-expansion.
        var data = new byte[2000];
        RandomNumberGenerator.Fill(data);
        byte[] result = Compressor.AlwaysCompress(data);
        Assert.True(Compressor.IsLz4Frame(result));
    }

    [Fact]
    public void IsLz4Frame_DetectsLz4Magic()
    {
        // LZ4 frame magic bytes: 0x04 0x22 0x4D 0x18
        var lz4Frame = new byte[] { 0x04, 0x22, 0x4D, 0x18, 0x60, 0x00, 0x00, 0x00 };
        Assert.True(Compressor.IsLz4Frame(lz4Frame));
        Assert.False(Compressor.IsLz4Frame(new byte[] { 0x00, 0x00, 0x00, 0x00 }));
    }
}
