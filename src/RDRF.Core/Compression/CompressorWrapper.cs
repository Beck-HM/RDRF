using RDRF.Core.Abstractions;

namespace RDRF.Core.Compression;

public class CompressorWrapper : ICompressor
{
    public byte[] Compress(byte[] data, string? method = null, string? options = null)
        => Compressor.Compress(data, method ?? Constants.CompressionLz4, options);

    public byte[] Decompress(byte[] data, string? method)
        => Compressor.Decompress(data, method ?? Constants.CompressionLz4);

    public byte[] AlwaysCompress(byte[] data, string? method = null, string? options = null)
        => Compressor.AlwaysCompress(data, method, options);

    public bool IsLz4Frame(byte[] data)
        => Compressor.IsLz4Frame(data);
}
