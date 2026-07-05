using RDRF.Core.Abstractions;

namespace RDRF.Core.Compression;

public class CompressorWrapper : ICompressor
{
    public byte[] Compress(byte[] data, string? method) => Compressor.Compress(data, method);
    public byte[] Decompress(byte[] data, string? method) => Compressor.Decompress(data, method);
    public byte[] AlwaysCompress(byte[] data) => Compressor.AlwaysCompress(data);
    public bool IsLz4Frame(byte[] data) => Compressor.IsLz4Frame(data);
}
