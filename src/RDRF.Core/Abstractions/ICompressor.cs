namespace RDRF.Core.Abstractions;

public interface ICompressor
{
    byte[] Compress(byte[] data, string? method);
    byte[] Decompress(byte[] data, string? method);
    byte[] AlwaysCompress(byte[] data);
    bool IsLz4Frame(byte[] data);
}
