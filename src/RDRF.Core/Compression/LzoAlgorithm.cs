using MiniLZO;

namespace RDRF.Core.Compression;

public class LzoAlgorithm : ICompressionAlgorithm
{
    public string Name => Constants.CompressionLzo;

    public byte[] Compress(byte[] data, string? options = null)
    {
        byte[] raw = MiniLZO.MiniLZO.Compress(data);
        byte[] result = new byte[8 + raw.Length];
        BitConverter.GetBytes(data.Length).CopyTo(result, 0);
        BitConverter.GetBytes(raw.Length).CopyTo(result, 4);
        Array.Copy(raw, 0, result, 8, raw.Length);
        return result;
    }

    public byte[] Decompress(byte[] data)
    {
        int originalSize = BitConverter.ToInt32(data, 0);
        int compressedSize = BitConverter.ToInt32(data, 4);
        return MiniLZO.MiniLZO.Decompress(data.AsSpan(8, compressedSize).ToArray(), originalSize);
    }

    public bool CanHandle(byte[] data)
    {
        return data.Length >= 12;
    }
}
