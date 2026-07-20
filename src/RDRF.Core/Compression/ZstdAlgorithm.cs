using ZstdSharp;

namespace RDRF.Core.Compression;

public class ZstdAlgorithm : ICompressionAlgorithm
{
    public string Name => Constants.CompressionZstd;

    public byte[] Compress(byte[] data, string? options = null)
    {
        int level = 3;
        if (!string.IsNullOrEmpty(options) && int.TryParse(options, out var lvl) && lvl >= 1 && lvl <= 22)
            level = lvl;
        byte[] raw = Zstd.Compress(data, level);
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
        return Zstd.Decompress(data.AsSpan(8, compressedSize).ToArray(), originalSize);
    }

    public bool CanHandle(byte[] data)
    {
        return data.Length >= 12
            && data[8] == 0x28 && data[9] == 0xB5 && data[10] == 0x2F && data[11] == 0xFD;
    }
}
