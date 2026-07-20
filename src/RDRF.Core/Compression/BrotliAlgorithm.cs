using System.IO.Compression;

namespace RDRF.Core.Compression;

public class BrotliAlgorithm : ICompressionAlgorithm
{
    public string Name => Constants.CompressionBrotli;

    public byte[] Compress(byte[] data, string? options = null)
    {
        var level = CompressionLevel.Optimal;
        if (!string.IsNullOrEmpty(options) && int.TryParse(options, out var lvl))
            level = lvl <= 1 ? CompressionLevel.Fastest :
                    lvl >= 9 ? CompressionLevel.SmallestSize :
                    CompressionLevel.Optimal;
        using var ms = new MemoryStream();
        using (var bs = new BrotliStream(ms, level, leaveOpen: true))
            bs.Write(data, 0, data.Length);
        byte[] result = new byte[8 + (int)ms.Length];
        BitConverter.GetBytes(data.Length).CopyTo(result, 0);
        BitConverter.GetBytes((int)ms.Length).CopyTo(result, 4);
        ms.ToArray().CopyTo(result, 8);
        return result;
    }

    public byte[] Decompress(byte[] data)
    {
        int originalSize = BitConverter.ToInt32(data, 0);
        int compressedSize = BitConverter.ToInt32(data, 4);
        using var ms = new MemoryStream(data, 8, compressedSize);
        using var bs = new BrotliStream(ms, CompressionMode.Decompress);
        byte[] result = new byte[originalSize];
        bs.ReadExactly(result);
        return result;
    }

    public bool CanHandle(byte[] data)
    {
        return data.Length >= 12;
    }
}
