using System.IO.Compression;

namespace RDRF.Core.Compression;

public class GzipAlgorithm : ICompressionAlgorithm
{
    public string Name => Constants.CompressionGzip;

    public byte[] Compress(byte[] data, string? options = null)
    {
        var level = CompressionLevel.Optimal;
        if (!string.IsNullOrEmpty(options) && int.TryParse(options, out var lvl))
            level = lvl <= 1 ? CompressionLevel.Fastest :
                    lvl >= 9 ? CompressionLevel.SmallestSize :
                    CompressionLevel.Optimal;
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, level, leaveOpen: true))
            gz.Write(data, 0, data.Length);
        byte[] result = new byte[8 + (int)ms.Length];
        BitConverter.GetBytes(data.Length).CopyTo(result, 0);
        BitConverter.GetBytes((int)ms.Length - 0).CopyTo(result, 4);
        ms.ToArray().CopyTo(result, 8);
        return result;
    }

    public byte[] Decompress(byte[] data)
    {
        int originalSize = BitConverter.ToInt32(data, 0);
        int compressedSize = BitConverter.ToInt32(data, 4);
        using var ms = new MemoryStream(data, 8, compressedSize);
        using var gz = new GZipStream(ms, CompressionMode.Decompress);
        byte[] result = new byte[originalSize];
        gz.ReadExactly(result);
        return result;
    }

    public bool CanHandle(byte[] data)
    {
        return data.Length >= 10 && data[8] == 0x1F && data[9] == 0x8B;
    }
}
