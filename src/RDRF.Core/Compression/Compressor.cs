using K4os.Compression.LZ4;
using K4os.Compression.LZ4.Streams;
using System.Buffers;

namespace RDRF.Core.Compression;

public static class Compressor
{
    private static readonly HashSet<string> CompressedMagic = new(StringComparer.OrdinalIgnoreCase)
    {
        "ffd8ffe0", "ffd8ffe1", "ffd8ffe2", "ffd8ffe3", "ffd8ffe8",
        "89504e47", "47494638", "504b0304", "504b0506", "504b0708",
        "1f8b08", "52617221", "377abcaf271c", "494433", "664c6143", "4d546864",
    };

    public static bool IsLz4Frame(byte[] data)
    {
        return data.Length >= 4 && data[0] == 0x04 && data[1] == 0x22 && data[2] == 0x4D && data[3] == 0x18;
    }

    public static byte[] AlwaysCompress(byte[] data)
    {
        var writer = new ArrayBufferWriter<byte>();
        LZ4Frame.Encode(data.AsSpan(), writer, LZ4Level.L00_FAST, 0);
        return writer.WrittenSpan.ToArray();
    }

    public static byte[] Compress(byte[] data, string? method)
    {
        if (method != Constants.CompressionLz4) return data;
        if (IsProbablyCompressed(data)) return data;
        var writer = new ArrayBufferWriter<byte>();
        LZ4Frame.Encode(data.AsSpan(), writer, LZ4Level.L00_FAST, 0);
        var compressed = writer.WrittenSpan.ToArray();
        return compressed.Length < data.Length ? compressed : data;
    }

    public static byte[] Decompress(byte[] data, string? method)
    {
        if (method != Constants.CompressionLz4) return data;
        var writer = new ArrayBufferWriter<byte>();
        LZ4Frame.Decode(data.AsSpan(), writer, 0);
        return writer.WrittenSpan.ToArray();
    }

    private static bool IsProbablyCompressed(byte[] data)
    {
        if (data.Length < 4) return false;
        string hex = Convert.ToHexString(data.AsSpan(0, Math.Min(16, data.Length)));
        foreach (string magic in CompressedMagic)
            if (hex.StartsWith(magic, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }
}
