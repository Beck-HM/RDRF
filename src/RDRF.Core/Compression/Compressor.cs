using K4os.Compression.LZ4;

namespace RDRF.Core.Compression;

public static class Compressor
{
    private static readonly HashSet<string> CompressedMagic = new(StringComparer.OrdinalIgnoreCase)
    {
        "ffd8ffe0", "ffd8ffe1", "ffd8ffe2", "ffd8ffe3", "ffd8ffe8", // JPEG
        "89504e47",                          // PNG
        "47494638",                          // GIF
        "504b0304", "504b0506", "504b0708",  // ZIP/DOCX
        "1f8b08",                            // GZIP
        "52617221",                          // RAR
        "377abcaf271c",                      // 7z
        "494433",                            // MP3 ID3v2
        "664c6143",                          // FLAC
        "4d546864",                          // MIDI
    };

    public static byte[] Compress(byte[] data, string? method)
    {
        if (method != Constants.CompressionLz4) return data;
        if (IsProbablyCompressed(data)) return data;
        var compressed = LZ4Pickler.Pickle(data, LZ4Level.L00_FAST);
        return compressed.Length < data.Length ? compressed : data;
    }

    public static byte[] Decompress(byte[] data, string? method)
    {
        return method == Constants.CompressionLz4 ? LZ4Pickler.Unpickle(data) : data;
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
