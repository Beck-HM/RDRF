using K4os.Compression.LZ4;

namespace RDRF.Core.Compression;

public static class Compressor
{
    public static byte[] Compress(byte[] data, string? method)
    {
        if (method != Constants.CompressionLz4) return data;
        var compressed = LZ4Pickler.Pickle(data, LZ4Level.L00_FAST);
        return compressed.Length < data.Length ? compressed : data;
    }

    public static byte[] Decompress(byte[] data, string? method)
    {
        return method == Constants.CompressionLz4 ? LZ4Pickler.Unpickle(data) : data;
    }
}
