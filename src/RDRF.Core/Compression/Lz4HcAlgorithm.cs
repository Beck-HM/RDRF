using K4os.Compression.LZ4;
using K4os.Compression.LZ4.Streams;
using System.Buffers;

namespace RDRF.Core.Compression;

public class Lz4HcAlgorithm : ICompressionAlgorithm
{
    public string Name => Constants.CompressionLz4Hc;

    public byte[] Compress(byte[] data, string? options = null)
    {
        int level = 9;
        if (!string.IsNullOrEmpty(options) && int.TryParse(options, out var lvl) && lvl >= 3 && lvl <= 12)
            level = lvl;
        var writer = new ArrayBufferWriter<byte>();
        LZ4Frame.Encode(data.AsSpan(), writer, (LZ4Level)level, 0);
        return writer.WrittenSpan.ToArray();
    }

    public byte[] Decompress(byte[] data)
    {
        var writer = new ArrayBufferWriter<byte>();
        LZ4Frame.Decode(data.AsSpan(), writer, 0);
        return writer.WrittenSpan.ToArray();
    }

    public bool CanHandle(byte[] data)
    {
        return data.Length >= 4 && data[0] == 0x04 && data[1] == 0x22 && data[2] == 0x4D && data[3] == 0x18;
    }
}
