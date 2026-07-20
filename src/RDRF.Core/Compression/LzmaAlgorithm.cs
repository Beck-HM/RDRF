using SevenZip.Compression.LZMA;

namespace RDRF.Core.Compression;

public class LzmaAlgorithm : ICompressionAlgorithm
{
    public string Name => Constants.CompressionLzma;

    public byte[] Compress(byte[] data, string? options = null)
    {
        int dictSize = 1 << 23;
        if (!string.IsNullOrEmpty(options) && int.TryParse(options, out var lvl) && lvl >= 1 && lvl <= 9)
            dictSize = 1 << (16 + lvl);
        using var ms = new MemoryStream();
        var enc = new Encoder();
        enc.WriteCoderProperties(ms);
        ms.Write(BitConverter.GetBytes((long)data.Length));
        enc.Code(new MemoryStream(data), ms, data.Length, -1, null);
        byte[] comp = ms.ToArray();
        byte[] result = new byte[8 + comp.Length];
        BitConverter.GetBytes(data.Length).CopyTo(result, 0);
        BitConverter.GetBytes(comp.Length).CopyTo(result, 4);
        comp.CopyTo(result, 8);
        return result;
    }

    public byte[] Decompress(byte[] data)
    {
        int originalSize = BitConverter.ToInt32(data, 0);
        int compressedSize = BitConverter.ToInt32(data, 4);
        using var ms = new MemoryStream(data, 8, compressedSize);
        var dec = new Decoder();
        byte[] props = new byte[5];
        ms.ReadExactly(props);
        long outSize = new BinaryReader(ms).ReadInt64();
        using var outMs = new MemoryStream();
        dec.SetDecoderProperties(props);
        dec.Code(ms, outMs, ms.Length - ms.Position, outSize, null);
        outMs.Position = 0;
        byte[] result = new byte[originalSize];
        outMs.ReadExactly(result);
        return result;
    }

    public bool CanHandle(byte[] data)
    {
        return data.Length >= 12;
    }
}
