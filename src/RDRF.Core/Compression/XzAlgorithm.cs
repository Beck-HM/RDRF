using SevenZip.Compression.LZMA;

namespace RDRF.Core.Compression;

public class XzAlgorithm : ICompressionAlgorithm
{
    public string Name => Constants.CompressionXz;

    private static readonly byte[] Magic = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];

    public byte[] Compress(byte[] data, string? options = null)
    {
        byte[] lzma2 = EncodeLzma2(data);
        uint dataCrc = Crc32.Compute(data, 0, data.Length);
        byte[] result = BuildXzStream(lzma2, data.Length, dataCrc);
        return result.Length < data.Length ? result : data;
    }

    public byte[] Decompress(byte[] data)
    {
        (byte[] lzma2, int uncompressedSize, uint expectedCrc) = ParseXzStream(data);
        byte[] result = DecodeLzma2(lzma2, uncompressedSize);
        uint actualCrc = Crc32.Compute(result, 0, result.Length);
        if (actualCrc != expectedCrc)
            throw new InvalidDataException($"XZ decompression CRC32 mismatch: expected 0x{expectedCrc:X8}, got 0x{actualCrc:X8}");
        return result;
    }

    public bool CanHandle(byte[] data)
    {
        if (data.Length < Magic.Length) return false;
        for (int i = 0; i < Magic.Length; i++)
            if (data[i] != Magic[i]) return false;
        return true;
    }

    // --- LZMA2 via LZMA-SDK ---

    private static byte[] EncodeLzma2(byte[] data)
    {
        using var input = new MemoryStream(data);
        using var output = new MemoryStream();
        var encoder = new Encoder();
        using var propStream = new MemoryStream();
        encoder.WriteCoderProperties(propStream);
        propStream.Position = 0;
        byte[] props = new byte[5];
        propStream.Read(props, 0, 5);
        output.Write(props, 0, 5);
        encoder.Code(input, output, data.Length, -1, null);
        return output.ToArray();
    }

    private static byte[] DecodeLzma2(byte[] lzma2, int uncompressedSize)
    {
        using var input = new MemoryStream(lzma2, 5, lzma2.Length - 5);
        using var output = new MemoryStream();
        var decoder = new Decoder();
        byte[] props = new byte[5];
        Array.Copy(lzma2, 0, props, 0, 5);
        decoder.SetDecoderProperties(props);
        decoder.Code(input, output, input.Length, uncompressedSize, null);
        return output.ToArray();
    }

    // --- XZ Container ---

    private static byte[] BuildXzStream(byte[] lzma2Data, int uncompressedSize, uint uncompressedCrc)
    {
        const int streamFlags = 0x01; // CRC32 check

        using var ms = new MemoryStream();

        // Stream Header: magic (6) + stream flags (2) + CRC32 (4) = 12 bytes
        ms.Write(Magic, 0, 6);
        ms.WriteByte(0x00);
        ms.WriteByte((byte)streamFlags);
        uint hdrCrc = Crc32.Compute(ms.GetBuffer(), 6, 2);
        WriteLE32(ms, hdrCrc);
        long bodyStart = ms.Position; // 12

        // Block Header — write size field last (patched) so padding includes the size byte.
        long cSize = lzma2Data.Length;
        long uSize = uncompressedSize;
        byte blockFlags = 0x00;

        long sizeFieldPos = ms.Position;
        ms.WriteByte(0x00); // placeholder: (headerSize/4)-1

        ms.WriteByte(blockFlags);
        WriteVarLen(ms, cSize);
        WriteVarLen(ms, uSize);

        // LZMA2 filter: ID(1) + property size(1) + property(1) + end(1)
        ms.WriteByte(0x01); // filter ID = LZMA2
        var encoder = new Encoder();
        byte[] lzmaProps = new byte[5];
        using (var ps = new MemoryStream())
        {
            encoder.WriteCoderProperties(ps);
            ps.Position = 0;
            ps.Read(lzmaProps, 0, 5);
        }
        byte propByte = (byte)((lzmaProps[0] * 2 + (lzmaProps[4] > 0 ? 1 : 0)) & 0xFF);
        ms.WriteByte(0x01); // property size
        ms.WriteByte(propByte);
        ms.WriteByte(0x00); // end of filter properties

        // Pad so entire block header (from bodyStart through CRC) is multiple of 4
        while ((ms.Position - bodyStart + 4) % 4 != 0)
            ms.WriteByte(0x00);

        byte[] buf = ms.GetBuffer();
        uint blockCrc = Crc32.Compute(buf, (int)bodyStart + 1, (int)(ms.Position - bodyStart - 1));
        WriteLE32(ms, blockCrc);

        int bhSize = (int)(ms.Position - bodyStart);
        if (bhSize < 8 || bhSize % 4 != 0 || (bhSize / 4) - 1 > 255)
            throw new InvalidDataException($"Invalid XZ block header size {bhSize}");
        buf = ms.GetBuffer();
        buf[sizeFieldPos] = (byte)((bhSize / 4) - 1);

        // Compressed data
        ms.Write(lzma2Data, 0, lzma2Data.Length);

        // Block padding (align compressed data end to 4 bytes from stream start of block body)
        while ((ms.Position - bodyStart) % 4 != 0)
            ms.WriteByte(0x00);

        // Check: CRC32 of uncompressed data
        WriteLE32(ms, uncompressedCrc);

        // Index
        long indexStart = ms.Position;
        ms.WriteByte(0x00); // index indicator
        WriteVarLen(ms, 1); // 1 record
        // Unpadded size = block header + compressed data + check field (CRC32 = 4)
        long unpadded = bhSize + cSize + 4;
        WriteVarLen(ms, unpadded);
        WriteVarLen(ms, uSize);
        while ((ms.Position - indexStart) % 4 != 0)
            ms.WriteByte(0x00);
        buf = ms.GetBuffer();
        uint idxCrc = Crc32.Compute(buf, (int)indexStart, (int)(ms.Position - indexStart));
        WriteLE32(ms, idxCrc);

        // Stream Footer: backward size (4) + stream flags (2) + footer CRC (4) + magic YZ (2)
        long indexSize = ms.Position - indexStart;
        // Backward Size field stores ((index_size / 4) - 1)
        uint backwardSizeField = (uint)((indexSize / 4) - 1);
        WriteLE32(ms, backwardSizeField);
        ms.WriteByte(0x00);
        ms.WriteByte((byte)streamFlags);
        buf = ms.GetBuffer();
        // Footer CRC covers Backward Size (4) + Stream Flags (2)
        uint footerCrc = Crc32.Compute(buf, (int)ms.Position - 6, 6);
        WriteLE32(ms, footerCrc);
        ms.WriteByte(0x59);
        ms.WriteByte(0x5A);

        return ms.ToArray();
    }

    private static bool MatchMagic(byte[] data)
    {
        if (data.Length < Magic.Length) return false;
        for (int i = 0; i < Magic.Length; i++)
            if (data[i] != Magic[i]) return false;
        return true;
    }

    private static (byte[] lzma2Data, int uncompressedSize, uint expectedCrc) ParseXzStream(byte[] data)
    {
        if (data.Length < 24 || !MatchMagic(data))
            throw new InvalidDataException("Not a valid XZ stream");

        const int bodyStart = 12; // after stream header
        int pos = bodyStart;

        int bhSize = (data[pos] + 1) * 4;
        if (bhSize < 8 || bodyStart + bhSize > data.Length)
            throw new InvalidDataException("Invalid XZ block header size");

        pos += 1; // size field
        pos++; // block flags
        long cSize = ReadVarLen(data, ref pos);
        long uSize = ReadVarLen(data, ref pos);
        if (cSize < 0 || cSize > data.Length || uSize < 0 || uSize > int.MaxValue)
            throw new InvalidDataException("Invalid XZ block sizes");

        // Compressed payload starts immediately after the full block header
        pos = bodyStart + bhSize;
        if (pos + cSize > data.Length)
            throw new InvalidDataException("XZ compressed data truncated");

        byte[] lzma2 = new byte[cSize];
        Array.Copy(data, pos, lzma2, 0, (int)cSize);
        pos += (int)cSize;

        // Padding to 4-byte alignment relative to block start (bodyStart ≡ 0 mod 4)
        while ((pos - bodyStart) % 4 != 0)
            pos++;

        if (pos + 4 > data.Length)
            throw new InvalidDataException("XZ block check field truncated");
        uint expectedCrc = ReadLE32(data, pos);
        pos += 4;

        if (pos >= data.Length || data[pos] != 0x00)
            throw new InvalidDataException("XZ index indicator not found");

        return (lzma2, (int)uSize, expectedCrc);
    }

    // --- Variable-length integer encoding (XZ uses little-endian multibyte) ---

    private static void WriteVarLen(Stream ms, long value)
    {
        while (value >= 0x80)
        {
            ms.WriteByte((byte)(value | 0x80));
            value >>= 7;
        }
        ms.WriteByte((byte)value);
    }

    private static long ReadVarLen(byte[] data, ref int pos)
    {
        long result = 0;
        int shift = 0;
        while (pos < data.Length)
        {
            byte b = data[pos++];
            result |= (long)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
        }
        return result;
    }

    private static int VarLenEncodedSize(long value)
    {
        int size = 0;
        do { size++; value >>= 7; } while (value > 0);
        return size;
    }

    private static void WriteLE32(Stream ms, uint value)
    {
        ms.WriteByte((byte)value);
        ms.WriteByte((byte)(value >> 8));
        ms.WriteByte((byte)(value >> 16));
        ms.WriteByte((byte)(value >> 24));
    }

    private static uint ReadLE32(byte[] data, int offset)
    {
        return (uint)(data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24));
    }
}

internal static class Crc32
{
    private static readonly uint[] Table = BuildTable();

    private static uint[] BuildTable()
    {
        var table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int j = 0; j < 8; j++)
                c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        return table;
    }

    public static uint Compute(byte[] data, int offset, int length)
    {
        uint crc = 0xFFFFFFFF;
        for (int i = offset; i < offset + length; i++)
            crc = Table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
        return crc ^ 0xFFFFFFFF;
    }
}
