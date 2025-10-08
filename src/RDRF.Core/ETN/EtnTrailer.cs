namespace RDRF.Core.ETN;

public readonly struct EtnTrailerData
{
    public readonly byte[] RawData;
    public readonly byte[] Index2B;
    public readonly int Index2BCount;
    public readonly byte[] Index8B;
    public readonly int Index8BCount;
    public readonly byte[] Rc2B;
    public readonly int Rc2BCount;
    public readonly byte[] Rc8B;
    public readonly int Rc8BCount;

    public EtnTrailerData(byte[] rawData, byte[] idx2B, int idx2Cnt, byte[] idx8B, int idx8Cnt,
        byte[] rc2B, int rc2Cnt, byte[] rc8B, int rc8Cnt)
    {
        RawData = rawData;
        Index2B = idx2B; Index2BCount = idx2Cnt;
        Index8B = idx8B; Index8BCount = idx8Cnt;
        Rc2B = rc2B; Rc2BCount = rc2Cnt;
        Rc8B = rc8B; Rc8BCount = rc8Cnt;
    }
}

public static class EtnTrailer
{
    public const int Trailer2BHashLen = 2;
    public const int Trailer8BHashLen = 8;

    public static byte[] Build(byte[] indexFlat, int indexCount, byte[] rcFlat, int rcCount, int rawSize = 0)
    {
        int idx2Size = indexCount * Trailer2BHashLen;
        int idx8Size = indexCount * Trailer8BHashLen;
        int rc2Size = rcCount * Trailer2BHashLen;
        int rc8Size = rcCount * Trailer8BHashLen;
        int trailerSize = 4 + 4 + idx2Size + idx8Size + 4 + rc2Size + rc8Size + 4;
        byte[] trailer = new byte[trailerSize];
        int offset = 0;
        Buffer.BlockCopy(BitConverter.GetBytes(rawSize), 0, trailer, offset, 4); offset += 4;

        Buffer.BlockCopy(BitConverter.GetBytes(indexCount), 0, trailer, offset, 4); offset += 4;
        if (indexCount > 0) { AppendTruncated(indexFlat, indexCount, Trailer2BHashLen, trailer, ref offset); }
        if (indexCount > 0) { AppendTruncated(indexFlat, indexCount, Trailer8BHashLen, trailer, ref offset); }

        Buffer.BlockCopy(BitConverter.GetBytes(rcCount), 0, trailer, offset, 4); offset += 4;
        if (rcCount > 0) { AppendTruncated(rcFlat, rcCount, Trailer2BHashLen, trailer, ref offset); }
        if (rcCount > 0) { AppendTruncated(rcFlat, rcCount, Trailer8BHashLen, trailer, ref offset); }

        Buffer.BlockCopy(BitConverter.GetBytes(trailerSize), 0, trailer, offset, 4);
        return trailer;
    }

    public static EtnTrailerData Parse(byte[] fragmentData)
    {
        if (fragmentData.Length < 12)
            return new EtnTrailerData(fragmentData, [], 0, [], 0, [], 0, [], 0);
        int trailerSize = BitConverter.ToInt32(fragmentData, fragmentData.Length - 4);
        if (trailerSize <= 0 || trailerSize > fragmentData.Length || trailerSize < 4)
            return new EtnTrailerData(fragmentData, [], 0, [], 0, [], 0, [], 0);
        int trailerStart = fragmentData.Length - trailerSize;
        if (trailerStart < 0)
            return new EtnTrailerData(fragmentData, [], 0, [], 0, [], 0, [], 0);
        int offset = trailerStart;
        int rawSize = BitConverter.ToInt32(fragmentData, offset); offset += 4;
        if (rawSize <= 0 || rawSize > fragmentData.Length)
            return new EtnTrailerData(fragmentData, [], 0, [], 0, [], 0, [], 0);

        int idxCount = BitConverter.ToInt32(fragmentData, offset); offset += 4;
        byte[] idx2B = ReadBlockMapFlat(fragmentData, ref offset, idxCount, Trailer2BHashLen);
        byte[] idx8B = ReadBlockMapFlat(fragmentData, ref offset, idxCount, Trailer8BHashLen);

        int rcCount = BitConverter.ToInt32(fragmentData, offset); offset += 4;
        byte[] rc2B = ReadBlockMapFlat(fragmentData, ref offset, rcCount, Trailer2BHashLen);
        byte[] rc8B = ReadBlockMapFlat(fragmentData, ref offset, rcCount, Trailer8BHashLen);

        byte[] rawData = new byte[rawSize];
        Buffer.BlockCopy(fragmentData, 0, rawData, 0, rawSize);
        return new EtnTrailerData(rawData, idx2B, idxCount, idx8B, idxCount, rc2B, rcCount, rc8B, rcCount);
    }

    private static byte[] ReadBlockMapFlat(byte[] data, ref int offset, int count, int hashLen)
    {
        if (count <= 0) return [];
        if (offset + count * hashLen > data.Length) count = (data.Length - offset) / hashLen;
        if (count <= 0) return [];
        byte[] flat = new byte[count * hashLen];
        Buffer.BlockCopy(data, offset, flat, 0, flat.Length);
        offset += flat.Length;
        return flat;
    }

    private static void AppendTruncated(byte[] fullFlat, int count, int hashLen, byte[] trailer, ref int offset)
    {
        for (int i = 0; i < count; i++)
        {
            Buffer.BlockCopy(fullFlat, i * EtnBlockMap.FullHashLen, trailer, offset, hashLen);
            offset += hashLen;
        }
    }
}
