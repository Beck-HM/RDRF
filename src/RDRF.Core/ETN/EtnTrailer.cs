namespace RDRF.Core.ETN;

public static class EtnTrailer
{
    public static byte[] Build(byte[] fragFlat, int fragCount, byte[] indexFlat, int indexCount, byte[] rcFlat, int rcCount, int rawSize = 0)
    {
        int trailerSize = 4 + 4 + fragCount * EtnBlockMap.TrailerHashLen + 4 + indexCount * EtnBlockMap.TrailerHashLen + 4 + rcCount * EtnBlockMap.TrailerHashLen + 4;
        byte[] trailer = new byte[trailerSize];
        int offset = 0;
        Buffer.BlockCopy(BitConverter.GetBytes(rawSize), 0, trailer, offset, 4); offset += 4;
        Buffer.BlockCopy(BitConverter.GetBytes(fragCount), 0, trailer, offset, 4); offset += 4;
        if (fragCount > 0) { AppendTruncated(fragFlat, fragCount, EtnBlockMap.TrailerHashLen, trailer, ref offset); }
        Buffer.BlockCopy(BitConverter.GetBytes(indexCount), 0, trailer, offset, 4); offset += 4;
        if (indexCount > 0) { AppendTruncated(indexFlat, indexCount, EtnBlockMap.TrailerHashLen, trailer, ref offset); }
        Buffer.BlockCopy(BitConverter.GetBytes(rcCount), 0, trailer, offset, 4); offset += 4;
        if (rcCount > 0) { AppendTruncated(rcFlat, rcCount, EtnBlockMap.TrailerHashLen, trailer, ref offset); }
        Buffer.BlockCopy(BitConverter.GetBytes(trailerSize), 0, trailer, offset, 4);
        return trailer;
    }

    public static (byte[] data, byte[] fragFlat, int fragCount, byte[] indexFlat, int indexCount, byte[] rcFlat, int rcCount) Parse(byte[] fragmentData)
    {
        if (fragmentData.Length < 12)
            return (fragmentData, Array.Empty<byte>(), 0, Array.Empty<byte>(), 0, Array.Empty<byte>(), 0);
        int trailerSize = BitConverter.ToInt32(fragmentData, fragmentData.Length - 4);
        if (trailerSize <= 0 || trailerSize > fragmentData.Length)
            return (fragmentData, Array.Empty<byte>(), 0, Array.Empty<byte>(), 0, Array.Empty<byte>(), 0);
        int trailerStart = fragmentData.Length - trailerSize;
        if (trailerStart < 0)
            return (fragmentData, Array.Empty<byte>(), 0, Array.Empty<byte>(), 0, Array.Empty<byte>(), 0);
        int offset = trailerStart;
        int rawSize = BitConverter.ToInt32(fragmentData, offset); offset += 4;
        if (rawSize <= 0 || rawSize > fragmentData.Length)
            return (fragmentData, Array.Empty<byte>(), 0, Array.Empty<byte>(), 0, Array.Empty<byte>(), 0);

        int fragCount = BitConverter.ToInt32(fragmentData, offset); offset += 4;
        byte[] fragFlat = ReadBlockMapFlat(fragmentData, ref offset, fragCount, EtnBlockMap.TrailerHashLen);

        int indexCount = BitConverter.ToInt32(fragmentData, offset); offset += 4;
        byte[] indexFlat = ReadBlockMapFlat(fragmentData, ref offset, indexCount, EtnBlockMap.TrailerHashLen);

        int rcCount = BitConverter.ToInt32(fragmentData, offset); offset += 4;
        byte[] rcFlat = ReadBlockMapFlat(fragmentData, ref offset, rcCount, EtnBlockMap.TrailerHashLen);

        byte[] rawData = new byte[rawSize];
        Buffer.BlockCopy(fragmentData, 0, rawData, 0, rawSize);
        return (rawData, fragFlat, fragCount, indexFlat, indexCount, rcFlat, rcCount);
    }

    private static byte[] ReadBlockMapFlat(byte[] data, ref int offset, int count, int hashLen)
    {
        if (count <= 0) return Array.Empty<byte>();
        if (offset + count * hashLen > data.Length) count = (data.Length - offset) / hashLen;
        if (count <= 0) return Array.Empty<byte>();
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
