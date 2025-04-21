namespace RDRF.Core.ETN;

public static class EtnTrailer
{
    public static byte[] Build(List<byte[]> fragmentBlockMap, List<byte[]> indexBlockMap, List<byte[]> rcBlockMap, int rawSize = 0)
    {
        byte[] fragFlat = Flatten(fragmentBlockMap);
        byte[] indexFlat = Flatten(indexBlockMap);
        byte[] rcFlat = Flatten(rcBlockMap);
        int trailerSize = 4 + 4 + fragFlat.Length + 4 + indexFlat.Length + 4 + rcFlat.Length + 4;
        byte[] trailer = new byte[trailerSize];
        int offset = 0;
        Buffer.BlockCopy(BitConverter.GetBytes(rawSize), 0, trailer, offset, 4); offset += 4;
        Buffer.BlockCopy(BitConverter.GetBytes(fragmentBlockMap.Count), 0, trailer, offset, 4); offset += 4;
        if (fragFlat.Length > 0) { Buffer.BlockCopy(fragFlat, 0, trailer, offset, fragFlat.Length); offset += fragFlat.Length; }
        Buffer.BlockCopy(BitConverter.GetBytes(indexBlockMap.Count), 0, trailer, offset, 4); offset += 4;
        if (indexFlat.Length > 0) { Buffer.BlockCopy(indexFlat, 0, trailer, offset, indexFlat.Length); offset += indexFlat.Length; }
        Buffer.BlockCopy(BitConverter.GetBytes(rcBlockMap.Count), 0, trailer, offset, 4); offset += 4;
        if (rcFlat.Length > 0) { Buffer.BlockCopy(rcFlat, 0, trailer, offset, rcFlat.Length); offset += rcFlat.Length; }
        Buffer.BlockCopy(BitConverter.GetBytes(trailerSize), 0, trailer, offset, 4);
        return trailer;
    }

    public static (byte[] data, List<byte[]> fragmentBlockMap, List<byte[]> indexBlockMap, List<byte[]> rcBlockMap) Parse(byte[] fragmentData)
    {
        if (fragmentData.Length < 12)
            return (fragmentData, new List<byte[]>(), new List<byte[]>(), new List<byte[]>());
        int trailerSize = BitConverter.ToInt32(fragmentData, fragmentData.Length - 4);
        if (trailerSize <= 0 || trailerSize > fragmentData.Length)
            return (fragmentData, new List<byte[]>(), new List<byte[]>(), new List<byte[]>());
        int trailerStart = fragmentData.Length - trailerSize;
        if (trailerStart < 0)
            return (fragmentData, new List<byte[]>(), new List<byte[]>(), new List<byte[]>());
        int offset = trailerStart;
        int rawSize = BitConverter.ToInt32(fragmentData, offset); offset += 4;
        if (rawSize <= 0 || rawSize > fragmentData.Length)
            return (fragmentData, new List<byte[]>(), new List<byte[]>(), new List<byte[]>());

        int fragBMCount = BitConverter.ToInt32(fragmentData, offset); offset += 4;
        var fragmentBlockMap = ReadBlockMap(fragmentData, ref offset, fragBMCount, 2);

        int indexBMCount = BitConverter.ToInt32(fragmentData, offset); offset += 4;
        var indexBlockMap = ReadBlockMap(fragmentData, ref offset, indexBMCount, 2);

        int rcBMCount = BitConverter.ToInt32(fragmentData, offset); offset += 4;
        var rcBlockMap = ReadBlockMap(fragmentData, ref offset, rcBMCount, 2);

        byte[] rawData = new byte[rawSize];
        Buffer.BlockCopy(fragmentData, 0, rawData, 0, rawSize);
        return (rawData, fragmentBlockMap, indexBlockMap, rcBlockMap);
    }

    private static List<byte[]> ReadBlockMap(byte[] data, ref int offset, int count, int hashLen)
    {
        var map = new List<byte[]>(count);
        for (int i = 0; i < count; i++)
        {
            if (offset + hashLen > data.Length) break;
            byte[] hash = new byte[hashLen];
            Buffer.BlockCopy(data, offset, hash, 0, hashLen);
            map.Add(hash);
            offset += hashLen;
        }
        return map;
    }

    private static byte[] Flatten(List<byte[]> hashes)
    {
        int total = 0;
        foreach (var h in hashes) total += h.Length;
        byte[] result = new byte[total];
        int offset = 0;
        foreach (byte[] h in hashes)
        {
            Buffer.BlockCopy(h, 0, result, offset, h.Length);
            offset += h.Length;
        }
        return result;
    }
}
