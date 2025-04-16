namespace RDRF.Core.ETN;

public static class EtnTrailer
{
    public static byte[] Build(List<byte[]> indexBlockMap, List<byte[]> rcBlockMap, int rawSize = 0)
    {
        byte[] indexFlat = Flatten(indexBlockMap);
        byte[] rcFlat = Flatten(rcBlockMap);
        int trailerSize = 4 + 4 + indexFlat.Length + 4 + rcFlat.Length + 4;
        byte[] trailer = new byte[trailerSize];
        int offset = 0;
        Buffer.BlockCopy(BitConverter.GetBytes(rawSize), 0, trailer, offset, 4); offset += 4;
        Buffer.BlockCopy(BitConverter.GetBytes(indexBlockMap.Count), 0, trailer, offset, 4); offset += 4;
        if (indexFlat.Length > 0) { Buffer.BlockCopy(indexFlat, 0, trailer, offset, indexFlat.Length); offset += indexFlat.Length; }
        Buffer.BlockCopy(BitConverter.GetBytes(rcBlockMap.Count), 0, trailer, offset, 4); offset += 4;
        if (rcFlat.Length > 0) { Buffer.BlockCopy(rcFlat, 0, trailer, offset, rcFlat.Length); offset += rcFlat.Length; }
        Buffer.BlockCopy(BitConverter.GetBytes(trailerSize), 0, trailer, offset, 4);
        return trailer;
    }

    public static (byte[] data, List<byte[]> indexBlockMap, List<byte[]> rcBlockMap) Parse(byte[] fragmentData)
    {
        if (fragmentData.Length < 8)
            return (fragmentData, new List<byte[]>(), new List<byte[]>());
        int trailerSize = BitConverter.ToInt32(fragmentData, fragmentData.Length - 4);
        if (trailerSize <= 0 || trailerSize > fragmentData.Length)
            return (fragmentData, new List<byte[]>(), new List<byte[]>());
        int trailerStart = fragmentData.Length - trailerSize;
        if (trailerStart < 0)
            return (fragmentData, new List<byte[]>(), new List<byte[]>());
        int offset = trailerStart;
        int rawSize = BitConverter.ToInt32(fragmentData, offset); offset += 4;
        if (rawSize <= 0 || rawSize > fragmentData.Length)
            return (fragmentData, new List<byte[]>(), new List<byte[]>());
        int indexBMCount = BitConverter.ToInt32(fragmentData, offset); offset += 4;
        var indexBlockMap = new List<byte[]>(indexBMCount);
        for (int i = 0; i < indexBMCount; i++)
        {
            if (offset + 32 > fragmentData.Length) break;
            byte[] hash = new byte[32];
            Buffer.BlockCopy(fragmentData, offset, hash, 0, 32);
            indexBlockMap.Add(hash);
            offset += 32;
        }
        int rcBMCount = BitConverter.ToInt32(fragmentData, offset); offset += 4;
        var rcBlockMap = new List<byte[]>(rcBMCount);
        for (int i = 0; i < rcBMCount; i++)
        {
            if (offset + 32 > fragmentData.Length) break;
            byte[] hash = new byte[32];
            Buffer.BlockCopy(fragmentData, offset, hash, 0, 32);
            rcBlockMap.Add(hash);
            offset += 32;
        }
        byte[] rawData = new byte[rawSize];
        Buffer.BlockCopy(fragmentData, 0, rawData, 0, rawSize);
        return (rawData, indexBlockMap, rcBlockMap);
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
