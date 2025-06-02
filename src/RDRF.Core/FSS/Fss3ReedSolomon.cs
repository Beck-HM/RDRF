namespace RDRF.Core.FSS;

public class Fss3ReedSolomon : IFssStrategy
{
    public string Level => Constants.FssLevel3;

    public List<byte[]> Encode(List<byte[]> fragments)
    {
        int dataShards = fragments.Count;
        int parityShards = 1;
        int totalShards = dataShards + parityShards;
        int shardSize = fragments[0].Length;

        foreach (var f in fragments)
            if (f.Length != shardSize)
                throw new ArgumentException("All fragments must be the same size for FSS3.");

        byte[][] shards = new byte[totalShards][];
        for (int i = 0; i < dataShards; i++)
        {
            shards[i] = new byte[shardSize];
            Buffer.BlockCopy(fragments[i], 0, shards[i], 0, shardSize);
        }

        var rs = new ReedSolomon(dataShards, parityShards);
        rs.Encode(shards);

        var result = new List<byte[]>();
        for (int i = 0; i < totalShards; i++)
            result.Add(shards[i]);
        return result;
    }

    public Dictionary<int, byte[]> Decode(
        Dictionary<int, byte[]> available,
        List<int> missingIndices,
        int totalFragments,
        List<int>? originalSizes = null)
    {
        int shardSize = available.Values.First().Length;
        byte[][] shards = new byte[totalFragments][];
        for (int i = 0; i < totalFragments; i++)
        {
            if (available.TryGetValue(i, out var data))
                shards[i] = data;
            else
                shards[i] = new byte[shardSize];
        }

        int dataShards = totalFragments - 1;
        var rs = new ReedSolomon(dataShards, 1);
        rs.Decode(shards, missingIndices);

        var result = new Dictionary<int, byte[]>();
        foreach (int idx in missingIndices)
        {
            byte[] recovered = shards[idx];
            if (originalSizes != null && idx < originalSizes.Count && originalSizes[idx] < shardSize)
            {
                byte[] trimmed = new byte[originalSizes[idx]];
                Buffer.BlockCopy(recovered, 0, trimmed, 0, trimmed.Length);
                result[idx] = trimmed;
            }
            else
            {
                result[idx] = recovered;
            }
        }
        return result;
    }

    public List<byte[]> Strip(
        Dictionary<int, byte[]> encodedFragments,
        int originalFragmentCount,
        List<int>? originalSizes = null)
    {
        var result = new List<byte[]>();
        for (int i = 0; i < originalFragmentCount; i++)
        {
            if (encodedFragments.TryGetValue(i, out var data))
                result.Add(data);
        }
        return result;
    }

    public byte[] StripSingle(byte[] encodedFragment, int index, List<int>? originalSizes = null)
        => encodedFragment;
}
