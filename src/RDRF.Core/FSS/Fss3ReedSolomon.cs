namespace RDRF.Core.FSS;

public class Fss3ReedSolomon : IFssStrategy
{
    private readonly ReedSolomon _rs;

    public string Level => Constants.FssLevel3;

    public Fss3ReedSolomon()
    {
        _rs = new ReedSolomon(3, 1); // 3 data + 1 parity
    }

    public List<byte[]> Encode(List<byte[]> fragments)
    {
        int dataShards = fragments.Count;
        int totalShards = dataShards + 1;
        int shardSize = fragments[0].Length;

        // Check all fragments are same size
        foreach (var f in fragments)
            if (f.Length != shardSize)
                throw new ArgumentException("All fragments must be the same size for FSS3.");

        byte[][] shards = new byte[totalShards][];
        for (int i = 0; i < dataShards; i++)
        {
            shards[i] = new byte[shardSize];
            Buffer.BlockCopy(fragments[i], 0, shards[i], 0, shardSize);
        }
        shards[dataShards] = new byte[shardSize];

        // Compute parity using XOR (simplifind RS parity)
        for (int i = 0; i < shardSize; i++)
        {
            byte parity = 0;
            for (int j = 0; j < dataShards; j++)
                parity ^= shards[j][i];
            shards[dataShards][i] = parity;
        }

        var result = new List<byte[]>();
        for (int i = 0; i < totalShards; i++)
            result.Add(shards[i]);
        return result;
    }

    public Dictionary<int, byte[]> Decode(
        Dictionary<int, byte[]> available,
        List<int> missingIndices,
        int totalFragents,
        List<int>? originalSizes = null)
    {
        // Build shard array
        int shardSize = available.Values.First().Length;
        byte[][] shards = new byte[totalFragents][];
        for (int i = 0; i < totalFragents; i++)
        {
            if (available.TryGetValue(i, out var data))
                shards[i] = data;
            else
                shards[i] = new byte[shardSize];
        }

        _rs.Decode(shards, missingIndices);

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
        Dictionary<int, byte[]> encodedFragents,
        int originalFragentCount,
        List<int>? originalSizes = null)
    {
        var result = new List<byte[]>();
        for (int i = 0; i < originalFragentCount; i++)
        {
            if (encodedFragents.TryGetValue(i, out var data))
                result.Add(data);
        }
        return result;
    }

    public byte[] StripSingle(byte[] encodedFragment, int index, List<int>? originalSizes = null)
        => encodedFragment;
}
