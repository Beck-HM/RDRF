using System.Linq;
using RDRF.Core.Index;

namespace RDRF.Core.FSS;

public class Fss2Verify : IFssStrategy
{
    private readonly Fss1Neighbor _fss1 = new();
    private const int SubBlockSize = 16;
    private const int SegSize = 256;
    private const int DataShards = 16;
    private const int ParityShards = 2;
    private const int TotalShards = DataShards + ParityShards;

    public string Level => Constants.FssLevel2;

    public List<byte[]> Encode(List<byte[]> fragments)
    {
        var fss1Result = _fss1.Encode(fragments);
        int K = fss1Result.Count;

        var allParity = new List<byte[]>();
        var rs = new ReedSolomon(DataShards, ParityShards);

        for (int i = 0; i < K; i++)
        {
            int fragSize = fss1Result[i].Length;
            int half = fragSize / 2;
            int segCount = (fragSize + SegSize - 1) / SegSize;
            byte[] upperSource = fss1Result[(i + 1) % K];
            byte[] lowerSource = fss1Result[(i - 1 + K) % K];

            for (int w = 0; w < segCount; w++)
            {
                int segHalf = SegSize / 2;
                int segOff = w * segHalf;

                var shards = new byte[TotalShards][];
                for (int b = 0; b < 8; b++)
                {
                    int off = segOff + b * SubBlockSize;
                    shards[b] = ReadSubBlock(upperSource, off);
                    shards[8 + b] = ReadSubBlock(lowerSource, off);
                }
                shards[DataShards] = new byte[SubBlockSize];
                shards[DataShards + 1] = new byte[SubBlockSize];

                rs.Encode(shards);
                allParity.Add(shards[DataShards]);
                allParity.Add(shards[DataShards + 1]);
            }
        }

        int totalParity = allParity.Count;
        int parityFragCount = (totalParity + 15) / 16;
        var result = new List<byte[]>(fss1Result);

        for (int p = 0; p < parityFragCount; p++)
        {
            byte[] frag = new byte[SegSize];
            for (int j = 0; j < 16 && p * 16 + j < totalParity; j++)
                Buffer.BlockCopy(allParity[p * 16 + j], 0, frag, j * SubBlockSize, SubBlockSize);
            result.Add(frag);
        }

        return result;
    }

    public Dictionary<int, byte[]> Decode(
        Dictionary<int, byte[]> available,
        List<int> missingIndices,
        int totalFragments,
        List<int>? originalSizes = null)
    {
        int K = originalSizes?.Count ?? available.Count;
        var fss1Available = new Dictionary<int, byte[]>();
        foreach (var kvp in available)
        {
            if (kvp.Key < K)
                fss1Available[kvp.Key] = kvp.Value;
        }
        var fss1Missing = missingIndices.Where(m => m < K).ToList();
        return _fss1.Decode(fss1Available, fss1Missing, K, originalSizes);
    }

    public List<byte[]> Strip(
        Dictionary<int, byte[]> encodedFragments,
        int originalFragmentCount,
        List<int>? originalSizes = null)
    {
        int K = originalFragmentCount;
        int totalFrags = encodedFragments.Count;
        int parityFragCount = totalFrags - K;

        var fss1Frags = new Dictionary<int, byte[]>();
        for (int i = 0; i < K; i++)
        {
            if (encodedFragments.TryGetValue(i, out var data))
                fss1Frags[i] = data;
        }

        if (parityFragCount <= 0 || fss1Frags.Count < K)
            return _fss1.Strip(fss1Frags, K, originalSizes);

        var rs = new ReedSolomon(DataShards, ParityShards);

        int totalSegCount = 0;
        var segCounts = new int[K];
        for (int i = 0; i < K; i++)
        {
            if (!fss1Frags.TryGetValue(i, out var frag)) continue;
            segCounts[i] = (frag.Length + SegSize - 1) / SegSize;
            totalSegCount += segCounts[i];
        }

        var storedParity = new List<byte[]>(totalSegCount * ParityShards);
        for (int p = 0; p < parityFragCount; p++)
        {
            if (!encodedFragments.TryGetValue(K + p, out var parityFrag))
            {
                storedParity.Clear();
                break;
            }
            int blocksInFrag = Math.Min(16, totalSegCount * ParityShards - storedParity.Count);
            for (int j = 0; j < blocksInFrag; j++)
            {
                var block = new byte[SubBlockSize];
                Buffer.BlockCopy(parityFrag, j * SubBlockSize, block, 0, SubBlockSize);
                storedParity.Add(block);
            }
        }

        if (storedParity.Count < totalSegCount * ParityShards)
            return _fss1.Strip(fss1Frags, K, originalSizes);

        int parityIdx = 0;
        for (int i = 0; i < K; i++)
        {
            if (!fss1Frags.TryGetValue(i, out _)) continue;

            int fragSize = (originalSizes != null && i < originalSizes.Count) ? originalSizes[i] : fss1Frags[i].Length;
            int half = fragSize / 2;
            int segCount = segCounts[i];

            byte[] upperSource = fss1Frags.ContainsKey((i + 1) % K)
                ? fss1Frags[(i + 1) % K]
                : null!;
            byte[] lowerSource = fss1Frags.ContainsKey((i - 1 + K) % K)
                ? fss1Frags[(i - 1 + K) % K]
                : null!;
            if (upperSource == null || lowerSource == null) continue;

            for (int w = 0; w < segCount; w++)
            {
                int segHalf = SegSize / 2;
                int segOff = w * segHalf;
                int wFragSize = half * 2;

                var shards = new byte[DataShards][];
                for (int b = 0; b < 8; b++)
                {
                    int off = segOff + b * SubBlockSize;
                    shards[b] = ReadSubBlock(upperSource, off);
                    shards[8 + b] = ReadSubBlock(lowerSource, off);
                }

                byte[] storedP = storedParity[parityIdx];
                byte[] storedQ = storedParity[parityIdx + 1];

                if (CheckParityMatch(rs, shards, storedP, storedQ))
                {
                    parityIdx += ParityShards;
                    continue;
                }

                int fixedShard = TryRepairShard(rs, shards, storedP, storedQ);
                if (fixedShard >= 0)
                {
                    int off;
                    if (fixedShard < 8)
                        off = segOff + fixedShard * SubBlockSize;
                    else
                        off = segOff + (fixedShard - 8) * SubBlockSize;

                    byte[] target;
                    int targetOff;
                    if (fixedShard < 8)
                    {
                        target = upperSource;
                        targetOff = off;
                    }
                    else
                    {
                        target = lowerSource;
                        targetOff = off;
                    }

                    if (targetOff + SubBlockSize <= target.Length)
                    {
                        byte[] buf = target;
                        Buffer.BlockCopy(shards[fixedShard], 0, buf, targetOff, Math.Min(SubBlockSize, buf.Length - targetOff));
                    }
                }
                parityIdx += ParityShards;
            }
        }

        return _fss1.Strip(fss1Frags, K, originalSizes);
    }

    public byte[] StripSingle(byte[] encodedFragment, int index, List<int>? originalSizes = null)
    {
        return _fss1.StripSingle(encodedFragment, index, originalSizes);
    }

    private static byte[] ReadSubBlock(byte[] source, int offset)
    {
        if (offset >= source.Length)
            return new byte[SubBlockSize];

        int len = Math.Min(SubBlockSize, source.Length - offset);
        byte[] block = new byte[SubBlockSize];
        Buffer.BlockCopy(source, offset, block, 0, len);
        return block;
    }

    private static bool CheckParityMatch(ReedSolomon rs, byte[][] dataShards, byte[] storedP, byte[] storedQ)
    {
        var shards = new byte[TotalShards][];
        for (int i = 0; i < DataShards; i++)
            shards[i] = dataShards[i];
        shards[DataShards] = new byte[SubBlockSize];
        shards[DataShards + 1] = new byte[SubBlockSize];

        rs.Encode(shards);
        return shards[DataShards].AsSpan().SequenceEqual(storedP) &&
               shards[DataShards + 1].AsSpan().SequenceEqual(storedQ);
    }

    private static int TryRepairShard(ReedSolomon rs, byte[][] dataShards, byte[] storedP, byte[] storedQ)
    {
        for (int suspect = 0; suspect < DataShards; suspect++)
        {
            var working = new byte[TotalShards][];
            for (int i = 0; i < DataShards; i++)
            {
                working[i] = new byte[SubBlockSize];
                Buffer.BlockCopy(dataShards[i], 0, working[i], 0, SubBlockSize);
            }
            working[DataShards] = new byte[SubBlockSize];
            Buffer.BlockCopy(storedP, 0, working[DataShards], 0, SubBlockSize);
            working[DataShards + 1] = new byte[SubBlockSize];
            Buffer.BlockCopy(storedQ, 0, working[DataShards + 1], 0, SubBlockSize);

            if (!rs.Decode(working, new List<int> { suspect }))
                continue;

            var encoded = new byte[TotalShards][];
            for (int i = 0; i < DataShards; i++)
            {
                encoded[i] = new byte[SubBlockSize];
                Buffer.BlockCopy(working[i], 0, encoded[i], 0, SubBlockSize);
            }
            encoded[DataShards] = new byte[SubBlockSize];
            encoded[DataShards + 1] = new byte[SubBlockSize];
            rs.Encode(encoded);

            if (encoded[DataShards].AsSpan().SequenceEqual(storedP) &&
                encoded[DataShards + 1].AsSpan().SequenceEqual(storedQ))
            {
                Buffer.BlockCopy(working[suspect], 0, dataShards[suspect], 0, SubBlockSize);
                return suspect;
            }
        }
        return -1;
    }
}
