namespace RDRF.Core.FSS;

public static class LtCode
{
    public const int DefaultBlockSize = 256;

    private static readonly double[] DegreeProbs = { 0.50, 0.30, 0.12, 0.05, 0.02, 0.005, 0.003, 0.002 };

    public static (List<byte[]> symbols, int seed) Encode(
        byte[][] allBlocks, int symbolCount, int blockSize)
    {
        int seed = System.Security.Cryptography.RandomNumberGenerator.GetInt32(int.MaxValue);
        ulong prng = (ulong)seed;
        int blockCount = allBlocks.Length;

        var result = new List<byte[]>(symbolCount);

        // Phase 1: guarantee at least one deg-1 symbol per block
        int guaranteed = Math.Min(symbolCount / 2, blockCount);
        var covered = new bool[blockCount];
        for (int bi = 0; bi < guaranteed; bi++)
        {
            byte[] data = new byte[blockSize];
            Buffer.BlockCopy(allBlocks[bi % blockCount], 0, data, 0, blockSize);
            result.Add(data);
            covered[bi % blockCount] = true;
        }

        // Phase 2: repair symbols for remaining (if any)
        int remaining = symbolCount - result.Count;
        for (int si = 0; si < remaining; si++)
        {
            int deg = SelectDegree(ref prng);
            if (deg > blockCount) deg = blockCount;

            var indices = new HashSet<int>();
            while (indices.Count < deg)
                indices.Add(NextPseudo(ref prng) % blockCount);

            byte[] data = new byte[blockSize];
            foreach (int idx in indices)
            {
                for (int b = 0; b < blockSize; b++)
                    data[b] ^= allBlocks[idx][b];
            }
            result.Add(data);
        }

        // If we still have uncovered blocks, add deg-1 for each
        for (int bi = 0; bi < blockCount && result.Count < symbolCount; bi++)
        {
            if (!covered[bi])
            {
                byte[] data = new byte[blockSize];
                Buffer.BlockCopy(allBlocks[bi], 0, data, 0, blockSize);
                result.Add(data);
                covered[bi] = true;
            }
        }

        return (result, seed);
    }

    public static bool Decode(
        byte[][] allBlocks, bool[] isCorrupted,
        int symbolCount, int seed, byte[] allSymbolData,
        int blockCount, int blockSize)
    {
        ulong prng = (ulong)seed;

        int guaranteed = Math.Min(symbolCount / 2, blockCount);
        var symbolDeg = new int[symbolCount];
        var symbolIdx = new int[symbolCount][];
        var symbolData = new byte[symbolCount][];

        int dataOff = 0;
        for (int si = 0; si < symbolCount; si++)
        {
            int deg;
            var indices = new HashSet<int>();

            if (si < guaranteed)
            {
                deg = 1;
                indices.Add(si % blockCount);
            }
            else
            {
                deg = SelectDegree(ref prng);
                if (deg > blockCount) deg = blockCount;
                while (indices.Count < deg)
                    indices.Add(NextPseudo(ref prng) % blockCount);
            }

            symbolDeg[si] = deg;
            symbolIdx[si] = indices.ToArray();
            symbolData[si] = new byte[blockSize];
            Buffer.BlockCopy(allSymbolData, dataOff, symbolData[si], 0, blockSize);
            dataOff += blockSize;
        }

        var blockToSymbols = new List<int>[blockCount];
        for (int i = 0; i < blockCount; i++)
            blockToSymbols[i] = new List<int>();

        for (int si = 0; si < symbolCount; si++)
            foreach (int bi in symbolIdx[si])
                blockToSymbols[bi].Add(si);

        var remainingDeg = new int[symbolCount];
        for (int si = 0; si < symbolCount; si++)
        {
            int actualDeg = symbolDeg[si];
            byte[] data = symbolData[si];

            foreach (int bi in symbolIdx[si])
            {
                if (!isCorrupted[bi] && allBlocks[bi] != null)
                {
                    for (int b = 0; b < blockSize; b++)
                        data[b] ^= allBlocks[bi][b];
                    actualDeg--;
                }
            }
            remainingDeg[si] = actualDeg;
        }

        var queue = new System.Collections.Generic.Queue<int>();
        for (int si = 0; si < symbolCount; si++)
            if (remainingDeg[si] == 1)
                queue.Enqueue(si);

        int recovered = 0;
        bool[] recoveredFlag = new bool[blockCount];
        int totalBad = 0;
        for (int i = 0; i < blockCount; i++)
            if (isCorrupted[i]) totalBad++;

        while (queue.Count > 0 && recovered < totalBad)
        {
            int si = queue.Dequeue();
            if (remainingDeg[si] != 1) continue;

            int targetBlock = -1;
            foreach (int bi in symbolIdx[si])
            {
                if (isCorrupted[bi] && !recoveredFlag[bi])
                {
                    targetBlock = bi;
                    break;
                }
            }
            if (targetBlock < 0) continue;

            allBlocks[targetBlock] = symbolData[si];
            recoveredFlag[targetBlock] = true;
            recovered++;

            foreach (int si2 in blockToSymbols[targetBlock])
            {
                if (remainingDeg[si2] <= 1) continue;

                for (int b = 0; b < blockSize; b++)
                    symbolData[si2][b] ^= allBlocks[targetBlock][b];
                remainingDeg[si2]--;

                if (remainingDeg[si2] == 1)
                    queue.Enqueue(si2);
            }
        }

        return recovered >= totalBad;
    }

    public static (int symbolCount, double overhead) GetSymbolCount(int blockCount, double repairRatio)
    {
        int count = Math.Max(1, (int)(blockCount * repairRatio));
        return (count, (double)count / blockCount);
    }

    private static ulong XorShift64(ref ulong state)
    {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        return state * 2685821657736338717UL;
    }

    private static int NextPseudo(ref ulong state)
    {
        return (int)((XorShift64(ref state) >> 32) & 0x7FFFFFFF);
    }

    private static int SelectDegree(ref ulong state)
    {
        int v = NextPseudo(ref state);
        double val = (v & 0x7FFFFFFF) / (double)0x7FFFFFFF;
        double cum = 0;
        for (int i = 0; i < DegreeProbs.Length; i++)
        {
            cum += DegreeProbs[i];
            if (val < cum) return i + 1;
        }
        return DegreeProbs.Length;
    }
}
