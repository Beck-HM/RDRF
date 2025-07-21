using System.Security.Cryptography;

namespace RDRF.Core.FSS;

public static class LtCode
{
    public const int DefaultBlockSize = 256;

    private static readonly double[] DegreeProbs = { 0.10, 0.20, 0.20, 0.20, 0.15, 0.10, 0.04, 0.01 };

    public static (List<byte[]> symbols, int seed) Encode(
        byte[][] allBlocks, int symbolCount, int blockSize)
    {
        int K = allBlocks.Length;
        int N = 2 * K;
        int seed = RandomNumberGenerator.GetInt32(int.MaxValue);
        ulong prng = (ulong)seed;

        var inter = Precode.Encode(allBlocks, blockSize);

        var result = new List<byte[]>(symbolCount);
        var idxSet = new HashSet<int>();
        for (int si = 0; si < symbolCount; si++)
        {
            int deg = SelectDegree(ref prng);
            if (deg > N) deg = N;

            idxSet.Clear();
            while (idxSet.Count < deg)
                idxSet.Add(NextPseudo(ref prng) % N);

            byte[] data = new byte[blockSize];
            foreach (int idx in idxSet)
            {
                for (int b = 0; b < blockSize; b++)
                    data[b] ^= inter[idx][b];
            }
            result.Add(data);
        }

        return (result, seed);
    }

    public static bool Decode(
        byte[][] allBlocks, bool[] isCorrupted,
        int symbolCount, int seed, byte[] allSymbolData,
        int blockCount, int blockSize)
    {
        int K = blockCount;
        int N = 2 * K;
        ulong prng = (ulong)seed;

        var inter = new byte[N][];
        for (int i = 0; i < K; i++)
        {
            inter[i] = new byte[blockSize];
            Buffer.BlockCopy(allBlocks[i], 0, inter[i], 0, blockSize);
        }
        for (int i = K; i < N; i++)
            inter[i] = new byte[blockSize];

        var known = new bool[N];
        var srcKnown = new bool[K];
        int totalBad = 0;
        for (int i = 0; i < K; i++)
        {
            if (!isCorrupted[i]) { known[i] = true; srcKnown[i] = true; }
            else totalBad++;
        }

        Precode.Derive(inter, known, K, blockSize);

        var symDeg = new int[symbolCount];
        var symIdx = new int[symbolCount][];
        var symData = new byte[symbolCount][];
        int dataOff = 0;

        var idxSet = new HashSet<int>();
        for (int si = 0; si < symbolCount; si++)
        {
            int deg = SelectDegree(ref prng);
            if (deg > N) deg = N;
            symDeg[si] = deg;
            idxSet.Clear();
            while (idxSet.Count < deg)
                idxSet.Add(NextPseudo(ref prng) % N);
            symIdx[si] = idxSet.ToArray();
            symData[si] = new byte[blockSize];
            Buffer.BlockCopy(allSymbolData, dataOff, symData[si], 0, blockSize);
            dataOff += blockSize;
        }

        var remainingDeg = new int[symbolCount];
        for (int si = 0; si < symbolCount; si++)
        {
            int deg = symDeg[si];
            byte[] sd = symData[si];
            foreach (int bi in symIdx[si])
            {
                if (known[bi])
                {
                    for (int b = 0; b < blockSize; b++)
                        sd[b] ^= inter[bi][b];
                    deg--;
                }
            }
            remainingDeg[si] = deg;
        }

        var symToBlock = new List<int>[N];
        for (int i = 0; i < N; i++) symToBlock[i] = new List<int>();
        for (int si = 0; si < symbolCount; si++)
            foreach (int bi in symIdx[si])
                symToBlock[bi].Add(si);

        var queue = new Queue<int>();
        for (int si = 0; si < symbolCount; si++)
            if (remainingDeg[si] == 1) queue.Enqueue(si);

        int recovered = 0;

        while (recovered < totalBad)
        {
            bool progress = false;
            var newlyKnown = new HashSet<int>();

            while (queue.Count > 0)
            {
                int si = queue.Dequeue();
                if (remainingDeg[si] != 1) continue;

                int target = -1;
                foreach (int bi in symIdx[si])
                    if (!known[bi]) { target = bi; break; }
                if (target < 0) continue;

                Buffer.BlockCopy(symData[si], 0, inter[target], 0, blockSize);
                known[target] = true;
                newlyKnown.Add(target);

                if (target < K && !srcKnown[target])
                {
                    Buffer.BlockCopy(inter[target], 0, allBlocks[target], 0, blockSize);
                    srcKnown[target] = true;
                    recovered++;
                    progress = true;
                }

                foreach (int si2 in symToBlock[target])
                {
                    if (remainingDeg[si2] <= 1) continue;
                    for (int b = 0; b < blockSize; b++)
                        symData[si2][b] ^= inter[target][b];
                    remainingDeg[si2]--;
                    if (remainingDeg[si2] == 1)
                        queue.Enqueue(si2);
                }
            }

            // Derive ladder/global from newly known source blocks
            var derived = Precode.Derive(inter, known, K, blockSize);
            foreach (int d in derived)
                newlyKnown.Add(d);

            var (unlocked, newSrcs) = Precode.Unlock(inter, known, srcKnown,
                allBlocks, K, blockSize);
            if (unlocked > 0)
            {
                recovered += unlocked;
                progress = true;
                foreach (int s in newSrcs)
                    newlyKnown.Add(s);

                var derived2 = Precode.Derive(inter, known, K, blockSize);
                foreach (int d in derived2)
                    newlyKnown.Add(d);
            }

            if (progress && newlyKnown.Count > 0)
            {
                // Incremental update: XOR newly known blocks from symbols
                queue.Clear();
                foreach (int nk in newlyKnown)
                {
                    foreach (int si in symToBlock[nk])
                    {
                        if (remainingDeg[si] <= 1) continue;
                        for (int b = 0; b < blockSize; b++)
                            symData[si][b] ^= inter[nk][b];
                        remainingDeg[si]--;
                        if (remainingDeg[si] == 1)
                            queue.Enqueue(si);
                    }
                }
            }

            if (!progress) break;
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
