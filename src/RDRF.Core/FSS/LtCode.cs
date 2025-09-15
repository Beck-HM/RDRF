using System.Buffers;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;

namespace RDRF.Core.FSS;

public static class LtCode
{
    public const int DefaultBlockSize = 256;

    private static readonly sbyte[] DegreeMap = BuildDegreeMap();

    private static sbyte[] BuildDegreeMap()
    {
        int[] thresholds = { 10, 30, 50, 70, 85, 95, 99, 100 };
        var map = new sbyte[100];
        int idx = 0;
        for (int d = 0; d < thresholds.Length; d++)
        {
            int end = thresholds[d];
            while (idx < end) map[idx++] = (sbyte)(d + 1);
        }
        return map;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void XorBlock(Span<byte> dest, ReadOnlySpan<byte> src)
    {
        int blockSize = dest.Length;
        ref byte dRef = ref MemoryMarshal.GetReference(dest);
        ref byte sRef = ref MemoryMarshal.GetReference(src);
        if (Avx2.IsSupported)
        {
            int i = 0;
            for (; i + 32 <= blockSize; i += 32)
            {
                var vd = Vector256.LoadUnsafe(ref dRef, (nuint)i);
                var vs = Vector256.LoadUnsafe(ref sRef, (nuint)i);
                Avx2.Xor(vd, vs).CopyTo(dest.Slice(i));
            }
            for (; i + 16 <= blockSize; i += 16)
            {
                var vd = Vector128.LoadUnsafe(ref dRef, (nuint)i);
                var vs = Vector128.LoadUnsafe(ref sRef, (nuint)i);
                Vector128.Xor(vd, vs).CopyTo(dest.Slice(i));
            }
            for (; i < blockSize; i++)
                dest[i] ^= src[i];
        }
        else
        {
            int i = 0;
            for (; i + 16 <= blockSize; i += 16)
            {
                var vd = Vector128.LoadUnsafe(ref dRef, (nuint)i);
                var vs = Vector128.LoadUnsafe(ref sRef, (nuint)i);
                Vector128.Xor(vd, vs).CopyTo(dest.Slice(i));
            }
            for (; i < blockSize; i++)
                dest[i] ^= src[i];
        }
    }
    private static readonly ConcurrentDictionary<(int K, int symbolCount, int seed), (int[] deg, int[][] idx)> _symCache = new();

    private static (int[] deg, int[][] idx) GetOrBuildSymbols(int K, int symbolCount, int seed)
    {
        var key = (K, symbolCount, seed);
        if (_symCache.TryGetValue(key, out var cached))
            return cached;

        int N = 2 * K;
        ulong prng = (ulong)seed;
        var deg = new int[symbolCount];
        var idx = new int[symbolCount][];
        var idxSet = new HashSet<int>();

        for (int si = 0; si < symbolCount; si++)
        {
            int d = SelectDegree(ref prng);
            if (d > N) d = N;
            deg[si] = d;
            idxSet.Clear();
            while (idxSet.Count < d)
                idxSet.Add(NextPseudo(ref prng) % N);
            idx[si] = idxSet.ToArray();
        }

        _symCache[key] = (deg, idx);
        return (deg, idx);
    }

    public static (List<byte[]> symbols, int seed) Encode(
        byte[][] allBlocks, int symbolCount, int blockSize)
    {
        int K = allBlocks.Length;
        int N = 2 * K;
        int seed = K;

        var inter = Precode.Encode(allBlocks, blockSize);
        var (deg, symIdx) = GetOrBuildSymbols(K, symbolCount, seed);

        var result = new List<byte[]>(symbolCount);
        for (int si = 0; si < symbolCount; si++)
        {
            byte[] data = new byte[blockSize];
            var sd = data.AsSpan(0, blockSize);
            var siIdx = symIdx[si];
            for (int t = 0; t < siIdx.Length; t++)
                XorBlock(sd, inter[siIdx[t]].AsSpan(0, blockSize));
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

        int interSize = N * blockSize;
        int symSize = symbolCount * blockSize;
        byte[] interBuf = ArrayPool<byte>.Shared.Rent(interSize);
        byte[] symBuf = ArrayPool<byte>.Shared.Rent(symSize);
        var interSpan = interBuf.AsSpan(0, interSize);
        var symSpan = symBuf.AsSpan(0, symSize);

        try
        {
            for (int i = 0; i < K; i++)
                Buffer.BlockCopy(allBlocks[i], 0, interBuf, i * blockSize, blockSize);

            var known = new bool[N];
            var srcKnown = new bool[K];
            int totalBad = 0;
            for (int i = 0; i < K; i++)
            {
                if (!isCorrupted[i]) { known[i] = true; srcKnown[i] = true; }
                else totalBad++;
            }

            Precode.Derive(interSpan, known, K, blockSize);

            var initiallyKnown = new bool[N];
            Array.Copy(known, initiallyKnown, N);

            var (symDeg, symIdx) = GetOrBuildSymbols(K, symbolCount, seed);

            var remainingDeg = new int[symbolCount];
            int symStride = blockSize;
            for (int si = 0; si < symbolCount; si++)
            {
                int deg = symDeg[si];
                var siIdx = symIdx[si];
                for (int t = 0; t < siIdx.Length; t++)
                    if (known[siIdx[t]]) deg--;
                remainingDeg[si] = deg;
            }

            bool[] symMaterialized = new bool[symbolCount];

            void EnsureSym(int si)
            {
                if (!symMaterialized[si])
                {
                    Buffer.BlockCopy(allSymbolData, si * blockSize, symBuf, si * blockSize, blockSize);
                    symMaterialized[si] = true;
                }
            }

            var symToList = new List<int>[N];
            for (int i = 0; i < N; i++) symToList[i] = new List<int>();
            for (int si = 0; si < symbolCount; si++)
            {
                var siIdx = symIdx[si];
                for (int t = 0; t < siIdx.Length; t++)
                    symToList[siIdx[t]].Add(si);
            }
            var symToBlock = new int[N][];
            for (int i = 0; i < N; i++)
                symToBlock[i] = symToList[i].Count > 0 ? symToList[i].ToArray() : Array.Empty<int>();

            var queue = new Queue<int>();
            for (int si = 0; si < symbolCount; si++)
                if (remainingDeg[si] == 1) queue.Enqueue(si);

            int recovered = 0;

            while (recovered < totalBad)
            {
                bool progress = false;
                var newlyKnown = new HashSet<int>();

                var recoveredBlocks = new List<int>();
                while (queue.Count > 0)
                {
                    int si = queue.Dequeue();
                    if (remainingDeg[si] != 1) continue;

                    // Materialize symbol data if not yet copied from allSymbolData
                    EnsureSym(si);

                    // XOR out initially-known blocks to isolate the single unknown block
                    var sd = symSpan.Slice(si * symStride, blockSize);
                    var tgtIdx = symIdx[si];
                    for (int t = 0; t < tgtIdx.Length; t++)
                    {
                        int bi = tgtIdx[t];
                        if (initiallyKnown[bi])
                            XorBlock(sd, interSpan.Slice(bi * symStride, blockSize));
                    }

                    int target = -1;
                    for (int t = 0; t < tgtIdx.Length; t++)
                    {
                        int bi = tgtIdx[t];
                        if (!known[bi]) { target = bi; break; }
                    }
                    if (target < 0) continue;

                    sd.CopyTo(interSpan.Slice(target * symStride, blockSize));
                    known[target] = true;

                    if (target < K && !srcKnown[target])
                    {
                        Buffer.BlockCopy(interBuf, target * symStride, allBlocks[target], 0, blockSize);
                        srcKnown[target] = true;
                        recovered++;
                        progress = true;
                        recoveredBlocks.Add(target);
                    }

                    var stbArr = symToBlock[target];
                    var interTgtSlice = interSpan.Slice(target * symStride, blockSize);
                    for (int t = 0; t < stbArr.Length; t++)
                    {
                        int si2 = stbArr[t];
                        if (remainingDeg[si2] <= 1) continue;
                        EnsureSym(si2);
                        XorBlock(symSpan.Slice(si2 * symStride, blockSize), interTgtSlice);
                        remainingDeg[si2]--;
                        if (remainingDeg[si2] == 1)
                            queue.Enqueue(si2);
                    }
                }

                // Incremental Derive: only check neighbors of queue-recovered source blocks
                var derived = Precode.DeriveIncremental(interSpan, known, K, blockSize, recoveredBlocks);
                foreach (int d in derived)
                    newlyKnown.Add(d);

                var (unlocked, newSrcs) = Precode.Unlock(interSpan, known, srcKnown,
                    allBlocks, K, blockSize);
                if (unlocked > 0)
                {
                    recovered += unlocked;
                    progress = true;
                    foreach (int s in newSrcs)
                        newlyKnown.Add(s);

                    // Incremental Derive from unlocked source blocks
                    var derived2 = Precode.DeriveIncremental(interSpan, known, K, blockSize, newSrcs);
                    foreach (int d in derived2)
                        newlyKnown.Add(d);
                }

                if (progress && newlyKnown.Count > 0)
                {
                    queue.Clear();
                    foreach (int nk in newlyKnown)
                    {
                        var nkArr = symToBlock[nk];
                        var interSlice = interSpan.Slice(nk * symStride, blockSize);
                        for (int t = 0; t < nkArr.Length; t++)
                        {
                            int si = nkArr[t];
                            if (remainingDeg[si] <= 1) continue;
                            EnsureSym(si);
                            XorBlock(symSpan.Slice(si * symStride, blockSize), interSlice);
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
        finally
        {
            ArrayPool<byte>.Shared.Return(interBuf);
            ArrayPool<byte>.Shared.Return(symBuf);
        }
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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int SelectDegree(ref ulong state)
    {
        int v = NextPseudo(ref state);
        return DegreeMap[(int)((v & 0x7FFFFFFF) % 100)];
    }
}
