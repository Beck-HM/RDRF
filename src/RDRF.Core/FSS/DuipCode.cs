using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace RDRF.Core.FSS;

public static class DuipCode
{
    public const int DefaultFaceSize = 32;
    public const int DefaultEntropyBits = 8;
    public const int DefaultBlockSize = 256;

    public static double RepairRatio { get; set; } = 0.5;

    public static (List<byte[]> symbols, byte[] entropySamples, int seed) Encode(
        byte[][] sourceBlocks, int blockSize, int faceSize = DefaultFaceSize, int entropyBits = DefaultEntropyBits)
    {
        int K = sourceBlocks.Length;
        int R = Math.Max(1, (int)(K * RepairRatio));
        int seed = K;

        int faceCount = (K + faceSize - 1) / faceSize;
        byte[] entropy = ComputeEntropy(sourceBlocks, faceSize, entropyBits, blockSize);

        int R1 = (int)(0.4 * R);
        int R2a = (int)(0.25 * R);
        int R2b = (int)(0.25 * R);
        // Layer 3 is always exactly 1 Global symbol. Excess symbols go to Layer 1.
        int extra = R - R1 - R2a - R2b - 1;
        if (extra > 0) R1 += extra;
        int R3 = 1;

        ulong prng = (ulong)seed;
        int[] colCoverage = new int[K];
        int[] faceCoverage = new int[faceCount];

        var result = new List<byte[]>(R);

        // Layer 1: adaptive sparse
        for (int si = 0; si < R1; si++)
            result.Add(GenSymbol(sourceBlocks, K, blockSize, faceSize, faceCount, entropy, entropyBits,
                ref prng, colCoverage, faceCoverage, useReverseDeg: false, lowEntropyOnly: false));

        // Layer 2A: reverse compensation
        for (int si = 0; si < R2a; si++)
            result.Add(GenSymbol(sourceBlocks, K, blockSize, faceSize, faceCount, entropy, entropyBits,
                ref prng, colCoverage, faceCoverage, useReverseDeg: true, lowEntropyOnly: false));

        // Layer 2B: cross-region bridging (low entropy faces only)
        for (int si = 0; si < R2b; si++)
            result.Add(GenSymbol(sourceBlocks, K, blockSize, faceSize, faceCount, entropy, entropyBits,
                ref prng, colCoverage, faceCoverage, useReverseDeg: false, lowEntropyOnly: true));

        // Layer 3: exactly 1 Global symbol (XOR all source)
        byte[] global = new byte[blockSize];
        for (int j = 0; j < K; j++)
            XorBlock(global.AsSpan(0, blockSize), sourceBlocks[j].AsSpan(0, blockSize));
        result.Add(global);

        return (result, entropy, seed);
    }

    public static int Decode(
        byte[][] allBlocks, bool[] isCorrupted,
        byte[] allSymbolData, byte[] entropySamples,
        int K, int blockSize, int faceSize, int entropyBits)
    {
        if (K == 0) return 0;
        int R = allSymbolData.Length / blockSize;
        int faceCount = (K + faceSize - 1) / faceSize;
        int globalIdx = R - 1;

        int stride = blockSize;
        int symStride = stride;

        var known = new bool[K];
        int totalBad = 0;
        for (int i = 0; i < K; i++)
        {
            known[i] = !isCorrupted[i];
            if (isCorrupted[i]) totalBad++;
        }

        if (totalBad == 0) return K;

        // Build symIdx and remainingDeg from entropy + PRNG
        ulong prng = (ulong)K;
        var symDeg = new int[R];
        var symIdx = new int[R][];
        BuildSymbols(R, K, faceSize, faceCount, entropySamples, entropyBits,
            ref prng, symDeg, symIdx);

        var symToList = new List<int>[K];
        for (int i = 0; i < K; i++) symToList[i] = new List<int>();
        for (int si = 0; si < R - 1; si++)
        {
            var idxArr = symIdx[si];
            for (int t = 0; t < idxArr.Length; t++)
                symToList[idxArr[t]].Add(si);
        }
        var symToBlock = new int[K][];
        for (int i = 0; i < K; i++)
            symToBlock[i] = symToList[i].Count > 0 ? symToList[i].ToArray() : Array.Empty<int>();

        var remainingDeg = new int[R];
        for (int si = 0; si < R - 1; si++)
        {
            int deg = symDeg[si];
            var idxArr = symIdx[si];
            for (int t = 0; t < idxArr.Length; t++)
                if (known[idxArr[t]]) deg--;
            remainingDeg[si] = deg;
        }

        // Phase 1: BP Ripple
        var queue = new Queue<int>();
        for (int si = 0; si < R - 1; si++)
            if (remainingDeg[si] == 1) queue.Enqueue(si);

        int recovered = 0;

        while (recovered < totalBad)
        {
            bool progress = false;

            while (queue.Count > 0)
            {
                int si = queue.Dequeue();
                if (remainingDeg[si] != 1) continue;

                int target = -1;
                var tgtIdx = symIdx[si];
                for (int t = 0; t < tgtIdx.Length; t++)
                {
                    int bi = tgtIdx[t];
                    if (!known[bi]) { target = bi; break; }
                }
                if (target < 0) continue;

                // Recover target block from this symbol
                int symOff = si * symStride;
                allSymbolData.AsSpan(symOff, blockSize).CopyTo(allBlocks[target]);
                // XOR all known blocks in this symbol out
                for (int t = 0; t < tgtIdx.Length; t++)
                {
                    int bi = tgtIdx[t];
                    if (bi != target && known[bi])
                        XorBlock(allBlocks[target].AsSpan(0, blockSize), allBlocks[bi].AsSpan(0, blockSize));
                }

                known[target] = true;
                recovered++;
                progress = true;

                var stbArr = symToBlock[target];
                for (int t = 0; t < stbArr.Length; t++)
                {
                    int si2 = stbArr[t];
                    if (remainingDeg[si2] <= 1) continue;
                    XorBlock(allSymbolData.AsSpan(si2 * symStride, blockSize),
                        allBlocks[target].AsSpan(0, blockSize));
                    remainingDeg[si2]--;
                    if (remainingDeg[si2] == 1)
                        queue.Enqueue(si2);
                }
            }

            // Phase 2: Global (recover last 1 block)
            if (recovered < totalBad)
            {
                int missing = -1;
                int knownCount = 0;
                for (int i = 0; i < K; i++)
                {
                    if (known[i]) knownCount++;
                    else missing = i;
                }
                if (knownCount == K - 1 && missing >= 0)
                {
                    allSymbolData.AsSpan(globalIdx * symStride, blockSize).CopyTo(allBlocks[missing]);
                    for (int i = 0; i < K; i++)
                    {
                        if (i != missing)
                            XorBlock(allBlocks[missing].AsSpan(0, blockSize), allBlocks[i].AsSpan(0, blockSize));
                    }
                    known[missing] = true;
                    recovered++;
                    progress = true;
                }
            }

            if (!progress) break;
        }

        // Phase 3: Small matrix (≤3 unknown blocks)
        if (recovered < totalBad)
        {
            var unknown = new List<int>();
            for (int i = 0; i < K; i++)
                if (!known[i]) unknown.Add(i);
            int N = unknown.Count;

            // Collect symbols covering these unknown blocks
            var coveringSymbols = new List<int>();
            for (int si = 0; si < R - 1; si++)
            {
                var idxArr = symIdx[si];
                bool covers = false;
                for (int t = 0; t < idxArr.Length; t++)
                {
                    if (unknown.Contains(idxArr[t])) { covers = true; break; }
                }
                if (covers) coveringSymbols.Add(si);
            }
            int M = coveringSymbols.Count;

            if (N <= 3 && M >= N + 1)
            {
                // Build M×N matrix over GF(2)
                int[,] mat = new int[M, N];
                byte[] rhs = new byte[M * blockSize];

                for (int mi = 0; mi < M; mi++)
                {
                    int si = coveringSymbols[mi];
                    var idxArr = symIdx[si];
                    for (int t = 0; t < idxArr.Length; t++)
                    {
                        int col = unknown.IndexOf(idxArr[t]);
                        if (col >= 0)
                            mat[mi, col] = 1;
                    }
                    Buffer.BlockCopy(allSymbolData, si * symStride, rhs, mi * blockSize, blockSize);
                }

                // Gaussian elimination over GF(2)
                int rank = GaussianEliminate(mat, M, N);
                if (rank >= N)
                {
                    // Back-substitute to recover each unknown block
                    for (int col = 0; col < N; col++)
                    {
                        int pivotRow = -1;
                        for (int r = col; r < M; r++)
                        {
                            if (mat[r, col] == 1) { pivotRow = r; break; }
                        }
                        if (pivotRow < 0) continue;

                        int srcBlock = unknown[col];
                        byte[] recoveredData = new byte[blockSize];
                        Buffer.BlockCopy(rhs, pivotRow * blockSize, recoveredData, 0, blockSize);

                        // XOR all already-known columns in this row
                        for (int c = col + 1; c < N; c++)
                        {
                            if (mat[pivotRow, c] == 1)
                                XorBlock(recoveredData.AsSpan(), allBlocks[unknown[c]].AsSpan(0, blockSize));
                        }

                        Buffer.BlockCopy(recoveredData, 0, allBlocks[srcBlock], 0, blockSize);
                        known[srcBlock] = true;
                        recovered++;
                    }
                }
            }
        }

        return recovered;
    }

    // ── Entropy ──

    private static byte[] ComputeEntropy(byte[][] sourceBlocks, int faceSize, int entropyBits, int blockSize)
    {
        int K = sourceBlocks.Length;
        int faceCount = (K + faceSize - 1) / faceSize;
        byte[] entropy = new byte[faceCount];

        for (int f = 0; f < faceCount; f++)
        {
            int start = f * faceSize;
            int end = Math.Min(start + faceSize, K);

            // XOR first 64 bytes of all blocks in this face
            Span<byte> xorBuf = stackalloc byte[64];
            for (int i = start; i < end; i++)
            {
                int copyLen = Math.Min(64, sourceBlocks[i].Length);
                for (int j = 0; j < copyLen; j++)
                    xorBuf[j] ^= sourceBlocks[i][j];
            }

            ulong hash = System.IO.Hashing.XxHash64.HashToUInt64(xorBuf);
            entropy[f] = (byte)(hash & ((1UL << entropyBits) - 1));
        }

        return entropy;
    }

    // ── Symbol Generation ──

    private static byte[] GenSymbol(byte[][] sourceBlocks, int K, int blockSize,
        int faceSize, int faceCount, byte[] entropy, int entropyBits,
        ref ulong prng, int[] colCoverage, int[] faceCoverage,
        bool useReverseDeg, bool lowEntropyOnly)
    {
        int faceMaxVal = (1 << entropyBits) - 1;

        // Choose anchor face
        int anchorFace;
        if (useReverseDeg)
        {
            // Pick least covered face
            int minCover = int.MaxValue;
            anchorFace = 0;
            for (int f = 0; f < faceCount; f++)
            {
                if (faceCoverage[f] < minCover)
                {
                    minCover = faceCoverage[f];
                    anchorFace = f;
                }
            }
        }
        else if (lowEntropyOnly)
        {
            // Pick from lowest-entropy 1/3 of faces
            var sorted = Enumerable.Range(0, faceCount)
                .OrderBy(f => entropy[f]).ToList();
            int third = Math.Max(1, faceCount / 3);
            anchorFace = sorted[NextPseudo(ref prng) % third];
        }
        else
        {
            anchorFace = NextPseudo(ref prng) % faceCount;
        }
        faceCoverage[anchorFace]++;

        int entVal = entropy[anchorFace];
        int degree = entVal switch
        {
            <= 1 => 2,
            <= 5 => 3,
            <= 9 => 4,
            <= 12 => 5,
            _ => 6,
        };

        if (useReverseDeg)
            degree = Math.Clamp(10 - degree, 2, 8);

        // Select columns for this symbol
        var used = new List<int>();
        int anchorCol = anchorFace * faceSize + (NextPseudo(ref prng) % Math.Min(faceSize, K - anchorFace * faceSize));
        used.Add(anchorCol);
        colCoverage[anchorCol]++;

        // Remaining degree-1 columns
        for (int t = 1; t < degree; t++)
        {
            int col;
            if (NextPseudo(ref prng) % 3 > 0)
            {
                // Pick from columns with coverage < 2
                var lowCov = new List<int>();
                for (int i = 0; i < K; i++)
                    if (colCoverage[i] < 2 && !used.Contains(i))
                        lowCov.Add(i);
                if (lowCov.Count > 0)
                {
                    col = lowCov[NextPseudo(ref prng) % lowCov.Count];
                    colCoverage[col]++;
                    used.Add(col);
                    continue;
                }
            }

            // Fallback: random unused column
            int tries = 0;
            do
            {
                col = NextPseudo(ref prng) % K;
                tries++;
            } while (used.Contains(col) && tries < K * 2);

            if (!used.Contains(col))
            {
                colCoverage[col]++;
                used.Add(col);
            }
            else
            {
                // Accept duplicate if all columns already covered
                col = NextPseudo(ref prng) % K;
                used.Add(col);
            }
        }

        // XOR all selected columns
        byte[] sym = new byte[blockSize];
        foreach (int bi in used)
            XorBlock(sym.AsSpan(0, blockSize), sourceBlocks[bi].AsSpan(0, blockSize));
        return sym;
    }

    private static int GaussianEliminate(int[,] mat, int rows, int cols)
    {
        int rank = 0;
        for (int col = 0; col < cols; col++)
        {
            int pivot = -1;
            for (int r = rank; r < rows; r++)
            {
                if (mat[r, col] == 1) { pivot = r; break; }
            }
            if (pivot < 0) continue;

            // Swap
            for (int c = col; c < cols; c++)
                (mat[rank, c], mat[pivot, c]) = (mat[pivot, c], mat[rank, c]);

            // Eliminate other rows
            for (int r = 0; r < rows; r++)
            {
                if (r != rank && mat[r, col] == 1)
                {
                    for (int c = col; c < cols; c++)
                        mat[r, c] ^= mat[rank, c];
                }
            }
            rank++;
        }
        return rank;
    }

    private static void BuildSymbols(int R, int K, int faceSize, int faceCount,
        byte[] entropy, int entropyBits, ref ulong prng,
        int[] symDeg, int[][] symIdx)
    {
        int R1 = (int)(0.4 * R);
        int R2a = (int)(0.25 * R);
        int R2b = (int)(0.25 * R);
        int extra = R - R1 - R2a - R2b - 1;
        if (extra > 0) R1 += extra;

        int[] colCoverage = new int[K];
        int[] faceCoverage = new int[faceCount];

        int si = 0;
        for (int i = 0; i < R1 && si < R - 1; i++, si++)
            BuildOneSymbol(K, faceSize, faceCount, entropy, entropyBits, ref prng,
                colCoverage, faceCoverage, false, false, out symDeg[si], out symIdx[si]);

        for (int i = 0; i < R2a && si < R - 1; i++, si++)
            BuildOneSymbol(K, faceSize, faceCount, entropy, entropyBits, ref prng,
                colCoverage, faceCoverage, true, false, out symDeg[si], out symIdx[si]);

        for (int i = 0; i < R2b && si < R - 1; i++, si++)
            BuildOneSymbol(K, faceSize, faceCount, entropy, entropyBits, ref prng,
                colCoverage, faceCoverage, false, true, out symDeg[si], out symIdx[si]);

        // Last symbol (si = R - 1) = Global (degree K, all indices)
        var allIndices = new int[K];
        for (int i = 0; i < K; i++) allIndices[i] = i;
        symDeg[R - 1] = K;
        symIdx[R - 1] = allIndices;
    }

    private static void BuildOneSymbol(int K, int faceSize, int faceCount,
        byte[] entropy, int entropyBits, ref ulong prng,
        int[] colCoverage, int[] faceCoverage,
        bool useReverseDeg, bool lowEntropyOnly,
        out int degree, out int[] indices)
    {
        int anchorFace;
        if (useReverseDeg)
        {
            int minCover = int.MaxValue;
            anchorFace = 0;
            for (int f = 0; f < faceCount; f++)
            {
                if (faceCoverage[f] < minCover)
                {
                    minCover = faceCoverage[f];
                    anchorFace = f;
                }
            }
        }
        else if (lowEntropyOnly)
        {
            var sorted = Enumerable.Range(0, faceCount)
                .OrderBy(f => entropy[f]).ToList();
            int third = Math.Max(1, faceCount / 3);
            anchorFace = sorted[NextPseudo(ref prng) % third];
        }
        else
        {
            anchorFace = NextPseudo(ref prng) % faceCount;
        }
        faceCoverage[anchorFace]++;

        int entVal = entropy[anchorFace];
        degree = entVal switch
        {
            <= 1 => 2,
            <= 5 => 3,
            <= 9 => 4,
            <= 12 => 5,
            _ => 6,
        };

        if (useReverseDeg)
            degree = Math.Clamp(10 - degree, 2, 8);

        int faceStart = anchorFace * faceSize;
        int faceEnd = Math.Min(faceStart + faceSize, K);
        int faceLen = faceEnd - faceStart;
        int anchorCol = anchorFace * faceSize + (NextPseudo(ref prng) % faceLen);

        var used = new List<int> { anchorCol };
        colCoverage[anchorCol]++;

        for (int t = 1; t < degree; t++)
        {
            int col;
            if (NextPseudo(ref prng) % 3 > 0)
            {
                var lowCov = new List<int>();
                for (int i = 0; i < K; i++)
                    if (colCoverage[i] < 2 && !used.Contains(i))
                        lowCov.Add(i);
                if (lowCov.Count > 0)
                {
                    col = lowCov[NextPseudo(ref prng) % lowCov.Count];
                    colCoverage[col]++;
                    used.Add(col);
                    continue;
                }
            }

            int tries = 0;
            do
            {
                col = NextPseudo(ref prng) % K;
                tries++;
            } while (used.Contains(col) && tries < K * 2);

            if (!used.Contains(col))
            {
                colCoverage[col]++;
                used.Add(col);
            }
            else
            {
                col = NextPseudo(ref prng) % K;
                used.Add(col);
            }
        }

        indices = used.ToArray();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void XorBlock(Span<byte> dest, ReadOnlySpan<byte> src)
    {
        int len = dest.Length;
        ref byte dRef = ref MemoryMarshal.GetReference(dest);
        ref byte sRef = ref MemoryMarshal.GetReference(src);
        int i = 0;
        if (Avx2.IsSupported)
        {
            for (; i + 32 <= len; i += 32)
            {
                Vector256.Xor(
                    Vector256.LoadUnsafe(ref dRef, (nuint)i),
                    Vector256.LoadUnsafe(ref sRef, (nuint)i))
                    .CopyTo(dest.Slice(i));
            }
        }
        for (; i + 16 <= len; i += 16)
        {
            Vector128.Xor(
                Vector128.LoadUnsafe(ref dRef, (nuint)i),
                Vector128.LoadUnsafe(ref sRef, (nuint)i))
                .CopyTo(dest.Slice(i));
        }
        for (; i < len; i++)
            dest[i] ^= src[i];
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
}
