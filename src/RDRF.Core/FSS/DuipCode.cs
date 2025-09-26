using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace RDRF.Core.FSS;

public static class DuipCode
{
    private const int MaxDegree = 8;

    public const int DefaultFaceSize = 32;
    public const int DefaultEntropyBits = 8;
    public const int DefaultBlockSize = 256;

    public static double RepairRatio { get; set; } = 0.5;

    // Cache disabled — entropy differs per data source (A/B/C), making simple key invalid.

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
        int extra = R - R1 - R2a - R2b - 1;
        if (extra > 0) R1 += extra;
        int R3 = 1;

        ulong prng = (ulong)seed;
        int[] colCoverage = new int[K];
        int[] faceCoverage = new int[faceCount];

        // Pre-sort faces by entropy for lowEntropyOnly
        var sortedFaces = Enumerable.Range(0, faceCount)
            .OrderBy(f => entropy[f]).ToArray();
        int third = Math.Max(1, faceCount / 3);

        var result = new List<byte[]>(R);

        // Layer 1: adaptive sparse
        for (int si = 0; si < R1; si++)
            result.Add(GenSymbol(sourceBlocks, K, blockSize, faceSize, entropy, entropyBits,
                ref prng, colCoverage, faceCoverage, sortedFaces, third,
                useReverseDeg: false, lowEntropyOnly: false));

        // Layer 2A: reverse compensation
        for (int si = 0; si < R2a; si++)
            result.Add(GenSymbol(sourceBlocks, K, blockSize, faceSize, entropy, entropyBits,
                ref prng, colCoverage, faceCoverage, sortedFaces, third,
                useReverseDeg: true, lowEntropyOnly: false));

        // Layer 2B: cross-region bridging (low entropy faces only)
        for (int si = 0; si < R2b; si++)
            result.Add(GenSymbol(sourceBlocks, K, blockSize, faceSize, entropy, entropyBits,
                ref prng, colCoverage, faceCoverage, sortedFaces, third,
                useReverseDeg: false, lowEntropyOnly: true));

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

        // Phase 3: Face-by-face matrix solve (faceSize = DefaultFaceSize)
        if (recovered < totalBad)
        {
            int faceSz = DefaultFaceSize;
            int fCount = (K + faceSz - 1) / faceSz;

            // Group remaining unknown blocks by face
            var unkByFace = new List<int>[fCount];
            for (int i = 0; i < fCount; i++) unkByFace[i] = new List<int>();
            for (int i = 0; i < K; i++)
                if (!known[i])
                    unkByFace[i / faceSz].Add(i);

            for (int f = 0; f < fCount; f++)
            {
                var unk = unkByFace[f];
                if (unk.Count == 0) continue;
                int Nf = unk.Count;

                // Build colMap: block index → column in matrix
                var colMap = new Dictionary<int, int>();
                for (int i = 0; i < Nf; i++)
                    colMap[unk[i]] = i;

                // Collect symbols that cover any of this face's unknown blocks
                var rows = new List<int>();  // symbol indices
                for (int si = 0; si < R - 1; si++)
                {
                    var idxArr = symIdx[si];
                    for (int t = 0; t < idxArr.Length; t++)
                    {
                        if (colMap.ContainsKey(idxArr[t]))
                        {
                            rows.Add(si);
                            break;
                        }
                    }
                }

                int Mf = rows.Count;
                if (Mf < Nf) continue;  // not enough constraints

                // Build Mf × Nf matrix + RHS
                int[,] mat = new int[Mf, Nf];
                byte[] rhsMat = new byte[Mf * blockSize];

                for (int r = 0; r < Mf; r++)
                {
                    int si = rows[r];
                    var idxArr = symIdx[si];

                    // Copy symbol raw data
                    Buffer.BlockCopy(allSymbolData, si * blockSize, rhsMat, r * blockSize, blockSize);

                    // XOR out all known blocks
                    for (int t = 0; t < idxArr.Length; t++)
                    {
                        int bi = idxArr[t];
                        if (known[bi])
                            XorBlock(rhsMat.AsSpan(r * blockSize, blockSize), allBlocks[bi].AsSpan(0, blockSize));
                    }

                    // XOR out non-face unknown blocks (cross-face blocks treated as known for this face)
                    for (int t = 0; t < idxArr.Length; t++)
                    {
                        int bi = idxArr[t];
                        if (!known[bi] && !colMap.ContainsKey(bi))
                            XorBlock(rhsMat.AsSpan(r * blockSize, blockSize), allBlocks[bi].AsSpan(0, blockSize));
                    }

                    // Mark face-local columns
                    for (int t = 0; t < idxArr.Length; t++)
                    {
                        int bi = idxArr[t];
                        if (colMap.TryGetValue(bi, out int ci))
                            mat[r, ci] = 1;
                    }
                }

                // Gaussian elimination
                int rank = GaussianEliminate(mat, Mf, Nf);
                if (rank < Nf) continue;  // can't fully solve this face

                // Back-substitute
                for (int col = 0; col < Nf; col++)
                {
                    int pivotRow = -1;
                    for (int r = col; r < Mf; r++)
                    {
                        if (mat[r, col] == 1) { pivotRow = r; break; }
                    }
                    if (pivotRow < 0) continue;

                    int srcBlock = unk[col];
                    Span<byte> recBuf = stackalloc byte[blockSize];
                    rhsMat.AsSpan(pivotRow * blockSize, blockSize).CopyTo(recBuf);

                    for (int c = col + 1; c < Nf; c++)
                    {
                        if (mat[pivotRow, c] == 1)
                            XorBlock(recBuf, allBlocks[unk[c]].AsSpan(0, blockSize));
                    }

                    recBuf.CopyTo(allBlocks[srcBlock]);
                    known[srcBlock] = true;
                    recovered++;
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

            // XOR first 64 bytes of all blocks in this face (SIMD)
            Vector256<byte> acc = Vector256<byte>.Zero;
            for (int i = start; i < end; i++)
            {
                int copyLen = Math.Min(64, sourceBlocks[i].Length);
                ref byte sRef = ref MemoryMarshal.GetReference(sourceBlocks[i].AsSpan());
                acc = Avx2.Xor(acc, Vector256.LoadUnsafe(ref sRef));
                // Also XOR the next 32 bytes for the remaining 32-63 range
                if (copyLen > 32)
                {
                    ref byte sRef2 = ref MemoryMarshal.GetReference(sourceBlocks[i].AsSpan(32));
                    acc = Avx2.Xor(acc, Vector256.LoadUnsafe(ref sRef2));
                }
            }

            ulong hash = System.IO.Hashing.XxHash64.HashToUInt64(MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref acc, 1)));
            entropy[f] = (byte)(hash & ((1UL << entropyBits) - 1));
        }

        return entropy;
    }

    // ── Symbol Generation ──

    private static byte[] GenSymbol(byte[][] sourceBlocks, int K, int blockSize,
        int faceSize, byte[] entropy, int entropyBits,
        ref ulong prng, int[] colCoverage, int[] faceCoverage,
        int[] sortedFaces, int third,
        bool useReverseDeg, bool lowEntropyOnly)
    {
        int anchorFace;
        if (useReverseDeg)
        {
            int minCover = int.MaxValue;
            anchorFace = 0;
            for (int f = 0; f < faceCoverage.Length; f++)
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
            anchorFace = sortedFaces[NextPseudo(ref prng) % third];
        }
        else
        {
            anchorFace = NextPseudo(ref prng) % faceCoverage.Length;
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
            degree = Math.Clamp(10 - degree, 2, MaxDegree);

        Span<int> used = stackalloc int[MaxDegree];
        int usedCount = 0;

        int anchorCol = anchorFace * faceSize + (NextPseudo(ref prng) % Math.Min(faceSize, K - anchorFace * faceSize));
        used[usedCount++] = anchorCol;
        colCoverage[anchorCol]++;

        for (int t = 1; t < degree; t++)
        {
            int col;
            if (NextPseudo(ref prng) % 3 > 0)
            {
                Span<int> lowCov = stackalloc int[K];
                int lowCnt = 0;
                for (int i = 0; i < K; i++)
                {
                    if (colCoverage[i] < 2 && !IsUsed(used, usedCount, i))
                        lowCov[lowCnt++] = i;
                }
                if (lowCnt > 0)
                {
                    col = lowCov[NextPseudo(ref prng) % lowCnt];
                    colCoverage[col]++;
                    used[usedCount++] = col;
                    continue;
                }
            }

            // Fallback: random column (accept duplicates)
            col = NextPseudo(ref prng) % K;
            bool dup = false;
            for (int i = 0; i < usedCount; i++)
                if (used[i] == col) { dup = true; break; }
            if (!dup)
                colCoverage[col]++;
            used[usedCount++] = col;
        }

        // XOR all selected columns
        byte[] sym = new byte[blockSize];
        for (int i = 0; i < usedCount; i++)
            XorBlock(sym.AsSpan(0, blockSize), sourceBlocks[used[i]].AsSpan(0, blockSize));
        return sym;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsUsed(Span<int> used, int count, int col)
    {
        for (int i = 0; i < count; i++)
            if (used[i] == col) return true;
        return false;
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

        var sortedFaces = Enumerable.Range(0, faceCount)
            .OrderBy(f => entropy[f]).ToArray();
        int third = Math.Max(1, faceCount / 3);

        int si = 0;
        for (int i = 0; i < R1 && si < R - 1; i++, si++)
            BuildOneSymbol(K, faceSize, entropy, entropyBits, ref prng,
                colCoverage, faceCoverage, sortedFaces, third, false, false,
                out symDeg[si], out symIdx[si]);

        for (int i = 0; i < R2a && si < R - 1; i++, si++)
            BuildOneSymbol(K, faceSize, entropy, entropyBits, ref prng,
                colCoverage, faceCoverage, sortedFaces, third, true, false,
                out symDeg[si], out symIdx[si]);

        for (int i = 0; i < R2b && si < R - 1; i++, si++)
            BuildOneSymbol(K, faceSize, entropy, entropyBits, ref prng,
                colCoverage, faceCoverage, sortedFaces, third, false, true,
                out symDeg[si], out symIdx[si]);

        var allIndices = new int[K];
        for (int i = 0; i < K; i++) allIndices[i] = i;
        symDeg[R - 1] = K;
        symIdx[R - 1] = allIndices;
    }

    private static void BuildOneSymbol(int K, int faceSize,
        byte[] entropy, int entropyBits, ref ulong prng,
        int[] colCoverage, int[] faceCoverage,
        int[] sortedFaces, int third,
        bool useReverseDeg, bool lowEntropyOnly,
        out int degree, out int[] indices)
    {
        int anchorFace;
        if (useReverseDeg)
        {
            int minCover = int.MaxValue;
            anchorFace = 0;
            for (int f = 0; f < faceCoverage.Length; f++)
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
            anchorFace = sortedFaces[NextPseudo(ref prng) % third];
        }
        else
        {
            anchorFace = NextPseudo(ref prng) % faceCoverage.Length;
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
            degree = Math.Clamp(10 - degree, 2, MaxDegree);

        Span<int> used = stackalloc int[MaxDegree];
        int usedCount = 0;

        int anchorCol = anchorFace * faceSize + (NextPseudo(ref prng) % Math.Min(faceSize, K - anchorFace * faceSize));
        used[usedCount++] = anchorCol;
        colCoverage[anchorCol]++;

        for (int t = 1; t < degree; t++)
        {
            int col;
            if (NextPseudo(ref prng) % 3 > 0)
            {
                Span<int> lowCov = stackalloc int[K];
                int lowCnt = 0;
                for (int i = 0; i < K; i++)
                {
                    if (colCoverage[i] < 2 && !IsUsed(used, usedCount, i))
                        lowCov[lowCnt++] = i;
                }
                if (lowCnt > 0)
                {
                    col = lowCov[NextPseudo(ref prng) % lowCnt];
                    colCoverage[col]++;
                    used[usedCount++] = col;
                    continue;
                }
            }

            // Fallback: random column (accept duplicates)
            col = NextPseudo(ref prng) % K;
            bool dup = false;
            for (int i = 0; i < usedCount; i++)
                if (used[i] == col) { dup = true; break; }
            if (!dup)
                colCoverage[col]++;
            used[usedCount++] = col;
        }

        indices = new int[usedCount];
        for (int i = 0; i < usedCount; i++)
            indices[i] = used[i];
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
