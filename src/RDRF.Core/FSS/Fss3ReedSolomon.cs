using RDRF.Core.Index;

namespace RDRF.Core.FSS;

/// <summary>
/// FSS3: 2D Reed-Solomon row+column encoding with sub-block parity.
/// </summary>

public class Fss3ReedSolomon : IFssStrategy
{
    private const int SubBlockSize = 16;
    private const int DefaultColParity = 2;

    public string Level => Constants.FssLevel3;

    private static int MatrixIdx(int f, int r, int B) => (f * B + r) * SubBlockSize;

    public List<byte[]> Encode(List<byte[]> fragments)
    {
        int K = fragments.Count;
        int maxSize = fragments.Max(f => f.Length);
        int B = (maxSize + SubBlockSize - 1) / SubBlockSize;
        int P = DefaultColParity;

        var rsRow = new ReedSolomon(K, 1);
        var rsCol = new ReedSolomon(B, P);

        byte[] matrix = new byte[K * B * SubBlockSize];
        for (int f = 0; f < K; f++)
        {
            var frag = fragments[f];
            for (int r = 0; r < B; r++)
            {
                int off = r * SubBlockSize;
                if (off < frag.Length)
                {
                    int len = Math.Min(SubBlockSize, frag.Length - off);
                    frag.AsSpan(off, len).CopyTo(matrix.AsSpan(MatrixIdx(f, r, B), len));
                }
            }
        }

        // Row RS → pack parity into rowFrag.
        // Systematic RS does not modify data shards.
        var po = new ParallelOptions { MaxDegreeOfParallelism = Constants.DefaultParallelism };
        byte[] rowFrag;
        if (RDRF.Core.Device.GpuContext.IsAvailable)
        {
            rowFrag = RDRF.Core.Device.GpuFss3.RowEncode(matrix, K, B, SubBlockSize);
        }
        else
        {
            rowFrag = new byte[B * SubBlockSize];
            Parallel.For(0, B, po, r =>
            {
                var shards = new byte[K + 1][];
                for (int f = 0; f < K; f++)
                {
                    shards[f] = new byte[SubBlockSize];
                    matrix.AsSpan(MatrixIdx(f, r, B), SubBlockSize).CopyTo(shards[f]);
                }
                shards[K] = new byte[SubBlockSize];
                rsRow.Encode(shards);
                Buffer.BlockCopy(shards[K], 0, rowFrag, r * SubBlockSize, SubBlockSize);
            });
        }

        // Column RS: keep only parity blocks (no data copy-back into matrix).
        var colParity = new byte[K][][];
        Parallel.For(0, K, po, f =>
        {
            var shards = new byte[B + P][];
            for (int r = 0; r < B; r++)
            {
                shards[r] = new byte[SubBlockSize];
                matrix.AsSpan(MatrixIdx(f, r, B), SubBlockSize).CopyTo(shards[r]);
            }
            for (int p = 0; p < P; p++)
                shards[B + p] = new byte[SubBlockSize];
            rsCol.Encode(shards);
            colParity[f] = new byte[P][];
            for (int p = 0; p < P; p++)
                colParity[f][p] = shards[B + p];
        });

        // Pack column parity into fragments
        int totalColBlocks = K * P;
        int blocksPerFrag = Math.Max(1, maxSize / SubBlockSize);
        int colFragCount = (totalColBlocks + blocksPerFrag - 1) / blocksPerFrag;
        var result = new List<byte[]>(fragments) { rowFrag };

        int blockIdx = 0;
        for (int c = 0; c < colFragCount; c++)
        {
            byte[] frag = new byte[blocksPerFrag * SubBlockSize];
            for (int j = 0; j < blocksPerFrag && blockIdx < totalColBlocks; j++, blockIdx++)
            {
                int f = blockIdx / P;
                int p = blockIdx % P;
                Buffer.BlockCopy(colParity[f][p], 0, frag, j * SubBlockSize, SubBlockSize);
            }
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
        int K = originalSizes?.Count ?? totalFragments;
        int maxSize = available.Values.Max(f => f.Length);
        int B = (maxSize + SubBlockSize - 1) / SubBlockSize;
        int P = DefaultColParity;
        int blocksPerFrag = Math.Max(1, maxSize / SubBlockSize);
        int colFragCount = (K * P + blocksPerFrag - 1) / blocksPerFrag;
        int totalEncoded = K + 1 + colFragCount;

        var rsRow = new ReedSolomon(K, 1);

        // Build initial matrix as flat array: zero for missing, data for available
        int matrixLen = K * B * SubBlockSize;
        byte[] matrix = new byte[matrixLen];
        for (int f = 0; f < K; f++)
        {
            if (available.TryGetValue(f, out var frag))
            {
                for (int r = 0; r < B; r++)
                {
                    int off = r * SubBlockSize;
                    if (off < frag.Length)
                    {
                        int len = Math.Min(SubBlockSize, frag.Length - off);
                        frag.AsSpan(off, len).CopyTo(matrix.AsSpan(MatrixIdx(f, r, B), len));
                    }
                }
            }
        }

        // Extract row parity fragment
        byte[] rowFrag = available.TryGetValue(K, out var rp) ? rp : null!;

        // Extract column parity blocks
        byte[][][] colParity = new byte[K][][];
        for (int f = 0; f < K; f++)
        {
            colParity[f] = new byte[P][];
            for (int p = 0; p < P; p++)
                colParity[f][p] = null!;
        }
        if (available.TryGetValue(K, out _))
        {
            int blockIdx = 0;
            for (int c = 0; c < colFragCount; c++)
            {
                if (available.TryGetValue(K + 1 + c, out var cf))
                {
                    for (int j = 0; j < blocksPerFrag && blockIdx < K * P; j++, blockIdx++)
                    {
                        int f = blockIdx / P;
                        int p = blockIdx % P;
                        byte[] block = new byte[SubBlockSize];
                        int off = j * SubBlockSize;
                        int len = Math.Min(SubBlockSize, cf.Length - off);
                        Buffer.BlockCopy(cf, off, block, 0, len);
                        colParity[f][p] = block;
                    }
                }
                else
                {
                    blockIdx += blocksPerFrag;
                }
            }
        }

        // Step 1: Row RS -> recover whole missing fragments
        var dataMissing = missingIndices.Where(m => m < K).ToList();
        if (dataMissing.Count > 0 && rowFrag != null)
        {
            Parallel.For(0, B, r =>
            {
                var shards = new byte[K + 1][];
                List<int> erasures = [];
                for (int f = 0; f < K; f++)
                {
                    shards[f] = new byte[SubBlockSize];
                    matrix.AsSpan(MatrixIdx(f, r, B), SubBlockSize).CopyTo(shards[f]);
                    if (dataMissing.Contains(f))
                        erasures.Add(f);
                }
                shards[K] = new byte[SubBlockSize];
                Buffer.BlockCopy(rowFrag, r * SubBlockSize, shards[K], 0, SubBlockSize);

                if (erasures.Count > 0 && erasures.Count <= 1)
                {
                    var decodeShards = new byte[K + 1][];
                    for (int f = 0; f <= K; f++)
                    {
                        if ((f < K && available.ContainsKey(f)) || (f == K && rowFrag != null))
                            decodeShards[f] = shards[f];
                        else
                            decodeShards[f] = new byte[SubBlockSize];
                    }

                    var rs = new ReedSolomon(K, 1);
                    var rowMissing = new List<int>();
                    foreach (int m in dataMissing)
                    {
                        if (m < K)
                            rowMissing.Add(m);
                    }
                    if (rowMissing.Count > 0)
                    {
                        if (rs.Decode(decodeShards, rowMissing))
                        {
                            foreach (int m in rowMissing)
                                decodeShards[m].CopyTo(matrix.AsSpan(MatrixIdx(m, r, B), SubBlockSize));
                        }
                    }
                }
            });
        }

        // Step 2: Column RS -> repair sub-block level corruption within fragments
        var rsCol = new ReedSolomon(B, P);
        Parallel.ForEach(dataMissing, f =>
        {
            if (f < colParity.Length && colParity[f][0] != null)
            {
                var shards = new byte[B + P][];
                var erasures = new List<int>();
                for (int r = 0; r < B; r++)
                {
                    shards[r] = new byte[SubBlockSize];
                    var src = matrix.AsSpan(MatrixIdx(f, r, B), SubBlockSize);
                    src.CopyTo(shards[r]);
                    if (IsZeroBlockSpan(src))
                        erasures.Add(r);
                }
                for (int p = 0; p < P; p++)
                    shards[B + p] = colParity[f][p];

                if (erasures.Count > 0 && erasures.Count <= P)
                {
                    rsCol.Decode(shards, erasures);
                    foreach (int r in erasures)
                        shards[r].CopyTo(matrix.AsSpan(MatrixIdx(f, r, B), SubBlockSize));
                }
            }
        });

        // Build result
        var result = new Dictionary<int, byte[]>();
        foreach (int idx in missingIndices)
        {
            if (idx >= K) continue;
            byte[] recovered = new byte[maxSize];
            for (int r = 0; r < B; r++)
            {
                int off = r * SubBlockSize;
                int len = Math.Min(SubBlockSize, recovered.Length - off);
                matrix.AsSpan(MatrixIdx(idx, r, B), len).CopyTo(recovered.AsSpan(off, len));
            }
            if (originalSizes != null && idx < originalSizes.Count && originalSizes[idx] > 0
                && originalSizes[idx] < recovered.Length)
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
                result.Add(StripSingle(data, i, originalSizes));
        }
        return result;
    }

    public byte[] StripSingle(byte[] encodedFragment, int index, List<int>? originalSizes = null)
    {
        if (originalSizes != null && index < originalSizes.Count && originalSizes[index] > 0
            && originalSizes[index] < encodedFragment.Length)
        {
            byte[] trimmed = new byte[originalSizes[index]];
            Buffer.BlockCopy(encodedFragment, 0, trimmed, 0, trimmed.Length);
            return trimmed;
        }
        return encodedFragment;
    }

    private static bool IsZeroBlockSpan(ReadOnlySpan<byte> block)
    {
        for (int i = 0; i < block.Length; i++)
            if (block[i] != 0) return false;
        return true;
    }

    private static bool IsZeroBlock(byte[] block)
    {
        for (int i = 0; i < block.Length; i++)
            if (block[i] != 0) return false;
        return true;
    }
}

