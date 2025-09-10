using RDRF.Core.Index;

namespace RDRF.Core.FSS;

public class Fss3ReedSolomon : IFssStrategy
{
    private const int SubBlockSize = 16;
    private const int DefaultColParity = 2;

    public string Level => Constants.FssLevel3;

    public List<byte[]> Encode(List<byte[]> fragments)
    {
        int K = fragments.Count;
        int maxSize = fragments.Max(f => f.Length);
        int B = (maxSize + SubBlockSize - 1) / SubBlockSize;
        int P = DefaultColParity;

        var rsRow = new ReedSolomon(K, 1);
        var rsCol = new ReedSolomon(B, P);

        // Build data matrix: K columns × B rows, each subBlock is 16 bytes
        byte[][][] matrix = new byte[K][][];
        for (int f = 0; f < K; f++)
        {
            matrix[f] = new byte[B][];
            for (int r = 0; r < B; r++)
            {
                int off = r * SubBlockSize;
                if (off < fragments[f].Length)
                {
                    int len = Math.Min(SubBlockSize, fragments[f].Length - off);
                    matrix[f][r] = new byte[SubBlockSize];
                    Buffer.BlockCopy(fragments[f], off, matrix[f][r], 0, len);
                }
                else
                {
                    matrix[f][r] = new byte[SubBlockSize];
                }
            }
        }

        // Row RS: each row across all K fragments
        var rowParity = new byte[B][];
        for (int r = 0; r < B; r++)
        {
            var shards = new byte[K + 1][];
            for (int f = 0; f < K; f++)
                shards[f] = matrix[f][r];
            shards[K] = new byte[SubBlockSize];
            rsRow.Encode(shards);
            rowParity[r] = shards[K];
        }

        // Pack row parity into 1 fragment
        byte[] rowFrag = new byte[B * SubBlockSize];
        for (int r = 0; r < B; r++)
            Buffer.BlockCopy(rowParity[r], 0, rowFrag, r * SubBlockSize, SubBlockSize);

        // Column RS: each fragment's B subBlocks
        var colParity = new byte[K][][];
        for (int f = 0; f < K; f++)
        {
            var shards = new byte[B + P][];
            for (int r = 0; r < B; r++)
                shards[r] = matrix[f][r];
            for (int p = 0; p < P; p++)
                shards[B + p] = new byte[SubBlockSize];
            rsCol.Encode(shards);
            colParity[f] = new byte[P][];
            for (int p = 0; p < P; p++)
                colParity[f][p] = shards[B + p];
        }

        // Pack column parity into fragments
        int totalColBlocks = K * P;
        int blocksPerFrag = maxSize / SubBlockSize;
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
        int blocksPerFrag = maxSize / SubBlockSize;
        int colFragCount = (K * P + blocksPerFrag - 1) / blocksPerFrag;
        int totalEncoded = K + 1 + colFragCount;

        var rsRow = new ReedSolomon(K, 1);

        // Build initial matrix: zero for missing, data for available
        byte[][][] matrix = new byte[K][][];
        for (int f = 0; f < K; f++)
        {
            matrix[f] = new byte[B][];
            if (available.TryGetValue(f, out var frag))
            {
                for (int r = 0; r < B; r++)
                {
                    int off = r * SubBlockSize;
                    if (off < frag.Length)
                    {
                        int len = Math.Min(SubBlockSize, frag.Length - off);
                        matrix[f][r] = new byte[SubBlockSize];
                        Buffer.BlockCopy(frag, off, matrix[f][r], 0, len);
                    }
                    else
                    {
                        matrix[f][r] = new byte[SubBlockSize];
                    }
                }
            }
            else
            {
                for (int r = 0; r < B; r++)
                    matrix[f][r] = new byte[SubBlockSize];
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

        // Step 1: Row RS → recover whole missing fragments
        var dataMissing = missingIndices.Where(m => m < K).ToList();
        if (dataMissing.Count > 0 && rowFrag != null)
        {
            for (int r = 0; r < B; r++)
            {
                var shards = new byte[K + 1][];
                var erasures = new List<int>();
                for (int f = 0; f < K; f++)
                {
                    shards[f] = matrix[f][r];
                    if (dataMissing.Contains(f))
                        erasures.Add(f);
                }
                shards[K] = new byte[SubBlockSize];
                Buffer.BlockCopy(rowFrag, r * SubBlockSize, shards[K], 0, SubBlockSize);

                if (erasures.Count > 0 && erasures.Count <= 1)
                {
                    // Use all available: K data (some missing) + 1 row parity = K+1 total
                    // Need: erasures.Count <= parityShards (1)
                    // The Decode needs the full array. Create a copy with all present.
                    var decodeShards = new byte[K + 1][];
                    for (int f = 0; f <= K; f++)
                    {
                        if (f < K && available.ContainsKey(f))
                            decodeShards[f] = shards[f];
                        else if (f == K && rowFrag != null)
                            decodeShards[f] = shards[f];
                        else
                            decodeShards[f] = new byte[SubBlockSize];
                    }

                    var rs = new ReedSolomon(K, 1);
                    // Build erasures for the current row's missing fragments
                    var rowMissing = new List<int>();
                    foreach (int m in dataMissing)
                    {
                        if (m < K && (m >= B || r < B)) // sanity check
                            rowMissing.Add(m);
                    }
                    if (rowMissing.Count > 0)
                    {
                        if (rs.Decode(decodeShards, rowMissing))
                        {
                            foreach (int m in rowMissing)
                                Buffer.BlockCopy(decodeShards[m], 0, matrix[m][r], 0, SubBlockSize);
                        }
                    }
                }
            }
        }

        // Step 2: Column RS → repair sub-block level corruption within fragments
        // (For missing fragments that were recovered above, verify column parity)
        var rsCol = new ReedSolomon(B, P);
        foreach (int f in dataMissing)
        {
            if (colParity[f][0] != null)
            {
                var shards = new byte[B + P][];
                var erasures = new List<int>();
                for (int r = 0; r < B; r++)
                {
                    shards[r] = matrix[f][r];
                    // Check if this block is zero (recovered but might be wrong)
                    if (IsZeroBlock(matrix[f][r]))
                        erasures.Add(r);
                }
                for (int p = 0; p < P; p++)
                    shards[B + p] = colParity[f][p];

                if (erasures.Count > 0 && erasures.Count <= P)
                {
                    rsCol.Decode(shards, erasures);
                    foreach (int r in erasures)
                        Buffer.BlockCopy(shards[r], 0, matrix[f][r], 0, SubBlockSize);
                }
            }
        }

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
                Buffer.BlockCopy(matrix[idx][r], 0, recovered, off, len);
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

    private static bool IsZeroBlock(byte[] block)
    {
        for (int i = 0; i < block.Length; i++)
            if (block[i] != 0) return false;
        return true;
    }
}
