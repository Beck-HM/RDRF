using System.Threading.Tasks;

namespace RDRF.Core.FSS;

public class ReedSolomon
{
    private readonly int _dataShards;
    private readonly int _parityShards;
    private readonly int _totalShards;
    private readonly byte[,] _encodeMatrix;

    private static readonly byte[] ExpTable = new byte[512];
    private static readonly byte[] LogTable = new byte[256];

    static ReedSolomon()
    {
        byte val = 1;
        for (int i = 0; i < 255; i++)
        {
            ExpTable[i] = val;
            LogTable[val] = (byte)i;
            val = GfMulVal(val, 2);
        }
        for (int i = 255; i < 512; i++)
            ExpTable[i] = ExpTable[i - 255];
    }

    public ReedSolomon(int dataShards, int parityShards)
    {
        _dataShards = dataShards;
        _parityShards = parityShards;
        _totalShards = dataShards + parityShards;

        // Precompute encoding matrix: _encodeMatrix[p, k] = coefficient for data[k] in parity shard p
        _encodeMatrix = new byte[parityShards, dataShards];
        for (int p = 0; p < parityShards; p++)
            for (int k = 0; k < dataShards; k++)
                _encodeMatrix[p, k] = ExpTable[((p + 1) * k) % 255];
    }

    // ── Encode ──

    public byte[][] Encode(byte[][] shards)
    {
        int shardSize = shards[0].Length;
        Parallel.For(0, _parityShards, p =>
        {
            int i = _dataShards + p;
            byte[] parity = new byte[shardSize];
            for (int j = 0; j < shardSize; j++)
            {
                byte val = 0;
                int k = 0;
                for (; k + 4 <= _dataShards; k += 4)
                {
                    byte c0 = _encodeMatrix[p, k];
                    if (c0 != 0) val ^= GfMul(c0, shards[k][j]);
                    byte c1 = _encodeMatrix[p, k + 1];
                    if (c1 != 0) val ^= GfMul(c1, shards[k + 1][j]);
                    byte c2 = _encodeMatrix[p, k + 2];
                    if (c2 != 0) val ^= GfMul(c2, shards[k + 2][j]);
                    byte c3 = _encodeMatrix[p, k + 3];
                    if (c3 != 0) val ^= GfMul(c3, shards[k + 3][j]);
                }
                for (; k < _dataShards; k++)
                {
                    byte c = _encodeMatrix[p, k];
                    if (c != 0) val ^= GfMul(c, shards[k][j]);
                }
                parity[j] = val;
            }
            shards[i] = parity;
        });
        return shards;
    }

    // ── Decode with erasures ──
    //
    // Uses GF(256) matrix inversion on the encoding matrix sub-matrix
    // to reconstruct missing shards.  Supports any (dataShards, parityShards)
    // configuration as long as fewer than parityShards shards are lost.

    public bool Decode(byte[][] shards, List<int> erasures)
    {
        int shardSize = shards[0].Length;
        int presentCount = _totalShards - erasures.Count;
        if (presentCount < _dataShards) return false;

        var presentIndices = new List<int>();
        for (int i = 0; i < _totalShards; i++)
            if (!erasures.Contains(i)) presentIndices.Add(i);

        var decodeIndices = presentIndices.Take(_dataShards).ToList();

        // Build encoding sub-matrix A for the chosen present shards.
        // A[r][c] = coefficient for data[c] in shard decodeIndices[r].
        byte[][] A = new byte[_dataShards][];
        for (int r = 0; r < _dataShards; r++)
        {
            A[r] = new byte[_dataShards];
            int rowIdx = decodeIndices[r];
            for (int c = 0; c < _dataShards; c++)
            {
                if (rowIdx < _dataShards)
                    A[r][c] = (byte)(rowIdx == c ? 1 : 0);
                else
                    A[r][c] = ExpTable[((rowIdx - _dataShards + 1) * c) % 255];
            }
        }

        // Invert A over GF(256)
        byte[][] invA = InvertMatrix(A);
        if (invA == null) return false;

        // Recover original data in parallel: data[c] = sum(invA[c][r] * shard[decodeIndices[r]])
        byte[][] data = new byte[_dataShards][];
        Parallel.For(0, _dataShards, c =>
        {
            data[c] = new byte[shardSize];
            for (int byteIdx = 0; byteIdx < shardSize; byteIdx++)
            {
                byte val = 0;
                for (int r = 0; r < _dataShards; r++)
                    val ^= GfMul(invA[c][r], shards[decodeIndices[r]][byteIdx]);
                data[c][byteIdx] = val;
            }
        });

        // Re-encode all erasures in parallel
        Parallel.ForEach(erasures, missingIdx =>
        {
            if (missingIdx < _dataShards)
            {
                shards[missingIdx] = data[missingIdx];
            }
            else
            {
                int p = missingIdx - _dataShards;
                byte[] recovered = new byte[shardSize];
                for (int byteIdx = 0; byteIdx < shardSize; byteIdx++)
                {
                    byte val = 0;
                    int k = 0;
                    for (; k + 4 <= _dataShards; k += 4)
                    {
                        byte c0 = _encodeMatrix[p, k]; if (c0 != 0) val ^= GfMul(c0, data[k][byteIdx]);
                        byte c1 = _encodeMatrix[p, k + 1]; if (c1 != 0) val ^= GfMul(c1, data[k + 1][byteIdx]);
                        byte c2 = _encodeMatrix[p, k + 2]; if (c2 != 0) val ^= GfMul(c2, data[k + 2][byteIdx]);
                        byte c3 = _encodeMatrix[p, k + 3]; if (c3 != 0) val ^= GfMul(c3, data[k + 3][byteIdx]);
                    }
                    for (; k < _dataShards; k++)
                    {
                        byte c = _encodeMatrix[p, k];
                        if (c != 0) val ^= GfMul(c, data[k][byteIdx]);
                    }
                    recovered[byteIdx] = val;
                }
                shards[missingIdx] = recovered;
            }
        });

        return true;
    }

    // ── GF(256) matrix inversion via Gaussian elimination ──

    private static byte[][]? InvertMatrix(byte[][] matrix)
    {
        int n = matrix.Length;
        byte[][] aug = new byte[n][];
        for (int i = 0; i < n; i++)
        {
            aug[i] = new byte[2 * n];
            for (int j = 0; j < n; j++)
                aug[i][j] = matrix[i][j];
            aug[i][n + i] = 1;
        }

        for (int col = 0; col < n; col++)
        {
            int pivot = -1;
            for (int row = col; row < n; row++)
            {
                if (aug[row][col] != 0) { pivot = row; break; }
            }
            if (pivot == -1) return null;

            (aug[col], aug[pivot]) = (aug[pivot], aug[col]);

            byte pivotVal = aug[col][col];
            for (int j = col; j < 2 * n; j++)
                aug[col][j] = GfDiv(aug[col][j], pivotVal);

            for (int row = 0; row < n; row++)
            {
                if (row == col) continue;
                byte factor = aug[row][col];
                if (factor == 0) continue;
                for (int j = col; j < 2 * n; j++)
                    aug[row][j] ^= GfMul(factor, aug[col][j]);
            }
        }

        byte[][] result = new byte[n][];
        for (int i = 0; i < n; i++)
        {
            result[i] = new byte[n];
            for (int j = 0; j < n; j++)
                result[i][j] = aug[i][n + j];
        }
        return result;
    }

    // ── GF(2^8) operations ──

    private static byte GfAdd(byte a, byte b) => (byte)(a ^ b);

    private static byte GfMul(byte a, byte b)
    {
        if (a == 0 || b == 0) return 0;
        return ExpTable[LogTable[a] + LogTable[b]];
    }

    private static byte GfMulVal(byte a, byte val)
    {
        byte result = 0;
        for (int i = 0; i < 8; i++)
        {
            if ((val & 1) != 0) result ^= a;
            byte high = (byte)(a & 0x80);
            a <<= 1;
            if (high != 0) a ^= 0x1D;
            val >>= 1;
        }
        return result;
    }

    private static byte GfDiv(byte a, byte b)
    {
        if (a == 0) return 0;
        if (b == 0) throw new DivideByZeroException();
        return ExpTable[LogTable[a] - LogTable[b] + 255];
    }
}
