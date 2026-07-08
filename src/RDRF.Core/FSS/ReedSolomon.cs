using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace RDRF.Core.FSS;

/// <summary>
/// Vandermonde-based Reed-Solomon erasure coding over GF(256). Encode/decode/matrix operations.
/// </summary>

public class ReedSolomon
{
    private readonly int _dataShards;
    private readonly int _parityShards;
    private readonly int _totalShards;
    private readonly byte[,] _encodeMatrix;
    private readonly byte[][] _mulTable;

    private static readonly byte[] ExpTable = new byte[512];
    private static readonly byte[] LogTable = new byte[256];
    private static readonly ConcurrentDictionary<string, byte[][]> _invCache = new();

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

        _encodeMatrix = new byte[parityShards, dataShards];
        for (int p = 0; p < parityShards; p++)
            for (int k = 0; k < dataShards; k++)
                _encodeMatrix[p, k] = ExpTable[((p + 1) * k) % 255];

        _mulTable = new byte[256][];
        _mulTable[0] = new byte[256];
        for (int c = 1; c < 256; c++)
        {
            var row = new byte[256];
            _mulTable[c] = row;
            int logC = LogTable[c];
            for (int a = 1; a < 256; a++)
                row[a] = ExpTable[LogTable[a] + logC];
        }
    }

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
                    val ^= _mulTable[_encodeMatrix[p, k]][shards[k][j]];
                    val ^= _mulTable[_encodeMatrix[p, k + 1]][shards[k + 1][j]];
                    val ^= _mulTable[_encodeMatrix[p, k + 2]][shards[k + 2][j]];
                    val ^= _mulTable[_encodeMatrix[p, k + 3]][shards[k + 3][j]];
                }
                for (; k < _dataShards; k++)
                    val ^= _mulTable[_encodeMatrix[p, k]][shards[k][j]];
                parity[j] = val;
            }
            shards[i] = parity;
        });
        return shards;
    }

    public bool Decode(byte[][] shards, List<int> erasures)
    {
        int shardSize = shards[0].Length;
        int presentCount = _totalShards - erasures.Count;
        if (presentCount < _dataShards) return false;

        var erased = new bool[_totalShards];
        foreach (var e in erasures) erased[e] = true;
        var presentIndices = new List<int>();
        for (int i = 0; i < _totalShards; i++)
            if (!erased[i]) presentIndices.Add(i);

        var decodeIndices = presentIndices.Take(_dataShards).ToList();

        bool isIdentity = true;
        for (int i = 0; i < _dataShards && isIdentity; i++)
            if (decodeIndices[i] != i) isIdentity = false;

        byte[][] data;

        if (isIdentity)
        {
            data = new byte[_dataShards][];
            for (int i = 0; i < _dataShards; i++)
            {
                data[i] = new byte[shardSize];
                Buffer.BlockCopy(shards[i], 0, data[i], 0, shardSize);
            }
        }
        else
        {
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

            var sb = new System.Text.StringBuilder();
            sb.Append(_dataShards);
            for (int i = 0; i < _dataShards; i++)
                sb.Append(',').Append(decodeIndices[i]);
            string invKey = sb.ToString();

            if (!_invCache.TryGetValue(invKey, out var invA))
            {
                invA = InvertMatrix(A);
                if (invA != null) _invCache[invKey] = invA;
            }
            if (invA == null) return false;

            data = new byte[_dataShards][];
            Parallel.For(0, _dataShards, c =>
            {
                data[c] = new byte[shardSize];
                for (int byteIdx = 0; byteIdx < shardSize; byteIdx++)
                {
                    byte val = 0;
                    for (int r = 0; r < _dataShards; r++)
                        val ^= _mulTable[invA[c][r]][shards[decodeIndices[r]][byteIdx]];
                    data[c][byteIdx] = val;
                }
            });
        }

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
                        val ^= _mulTable[_encodeMatrix[p, k]][data[k][byteIdx]];
                        val ^= _mulTable[_encodeMatrix[p, k + 1]][data[k + 1][byteIdx]];
                        val ^= _mulTable[_encodeMatrix[p, k + 2]][data[k + 2][byteIdx]];
                        val ^= _mulTable[_encodeMatrix[p, k + 3]][data[k + 3][byteIdx]];
                    }
                    for (; k < _dataShards; k++)
                        val ^= _mulTable[_encodeMatrix[p, k]][data[k][byteIdx]];
                    recovered[byteIdx] = val;
                }
                shards[missingIdx] = recovered;
            }
        });

        return true;
    }

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
                if (aug[row][col] != 0) { pivot = row; break; }
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

    private static byte GfAdd(byte a, byte b) => (byte)(a ^ b);
    private static byte GfMul(byte a, byte b)
    {
        if (a == 0 || b == 0) return 0;
        return ExpTable[LogTable[a] + LogTable[b]];
    }
    private static readonly byte[][] _mulTableStatic = BuildMulTable();

    private static byte[][] BuildMulTable()
    {
        var tbl = new byte[256][];
        tbl[0] = new byte[256];
        for (int c = 1; c < 256; c++)
        {
            var row = new byte[256];
            tbl[c] = row;
            int logC = LogTable[c];
            for (int a = 1; a < 256; a++)
                row[a] = ExpTable[LogTable[a] + logC];
        }
        return tbl;
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

