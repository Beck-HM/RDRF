namespace RDRF.Core.FSS;

public class ReedSolomon
{
    private readonly int _dataShards;
    private readonly int _parityShards;
    private readonly int _totalShards;

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
    }

    // ── Encode ──

    public byte[][] Encode(byte[][] shards)
    {
        int shardSize = shards[0].Length;
        for (int i = _dataShards; i < _totalShards; i++)
        {
            shards[i] = new byte[shardSize];
            for (int j = 0; j < shardSize; j++)
            {
                byte val = 0;
                for (int k = 0; k < _dataShards; k++)
                    val ^= GfMul(ExpTable[(i - _dataShards + 1) * k], shards[k][j]);
                shards[i][j] = val;
            }
        }
        return shards;
    }

    // ── Decode with erasures ──

    public bool Decode(byte[][] shards, List<int> erasures)
    {
        int shardSize = shards[0].Length;
        int presentCount = _totalShards - erasures.Count;

        if (presentCount < _dataShards) return false;

        var presentIndices = new List<int>();
        for (int i = 0; i < _totalShards; i++)
            if (!erasures.Contains(i)) presentIndices.Add(i);

        var decodeIndices = presentIndices.Take(_dataShards).ToList();
        var lagrangeWeights = new Dictionary<int, byte[]>();

        foreach (int missingIdx in erasures)
        {
            byte x = (byte)missingIdx;
            byte[] weights = new byte[_dataShards];
            for (int i = 0; i < _dataShards; i++)
            {
                byte num = 1, den = 1;
                for (int j = 0; j < _dataShards; j++)
                {
                    if (i == j) continue;
                    num = GfMul(num, GfAdd(x, (byte)decodeIndices[j]));
                    den = GfMul(den, GfAdd((byte)decodeIndices[i], (byte)decodeIndices[j]));
                }
                weights[i] = GfDiv(num, den);
            }
            lagrangeWeights[missingIdx] = weights;
        }

        for (int byteIdx = 0; byteIdx < shardSize; byteIdx++)
        {
            foreach (int missingIdx in erasures)
            {
                byte[] weights = lagrangeWeights[missingIdx];
                byte result = 0;
                for (int i = 0; i < _dataShards; i++)
                    result ^= GfMul(shards[decodeIndices[i]][byteIdx], weights[i]);
                shards[missingIdx][byteIdx] = result;
            }
        }
        return true;
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
        return ExpTable[(LogTable[a] - LogTable[b] + 255) % 255];
    }
}
