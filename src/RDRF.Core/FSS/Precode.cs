namespace RDRF.Core.FSS;

public static class Precode
{
    public static byte[][] Encode(byte[][] source, int blockSize)
    {
        int K = source.Length;
        int N = 2 * K;
        var inter = new byte[N][];

        for (int i = 0; i < K; i++)
        {
            inter[i] = new byte[blockSize];
            Buffer.BlockCopy(source[i], 0, inter[i], 0, blockSize);
        }

        for (int i = 0; i < K - 1; i++)
        {
            inter[K + i] = new byte[blockSize];
            XorAssign(inter[K + i], inter[i], inter[i + 1], blockSize);
        }

        inter[N - 1] = new byte[blockSize];
        for (int i = 0; i < K; i++)
            XorInto(inter[N - 1], inter[i], blockSize);

        return inter;
    }

    public static void Derive(byte[][] inter, bool[] known, int K, int blockSize)
    {
        int N = 2 * K;

        for (int i = 0; i < K - 1; i++)
        {
            int idx = K + i;
            if (!known[idx] && known[i] && known[i + 1])
            {
                inter[idx] ??= new byte[blockSize];
                XorAssign(inter[idx], inter[i], inter[i + 1], blockSize);
                known[idx] = true;
            }
        }

        int gIdx = N - 1;
        if (!known[gIdx])
        {
            bool all = true;
            for (int i = 0; i < K; i++) { if (!known[i]) { all = false; break; } }
            if (all)
            {
                inter[gIdx] ??= new byte[blockSize];
                Array.Clear(inter[gIdx], 0, blockSize);
                for (int i = 0; i < K; i++)
                    XorInto(inter[gIdx], inter[i], blockSize);
                known[gIdx] = true;
            }
        }
    }

    public static int Unlock(byte[][] inter, bool[] known,
        bool[] srcKnown, byte[][] allBlocks, int K, int blockSize)
    {
        int recovered = 0;

        for (int i = 0; i < K - 1; i++)
        {
            int qi = K + i;
            if (!srcKnown[i + 1] && srcKnown[i] && known[qi])
            {
                inter[i + 1] ??= new byte[blockSize];
                XorAssign(inter[i + 1], inter[i], inter[qi], blockSize);
                known[i + 1] = true;
                srcKnown[i + 1] = true;
                Buffer.BlockCopy(inter[i + 1], 0, allBlocks[i + 1], 0, blockSize);
                recovered++;
            }
        }

        for (int i = K - 2; i >= 0; i--)
        {
            int qi = K + i;
            if (!srcKnown[i] && srcKnown[i + 1] && known[qi])
            {
                inter[i] ??= new byte[blockSize];
                XorAssign(inter[i], inter[i + 1], inter[qi], blockSize);
                known[i] = true;
                srcKnown[i] = true;
                Buffer.BlockCopy(inter[i], 0, allBlocks[i], 0, blockSize);
                recovered++;
            }
        }

        int gIdx = 2 * K - 1;
        if (known[gIdx])
        {
            int missing = -1;
            int count = 0;
            for (int i = 0; i < K; i++)
            {
                if (srcKnown[i]) count++;
                else missing = i;
            }
            if (count == K - 1 && missing >= 0)
            {
                inter[missing] ??= new byte[blockSize];
                Array.Clear(inter[missing], 0, blockSize);
                Buffer.BlockCopy(inter[gIdx], 0, inter[missing], 0, blockSize);
                for (int i = 0; i < K; i++)
                {
                    if (i != missing)
                        XorInto(inter[missing], inter[i], blockSize);
                }
                known[missing] = true;
                srcKnown[missing] = true;
                Buffer.BlockCopy(inter[missing], 0, allBlocks[missing], 0, blockSize);
                recovered++;
            }
        }

        return recovered;
    }

    internal static void XorAssign(byte[] target, byte[] a, byte[] b, int len)
    {
        for (int i = 0; i < len; i++) target[i] = (byte)(a[i] ^ b[i]);
    }

    internal static void XorInto(byte[] target, byte[] src, int len)
    {
        for (int i = 0; i < len; i++) target[i] ^= src[i];
    }
}

