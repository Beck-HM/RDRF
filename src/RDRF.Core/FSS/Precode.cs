using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

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

    public static List<int> Derive(byte[][] inter, bool[] known, int K, int blockSize)
    {
        var derived = new List<int>();
        int N = 2 * K;

        for (int i = 0; i < K - 1; i++)
        {
            int idx = K + i;
            if (!known[idx] && known[i] && known[i + 1])
            {
                inter[idx] ??= new byte[blockSize];
                XorAssign(inter[idx], inter[i], inter[i + 1], blockSize);
                known[idx] = true;
                derived.Add(idx);
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
                derived.Add(gIdx);
            }
        }

        return derived;
    }

    public static (int recovered, List<int> newSources) Unlock(byte[][] inter, bool[] known,
        bool[] srcKnown, byte[][] allBlocks, int K, int blockSize)
    {
        int recovered = 0;
        var newSources = new List<int>();

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
                newSources.Add(i + 1);
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
                newSources.Add(i);
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
                newSources.Add(missing);
            }
        }

        return (recovered, newSources);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void XorAssign(byte[] target, byte[] a, byte[] b, int len)
    {
        int i = 0;
        if (Avx2.IsSupported)
        {
            for (; i + 32 <= len; i += 32)
            {
                var va = Vector256.LoadUnsafe(ref a[i]);
                var vb = Vector256.LoadUnsafe(ref b[i]);
                Avx2.Xor(va, vb).CopyTo(target.AsSpan(i));
            }
        }
        for (; i + 16 <= len; i += 16)
        {
            var va = Vector128.LoadUnsafe(ref a[i]);
            var vb = Vector128.LoadUnsafe(ref b[i]);
            Vector128.Xor(va, vb).CopyTo(target.AsSpan(i));
        }
        for (; i < len; i++) target[i] = (byte)(a[i] ^ b[i]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void XorInto(byte[] target, byte[] src, int len)
    {
        int i = 0;
        if (Avx2.IsSupported)
        {
            for (; i + 32 <= len; i += 32)
            {
                var vt = Vector256.LoadUnsafe(ref target[i]);
                var vs = Vector256.LoadUnsafe(ref src[i]);
                Avx2.Xor(vt, vs).CopyTo(target.AsSpan(i));
            }
        }
        for (; i + 16 <= len; i += 16)
        {
            var vt = Vector128.LoadUnsafe(ref target[i]);
            var vs = Vector128.LoadUnsafe(ref src[i]);
            Vector128.Xor(vt, vs).CopyTo(target.AsSpan(i));
        }
        for (; i < len; i++) target[i] ^= src[i];
    }
}
