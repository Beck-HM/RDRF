using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace RDRF.Core.FSS;

/// <summary>
/// Precoding for LT fountain codes: interleaved XOR chain + global XOR with SIMD optimization.
/// </summary>

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
    private static void XorAssignSpan(Span<byte> target, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        int len = target.Length;
        ref byte tRef = ref MemoryMarshal.GetReference(target);
        ref byte aRef = ref MemoryMarshal.GetReference(a);
        ref byte bRef = ref MemoryMarshal.GetReference(b);
        int i = 0;
        if (Avx2.IsSupported)
        {
            for (; i + 32 <= len; i += 32)
            {
                var va = Vector256.LoadUnsafe(ref aRef, (nuint)i);
                var vb = Vector256.LoadUnsafe(ref bRef, (nuint)i);
                Avx2.Xor(va, vb).CopyTo(target.Slice(i));
            }
        }
        for (; i + 16 <= len; i += 16)
        {
            var va = Vector128.LoadUnsafe(ref aRef, (nuint)i);
            var vb = Vector128.LoadUnsafe(ref bRef, (nuint)i);
            Vector128.Xor(va, vb).CopyTo(target.Slice(i));
        }
        for (; i < len; i++) target[i] = (byte)(a[i] ^ b[i]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void XorAssign(byte[] target, byte[] a, byte[] b, int len)
        => XorAssignSpan(target.AsSpan(0, len), a.AsSpan(0, len), b.AsSpan(0, len));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void XorIntoSpan(Span<byte> target, ReadOnlySpan<byte> src)
    {
        int len = target.Length;
        ref byte tRef = ref MemoryMarshal.GetReference(target);
        ref byte sRef = ref MemoryMarshal.GetReference(src);
        int i = 0;
        if (Avx2.IsSupported)
        {
            for (; i + 32 <= len; i += 32)
            {
                var vt = Vector256.LoadUnsafe(ref tRef, (nuint)i);
                var vs = Vector256.LoadUnsafe(ref sRef, (nuint)i);
                Avx2.Xor(vt, vs).CopyTo(target.Slice(i));
            }
        }
        for (; i + 16 <= len; i += 16)
        {
            var vt = Vector128.LoadUnsafe(ref tRef, (nuint)i);
            var vs = Vector128.LoadUnsafe(ref sRef, (nuint)i);
            Vector128.Xor(vt, vs).CopyTo(target.Slice(i));
        }
        for (; i < len; i++) target[i] ^= src[i];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void XorInto(byte[] target, byte[] src, int len)
        => XorIntoSpan(target.AsSpan(0, len), src.AsSpan(0, len));

    public static List<int> Derive(Span<byte> interBuf, bool[] known, int K, int blockSize)
    {
        var derived = new List<int>();
        int N = 2 * K;

        for (int i = 0; i < K - 1; i++)
        {
            int idx = K + i;
            if (!known[idx] && known[i] && known[i + 1])
            {
                XorAssignSpan(
                    interBuf.Slice(idx * blockSize, blockSize),
                    interBuf.Slice(i * blockSize, blockSize),
                    interBuf.Slice((i + 1) * blockSize, blockSize));
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
                var target = interBuf.Slice(gIdx * blockSize, blockSize);
                target.Clear();
                for (int i = 0; i < K; i++)
                    XorIntoSpan(target, interBuf.Slice(i * blockSize, blockSize));
                known[gIdx] = true;
                derived.Add(gIdx);
            }
        }

        return derived;
    }

    public static (int recovered, List<int> newSources) Unlock(
        Span<byte> interBuf, bool[] known,
        bool[] srcKnown, byte[][] allBlocks, int K, int blockSize,
        int knownSourceCount)
    {
        int recovered = 0;
        var newSources = new List<int>();

        for (int i = 0; i < K - 1; i++)
        {
            int qi = K + i;
            if (!srcKnown[i + 1] && srcKnown[i] && known[qi])
            {
                XorAssignSpan(
                    interBuf.Slice((i + 1) * blockSize, blockSize),
                    interBuf.Slice(i * blockSize, blockSize),
                    interBuf.Slice(qi * blockSize, blockSize));
                known[i + 1] = true;
                srcKnown[i + 1] = true;
                interBuf.Slice((i + 1) * blockSize, blockSize).CopyTo(allBlocks[i + 1]);
                recovered++;
                newSources.Add(i + 1);
            }
        }

        for (int i = K - 2; i >= 0; i--)
        {
            int qi = K + i;
            if (!srcKnown[i] && srcKnown[i + 1] && known[qi])
            {
                XorAssignSpan(
                    interBuf.Slice(i * blockSize, blockSize),
                    interBuf.Slice((i + 1) * blockSize, blockSize),
                    interBuf.Slice(qi * blockSize, blockSize));
                known[i] = true;
                srcKnown[i] = true;
                interBuf.Slice(i * blockSize, blockSize).CopyTo(allBlocks[i]);
                recovered++;
                newSources.Add(i);
            }
        }

        int gIdx = 2 * K - 1;
        if (known[gIdx] && knownSourceCount == K - 1)
        {
            int missing = -1;
            for (int i = 0; i < K; i++)
                if (!srcKnown[i]) { missing = i; break; }
            if (missing >= 0)
            {
                var target = interBuf.Slice(missing * blockSize, blockSize);
                interBuf.Slice(gIdx * blockSize, blockSize).CopyTo(target);
                for (int i = 0; i < K; i++)
                {
                    if (i != missing)
                        XorIntoSpan(target, interBuf.Slice(i * blockSize, blockSize));
                }
                known[missing] = true;
                srcKnown[missing] = true;
                target.CopyTo(allBlocks[missing]);
                recovered++;
                newSources.Add(missing);
            }
        }

        return (recovered, newSources);
    }

    public static List<int> DeriveIncremental(Span<byte> interBuf, bool[] known, int K, int blockSize,
        List<int> changedSrcIndices, int knownSourceCount)
    {
        var derived = new List<int>();
        int N = 2 * K;

        foreach (int nk in changedSrcIndices)
        {
            if (nk < K - 1)
            {
                int idx = K + nk;
                if (!known[idx] && known[nk] && known[nk + 1])
                {
                    XorAssignSpan(
                        interBuf.Slice(idx * blockSize, blockSize),
                        interBuf.Slice(nk * blockSize, blockSize),
                        interBuf.Slice((nk + 1) * blockSize, blockSize));
                    known[idx] = true;
                    derived.Add(idx);
                }
            }
            if (nk > 0)
            {
                int idx = K + nk - 1;
                if (!known[idx] && known[nk - 1] && known[nk])
                {
                    XorAssignSpan(
                        interBuf.Slice(idx * blockSize, blockSize),
                        interBuf.Slice((nk - 1) * blockSize, blockSize),
                        interBuf.Slice(nk * blockSize, blockSize));
                    known[idx] = true;
                    derived.Add(idx);
                }
            }
        }

        int gIdx = N - 1;
        if (!known[gIdx] && knownSourceCount == K)
        {
            var target = interBuf.Slice(gIdx * blockSize, blockSize);
            target.Clear();
            for (int i = 0; i < K; i++)
                XorIntoSpan(target, interBuf.Slice(i * blockSize, blockSize));
            known[gIdx] = true;
            derived.Add(gIdx);
        }

        return derived;
    }
}

