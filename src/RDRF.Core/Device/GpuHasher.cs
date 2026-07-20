using ILGPU;
using ILGPU.Runtime;

namespace RDRF.Core.Device;

public static partial class GpuHasher
{
    public static byte[] HashSHA256(List<byte[]> fragments)
    {
        if (fragments.Count == 0) return [];
        int n = fragments.Count;
        var res = new byte[n * 32];
        for (int i = 0; i < n; i++)
        {
            var hash = System.Security.Cryptography.SHA256.HashData(fragments[i]);
            hash.CopyTo(res.AsSpan(i * 32, 32));
        }
        return res;
    }

    public static List<byte[]> HashXXH128(List<byte[]> fragments)
    {
        if (fragments.Count == 0) return [];
        if (!GpuContext.IsAvailable)
            return CpuHashXXH128(fragments);

        var acc = GpuContext.Accelerator;
        int n = fragments.Count;
        var (flat, offs, lens) = Pack(fragments);
        var res = new byte[n * 16];
        using var db = acc.Allocate1D<byte>(flat.Length);
        using var ob = acc.Allocate1D<int>(n);
        using var lb = acc.Allocate1D<int>(n);
        using var rb = acc.Allocate1D<byte>(n * 16);
        db.CopyFromCPU(flat); ob.CopyFromCPU(offs); lb.CopyFromCPU(lens);
        var k = acc.LoadAutoGroupedStreamKernel<Index1D, ArrayView<byte>, ArrayView<int>, ArrayView<int>, ArrayView<byte>>(XXH128Gpu);
        k(n, db.View, ob.View, lb.View, rb.View);
        acc.Synchronize();
        rb.CopyToCPU(res);
        var list = new List<byte[]>(n);
        for (int i = 0; i < n; i++) { var h = new byte[16]; Array.Copy(res, i * 16, h, 0, 16); list.Add(h); }
        return list;
    }

    private static List<byte[]> CpuHashXXH128(List<byte[]> fragments)
    {
        var list = new List<byte[]>(fragments.Count);
        foreach (var f in fragments)
            list.Add(System.IO.Hashing.XxHash128.Hash(f.AsSpan()));
        return list;
    }

    private static (byte[], int[], int[]) Pack(List<byte[]> frags)
    {
        int n = frags.Count, total = 0;
        foreach (var f in frags) total += f.Length;
        var flat = new byte[total];
        var offs = new int[n];
        var lens = new int[n];
        int p = 0;
        for (int i = 0; i < n; i++) { offs[i] = p; lens[i] = frags[i].Length; Array.Copy(frags[i], 0, flat, p, frags[i].Length); p += frags[i].Length; }
        return (flat, offs, lens);
    }

    internal static void XXH128Gpu(Index1D idx, ArrayView<byte> data, ArrayView<int> offs, ArrayView<int> lens, ArrayView<byte> output)
    {
        int i = idx.X, start = offs[i], len = lens[i], ob = i * 16;
        const ulong P1 = 0x9E3779B185EBCA87, P2 = 0xC2B2AE3D27D4EB4F, P3 = 0x165667B19E3779F9;
        const ulong P4 = 0x85EBCA77C2B2AE63, P5 = 0x27D4EB2F165667C5;
        ulong a1 = 0x60EA27AEAD9985D6, a2 = P2, a3 = 0, a4 = 0x61846A3E79C65D79;
        int p = 0;
        if (len >= 32) { int lim = len - 32; for (; p <= lim; p += 32) { a1 = XXHRound(a1, RU64(data, start + p)); a2 = XXHRound(a2, RU64(data, start + p + 8)); a3 = XXHRound(a3, RU64(data, start + p + 16)); a4 = XXHRound(a4, RU64(data, start + p + 24)); } a1 = ROL64(a1, 1); a2 = ROL64(a2, 7); a3 = ROL64(a3, 12); a4 = ROL64(a4, 18); a1 = XXHMerge(a1, a2); a3 = XXHMerge(a3, a4); a1 = XXHMerge(a1, a3); } else a1 = P5;
        a1 += (ulong)len;
        for (; p + 8 <= len; p += 8) { a1 ^= XXHRound(0, RU64(data, start + p)); a1 = ROL64(a1, 27) * P1 + P4; }
        for (; p + 4 <= len; p += 4) { a1 ^= RU32(data, start + p) * P1; a1 = ROL64(a1, 23) * P2 + P3; }
        for (; p < len; p++) { a1 ^= data[start + p] * P5; a1 = ROL64(a1, 11) * P1; }
        a1 ^= a1 >> 33; a1 *= P2; a1 ^= a1 >> 29; a1 *= P3; a1 ^= a1 >> 32;
        W64(output, ob, a1); W64(output, ob + 8, a1 + 0x61846A3E79C65D79);
    }

    private static uint ROR(uint v, int n) => (v >> n) | (v << (32 - n));
    private static ulong ROL64(ulong v, int n) => (v << n) | (v >> (64 - n));
    private static ulong XXHRound(ulong a, ulong v) { a += v * P2; a = ROL64(a, 31); a *= P1; return a; }
    private const ulong P1 = 0x9E3779B185EBCA87, P2 = 0xC2B2AE3D27D4EB4F;
    private static ulong XXHMerge(ulong a, ulong b) { a ^= XXHRound(0, b); a *= P1; return a + P2; }
    private static ulong RU64(ArrayView<byte> d, int p) => (ulong)d[p] | ((ulong)d[p + 1] << 8) | ((ulong)d[p + 2] << 16) | ((ulong)d[p + 3] << 24) | ((ulong)d[p + 4] << 32) | ((ulong)d[p + 5] << 40) | ((ulong)d[p + 6] << 48) | ((ulong)d[p + 7] << 56);
    private static ulong RU32(ArrayView<byte> d, int p) => (uint)(d[p] | (d[p + 1] << 8) | (d[p + 2] << 16) | (d[p + 3] << 24));
    private static void W64(ArrayView<byte> o, int p, ulong v) { o[p] = (byte)v; o[p + 1] = (byte)(v >> 8); o[p + 2] = (byte)(v >> 16); o[p + 3] = (byte)(v >> 24); o[p + 4] = (byte)(v >> 32); o[p + 5] = (byte)(v >> 40); o[p + 6] = (byte)(v >> 48); o[p + 7] = (byte)(v >> 56); }
}
