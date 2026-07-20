using System.Runtime.CompilerServices;

namespace RDRF.Core.Compression.Ckc;

internal static class CkcBwt
{
    public static void BuildSA(byte[] data, int[] sa, int[] rank, int[] lcp)
    {
        int n = data.Length;
        if (n <= 1) { if (n == 1) { sa[0] = 0; rank[0] = 0; } return; }

        // Step 1: counting sort by first byte
        int[] cnt = new int[257];
        for (int i = 0; i < n; i++) cnt[data[i] + 1]++;
        for (int i = 1; i < 257; i++) cnt[i] += cnt[i - 1];
        for (int i = 0; i < n; i++) sa[cnt[data[i]]++] = i;

        int[] key = new int[n], tmp = new int[n];
        int maxRank = 0;
        key[sa[0]] = 0;
        for (int i = 1; i < n; i++)
        {
            key[sa[i]] = key[sa[i - 1]];
            if (data[sa[i]] != data[sa[i - 1]]) { key[sa[i]]++; maxRank = key[sa[i]]; }
        }

        int[] bs = new int[n + 2];
        for (int k = 1; k < n; k <<= 1)
        {
            int bucketSize = maxRank + 2;
            Array.Clear(bs, 0, bucketSize);
            for (int i = 0; i < n; i++) bs[sa[i] + k < n ? key[sa[i] + k] + 1 : 0]++;
            for (int i = 1; i < bucketSize; i++) bs[i] += bs[i - 1];
            for (int i = n - 1; i >= 0; i--) tmp[--bs[sa[i] + k < n ? key[sa[i] + k] + 1 : 0]] = sa[i];

            Array.Clear(bs, 0, bucketSize);
            for (int i = 0; i < n; i++) bs[key[tmp[i]] + 1]++;
            for (int i = 1; i < bucketSize; i++) bs[i] += bs[i - 1];
            for (int i = n - 1; i >= 0; i--) sa[--bs[key[tmp[i]] + 1]] = tmp[i];

            tmp[sa[0]] = 0;
            int newMax = 0;
            for (int i = 1; i < n; i++)
            {
                int prev = sa[i - 1], cur = sa[i];
                bool same = key[prev] == key[cur] && SecondKey(prev, k, key, n) == SecondKey(cur, k, key, n);
                tmp[cur] = tmp[prev] + (same ? 0 : 1);
                if (!same) newMax++;
            }
            int[] sw = key; key = tmp; tmp = sw;
            maxRank = newMax;
            if (maxRank == n - 1) break;
        }

        for (int i = 0; i < n; i++) rank[sa[i]] = i;

        int h = 0;
        for (int i = 0; i < n; i++)
        {
            if (rank[i] == 0) continue;
            int j = sa[rank[i] - 1];
            while (i + h < n && j + h < n && data[i + h] == data[j + h]) h++;
            lcp[rank[i]] = h;
            if (h > 0) h--;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int SecondKey(int pos, int k, int[] key, int n) => pos + k < n ? key[pos + k] : -1;

    public static byte[] ForwardMTF(byte[] data)
    {
        var mtf = new byte[data.Length];
        var list = new byte[256];
        for (int i = 0; i < 256; i++) list[i] = (byte)i;
        for (int i = 0; i < data.Length; i++)
        {
            byte b = data[i];
            int pos = 0;
            while (list[pos] != b) pos++;
            mtf[i] = (byte)pos;
            for (int j = pos; j > 0; j--) list[j] = list[j - 1];
            list[0] = b;
        }
        return mtf;
    }

    public static byte[] InverseMTF(byte[] mtf)
    {
        var data = new byte[mtf.Length];
        var list = new byte[256];
        for (int i = 0; i < 256; i++) list[i] = (byte)i;
        for (int i = 0; i < mtf.Length; i++)
        {
            int pos = mtf[i];
            byte b = list[pos];
            data[i] = b;
            for (int j = pos; j > 0; j--) list[j] = list[j - 1];
            list[0] = b;
        }
        return data;
    }

    public static (byte[] bwt, int primary) Forward(byte[] data)
    {
        int n = data.Length;
        var sa = new int[n];
        var rank = new int[n];
        var lcp = new int[n];
        BuildSA(data, sa, rank, lcp);

        var bwt = new byte[n];
        int primary = 0;
        for (int i = 0; i < n; i++)
        {
            if (sa[i] == 0) { bwt[i] = data[n - 1]; primary = i; }
            else bwt[i] = data[sa[i] - 1];
        }
        return (bwt, primary);
    }

    public static byte[] Inverse(byte[] bwt, int primary)
    {
        int n = bwt.Length;
        // Stable counting sort of BWT positions by byte value
        var count = new int[256];
        for (int i = 0; i < n; i++) count[bwt[i] & 0xFF]++;
        for (int i = 1; i < 256; i++) count[i] += count[i - 1];

        // tt[j] = BWT position whose byte comes at sorted position j
        var tt = new int[n];
        for (int i = n - 1; i >= 0; i--) tt[--count[bwt[i] & 0xFF]] = i;

        // inv[BWT_position] = sorted rank
        var inv = new int[n];
        for (int j = 0; j < n; j++) inv[tt[j]] = j;

        // Walk from primary through inv: first advance n-1 steps to find correct start
        var result = new byte[n];
        int row = primary;
        for (int i = 0; i < n - 1; i++) row = inv[row];
        for (int i = 0; i < n; i++)
        {
            result[i] = bwt[row];
            row = inv[row];
        }
        return result;
    }
}
