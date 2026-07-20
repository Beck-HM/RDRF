using System.Collections.Concurrent;
using System.Runtime.CompilerServices;

namespace RDRF.Core.Compression.Ckc;

internal sealed class CkcMatchFinder
{
    private const int H0Size = 1 << 14; // 16K  — 3-byte XOR, diverse
    private const int H1Size = 1 << 16; // 64K  — 4-byte CRC, main precision
    private const int H2Size = 1 << 18; // 256K — 5-byte CRC, ultra-precise
    private const int H3Size = 1 << 19; // 512K — 6-byte CRC, extreme
    private const int H4Size = 1 << 20; // 1M   — 7-byte CRC, very extreme
    private const int H5Size = 1 << 21; // 2M   — 8-byte CRC, maximal precision
    private const int MinMatchLen = 3;

    private byte[] _data;
    private int _dataLen;
    private int _dictSize;
    private int _cutValue;
    private int _hashLevels = 6; // 1..6; fast mode uses 3 (H0–H2 only)
    private int[] _h0, _n0, _h1, _n1, _h2, _n2, _h3, _n3, _h4, _n4, _h5, _n5;
    private readonly uint[] _crc;

    private static readonly ConcurrentBag<CkcMatchFinder> _pool = new();

    public CkcMatchFinder(byte[] data, int dictSize = 0, int cutValue = 32, int hashLevels = 6)
    {
        _crc = InitCrcTable();
        Alloc(data, dictSize, cutValue, hashLevels);
    }

    public void Reset(byte[] data, int dictSize, int cutValue, int hashLevels = 6)
    {
        int n = data.Length;
        _hashLevels = Math.Clamp(hashLevels, 1, 6);
        Ensure(ref _h0, H0Size); Ensure(ref _n0, n);
        Ensure(ref _h1, H1Size); Ensure(ref _n1, n);
        Ensure(ref _h2, H2Size); Ensure(ref _n2, n);
        if (_hashLevels >= 4) { Ensure(ref _h3, H3Size); Ensure(ref _n3, n); }
        if (_hashLevels >= 5) { Ensure(ref _h4, H4Size); Ensure(ref _n4, n); }
        if (_hashLevels >= 6) { Ensure(ref _h5, H5Size); Ensure(ref _n5, n); }

        _data = data; _dataLen = data.Length;
        _dictSize = dictSize > 0 ? dictSize : data.Length;
        _cutValue = cutValue;

        Fill(_h0, H0Size); Fill(_n0, n);
        Fill(_h1, H1Size); Fill(_n1, n);
        Fill(_h2, H2Size); Fill(_n2, n);
        if (_hashLevels >= 4) { Fill(_h3, H3Size); Fill(_n3, n); }
        if (_hashLevels >= 5) { Fill(_h4, H4Size); Fill(_n4, n); }
        if (_hashLevels >= 6) { Fill(_h5, H5Size); Fill(_n5, n); }
    }

    private static void Ensure(ref int[] arr, int size) { if (arr == null || arr.Length < size) arr = new int[size]; }
    private static void Fill(int[] arr, int n) { Array.Fill(arr, -1, 0, n); }

    private void Alloc(byte[] data, int dictSize, int cutValue, int hashLevels = 6)
    {
        _data = data; _dataLen = data.Length;
        _dictSize = dictSize > 0 ? dictSize : data.Length;
        _hashLevels = Math.Clamp(hashLevels, 1, 6);
        _h0 = new int[H0Size]; _n0 = new int[data.Length];
        _h1 = new int[H1Size]; _n1 = new int[data.Length];
        _h2 = new int[H2Size]; _n2 = new int[data.Length];
        if (_hashLevels >= 4) { _h3 = new int[H3Size]; _n3 = new int[data.Length]; }
        if (_hashLevels >= 5) { _h4 = new int[H4Size]; _n4 = new int[data.Length]; }
        if (_hashLevels >= 6) { _h5 = new int[H5Size]; _n5 = new int[data.Length]; }
        _cutValue = cutValue;
        Fill(_h0, H0Size); Fill(_n0, data.Length);
        Fill(_h1, H1Size); Fill(_n1, data.Length);
        Fill(_h2, H2Size); Fill(_n2, data.Length);
        if (_hashLevels >= 4) { Fill(_h3, H3Size); Fill(_n3, data.Length); }
        if (_hashLevels >= 5) { Fill(_h4, H4Size); Fill(_n4, data.Length); }
        if (_hashLevels >= 6) { Fill(_h5, H5Size); Fill(_n5, data.Length); }
    }

    public static CkcMatchFinder Rent(byte[] data, int dictSize, int cutValue, int hashLevels = 6)
    {
        if (_pool.TryTake(out var mf)) { mf.Reset(data, dictSize, cutValue, hashLevels); return mf; }
        return new CkcMatchFinder(data, dictSize, cutValue, hashLevels);
    }
    public static void Return(CkcMatchFinder mf) => _pool.Add(mf);

    private static uint[] InitCrcTable()
    {
        var t = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint r = i;
            for (int j = 0; j < 8; j++) r = (r >> 1) ^ (0xEDB88320 & (0 - (r & 1)));
            t[i] = r;
        }
        return t;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)] private static int H3b(int pos, byte[] d) => (d[pos] ^ (d[pos+1] << 5) ^ (d[pos+2] << 11)) & (H0Size - 1);
    [MethodImpl(MethodImplOptions.AggressiveInlining)] private uint H4(int p) { uint t = _crc[_data[p]] ^ _data[p+1]; t ^= (uint)_data[p+2] << 8; t ^= _crc[_data[p+3]] << 5; return t & (H1Size - 1); }
    [MethodImpl(MethodImplOptions.AggressiveInlining)] private uint H5(int p) { uint h = _crc[_data[p]] ^ _data[p+1]; h ^= (uint)_data[p+2] << 8; h ^= _crc[_data[p+3]] << 5; h ^= _crc[_data[p+4]] << 10; return h & (H2Size - 1); }
    [MethodImpl(MethodImplOptions.AggressiveInlining)] private uint H6(int p) { return (H5(p) | (_crc[_data[p+5]] << 15)) & (H3Size - 1); }
    [MethodImpl(MethodImplOptions.AggressiveInlining)] private uint H7(int p) { uint h = H5(p); h ^= _crc[_data[p+5]] << 15; h ^= _crc[_data[p+6]] << 20; return h & (H4Size - 1); }
    [MethodImpl(MethodImplOptions.AggressiveInlining)] private uint H8(int p) { uint h = H5(p); h ^= _crc[_data[p+5]] << 15; h ^= _crc[_data[p+6]] << 20; h ^= _crc[_data[p+7]] << 25; return h & (H5Size - 1); }

    private int Try(int[] head, int[] next, uint hv, int pos, int limit, int cd, ref int maxLen, ref int maxDist)
    {
        int cm = head[hv];
        while (cm >= 0 && cd-- > 0)
        {
            int delta = pos - cm;
            if (delta <= 0 || delta > _dictSize) { cm = next[cm]; continue; }
            if (_data[cm] == _data[pos] && _data[cm+1] == _data[pos+1] && _data[cm+2] == _data[pos+2])
            {
                int len = 3;
                while (len < limit && _data[cm + len] == _data[pos + len]) len++;
                if (len > maxLen) { maxLen = len; maxDist = delta; if (len >= limit) return -1; }
            }
            cm = next[cm];
        }
        return 0;
    }

    public (int len, int dist) FindLongestMatch(int pos, int lenLimit)
    {
        if (pos + 8 > _dataLen || pos + MinMatchLen > _dataLen) return (0, 0);

        uint hv0 = (uint)H3b(pos, _data);
        uint hv1 = H4(pos), hv2 = H5(pos);

        _n0[pos] = _h0[hv0]; _h0[hv0] = pos;
        _n1[pos] = _h1[hv1]; _h1[hv1] = pos;
        _n2[pos] = _h2[hv2]; _h2[hv2] = pos;
        if (_hashLevels >= 4) { uint hv3 = H6(pos); _n3[pos] = _h3[hv3]; _h3[hv3] = pos; }
        if (_hashLevels >= 5) { uint hv4 = H7(pos); _n4[pos] = _h4[hv4]; _h4[hv4] = pos; }
        if (_hashLevels >= 6) { uint hv5 = H8(pos); _n5[pos] = _h5[hv5]; _h5[hv5] = pos; }

        int maxLen = MinMatchLen - 1, maxDist = 0;
        int limit = Math.Min(lenLimit, _dataLen - pos);
        int chain = Math.Min(_cutValue, _hashLevels <= 3 ? 48 : 160);

        // H1 (64K, 4-byte): main precision
        if (Try(_h1, _n1, hv1, pos, limit, chain, ref maxLen, ref maxDist) < 0) goto done;

        // H0 (16K, 3-byte)
        if (maxLen < 12) Try(_h0, _n0, hv0, pos, limit, Math.Min(chain, 64), ref maxLen, ref maxDist);

        // H2 (256K, 5-byte)
        if (maxLen < 8) Try(_h2, _n2, hv2, pos, limit, Math.Min(chain, 64), ref maxLen, ref maxDist);

        if (_hashLevels >= 4 && maxLen < 6)
            Try(_h3, _n3, H6(pos), pos, limit, 64, ref maxLen, ref maxDist);
        if (_hashLevels >= 5 && maxLen < 5)
            Try(_h4, _n4, H7(pos), pos, limit, 80, ref maxLen, ref maxDist);
        if (_hashLevels >= 6 && maxLen < 4)
            Try(_h5, _n5, H8(pos), pos, limit, 80, ref maxLen, ref maxDist);

        done:
        return maxLen >= MinMatchLen ? (maxLen, maxDist) : (0, 0);
    }

    public bool HeadHasEntry(int pos)
    {
        if (pos + 4 > _dataLen) return false;
        return _h1[H4(pos)] >= 0;
    }
}
