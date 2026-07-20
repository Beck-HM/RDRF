using System.Collections.Concurrent;
using System.Runtime.CompilerServices;

namespace RDRF.Core.Compression.Ckc;

internal static class CkcDictionary
{
    internal static byte[] _trained;
    internal static readonly object _lock = new();

    internal static byte[] Get()
    {
        if (_trained != null) return _trained;
        lock (_lock) { if (_trained != null) return _trained; _trained = DefaultDict(); }
        return _trained;
    }

    public static byte[] Train(byte[][] samples, int maxDictSize = 16384)
    {
        // Greedy coverage: find substrings that maximize bytes-covered / dict-bytes-used
        const int segLen = 8;
        var freq = new ConcurrentDictionary<long, int>();
        var segBytes = new ConcurrentDictionary<long, byte[]>();

        foreach (var s in samples)
        {
            if (s.Length < segLen) continue;
            Parallel.For(0, s.Length - segLen + 1, i =>
            {
                long key = 0;
                for (int j = 0; j < segLen; j++) key = (key << 8) | s[i + j];
                freq.AddOrUpdate(key, 1, (_, v) => v + 1);
                if (!segBytes.ContainsKey(key))
                {
                    var b = new byte[segLen];
                    Array.Copy(s, i, b, 0, segLen);
                    segBytes[key] = b;
                }
            });
        }

        // Score = frequency * segLen (total bytes potentially matched)
        var ranked = freq.Where(kv => kv.Value >= 2)
            .OrderByDescending(kv => kv.Value * segLen)
            .Take(maxDictSize / segLen).ToArray();

        // Check that we collected enough segments
        if (ranked.Length == 0)
        {
            // Fallback: use 4-byte n-grams
            var freq4 = new ConcurrentDictionary<int, int>();
            foreach (var s in samples)
            {
                if (s.Length < 4) continue;
                for (int i = 0; i < s.Length - 3; i++)
                {
                    int key4 = s[i] | (s[i + 1] << 8) | (s[i + 2] << 16) | (s[i + 3] << 24);
                    freq4.AddOrUpdate(key4, 1, (_, v) => v + 1);
                }
            }
            var r4 = freq4.Where(kv => kv.Value >= 3).OrderByDescending(kv => kv.Value).Take(maxDictSize / 4).ToArray();
            var dict = new byte[r4.Length * 4];
            for (int i = 0; i < r4.Length; i++)
            {
                int k = r4[i].Key;
                dict[i * 4] = (byte)k; dict[i * 4 + 1] = (byte)(k >> 8);
                dict[i * 4 + 2] = (byte)(k >> 16); dict[i * 4 + 3] = (byte)(k >> 24);
            }
            return dict;
        }

        var dict8 = new byte[ranked.Length * segLen];
        for (int i = 0; i < ranked.Length; i++)
        {
            var entry = segBytes[ranked[i].Key];
            Array.Copy(entry, 0, dict8, i * segLen, segLen);
        }
        return dict8;
    }

    private static byte[] DefaultDict()
    {
        return new byte[] {
            (byte)'p', (byte)'u', (byte)'b', (byte)'l',
            (byte)'p', (byte)'r', (byte)'i', (byte)'v',
            (byte)'s', (byte)'t', (byte)'a', (byte)'t',
            (byte)'c', (byte)'l', (byte)'a', (byte)'s',
            (byte)'s', (byte)'t', (byte)'r', (byte)'i',
            (byte)'u', (byte)'s', (byte)'i', (byte)'n',
            (byte)'n', (byte)'a', (byte)'m', (byte)'e',
            (byte)'v', (byte)'o', (byte)'i', (byte)'d',
            (byte)'r', (byte)'e', (byte)'t', (byte)'u',
            (byte)'b', (byte)'y', (byte)'t', (byte)'e',
            (byte)'v', (byte)'a', (byte)'r', (byte)' ',
            (byte)'n', (byte)'e', (byte)'w', (byte)' ',
            (byte)'i', (byte)'n', (byte)'t', (byte)' ',
            (byte)'b', (byte)'o', (byte)'o', (byte)'l',
            (byte)'f', (byte)'o', (byte)'r', (byte)' ',
            (byte)'i', (byte)'f', (byte)' ', (byte)'(',
            (byte)'e', (byte)'l', (byte)'s', (byte)'e',
            (byte)'t', (byte)'h', (byte)'i', (byte)'s',
            (byte)'n', (byte)'u', (byte)'l', (byte)'l',
            (byte)'t', (byte)'r', (byte)'u', (byte)'e',
            (byte)'f', (byte)'a', (byte)'l', (byte)'s',
            (byte)'C', (byte)'o', (byte)'n', (byte)'s',
            (byte)'L', (byte)'i', (byte)'s', (byte)'t',
            (byte)' ', (byte)'{', (byte)'\r',(byte)'\n',
            (byte)'}', (byte)'\r', (byte)'\n', (byte)' ',
            (byte)';', (byte)'\r', (byte)'\n', (byte)' ',
            (byte)' ', (byte)'=', (byte)' ', (byte)' ',
            (byte)'(', (byte)'i', (byte)'n', (byte)'t',
            (byte)'(', (byte)'b', (byte)'y', (byte)'t',
            (byte)'a', (byte)'r', (byte)'r', (byte)'a',
            (byte)'R', (byte)'D', (byte)'R', (byte)'F',
            (byte)'C', (byte)'o', (byte)'r', (byte)'e',
            (byte)'C', (byte)'o', (byte)'m', (byte)'p',
            (byte)'R', (byte)'e', (byte)'a', (byte)'d',
            (byte)'W', (byte)'r', (byte)'i', (byte)'t',
            (byte)'T', (byte)'a', (byte)'b', (byte)'l',
            (byte)'E', (byte)'n', (byte)'c', (byte)'o',
            (byte)'D', (byte)'e', (byte)'c', (byte)'o',
            (byte)'C', (byte)'k', (byte)'c', (byte)'M',
            (byte)'a', (byte)'t', (byte)'c', (byte)'h',
            (byte)'T', (byte)'o', (byte)'k', (byte)'e',
            (byte)'S', (byte)'t', (byte)'a', (byte)'t',
            (byte)'F', (byte)'i', (byte)'n', (byte)'d',
            (byte)'L', (byte)'o', (byte)'n', (byte)'g',
            (byte)'T', (byte)'a', (byte)'n', (byte)'s',
        };
    }
}
