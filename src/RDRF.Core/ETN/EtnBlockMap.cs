using System.Security.Cryptography;

namespace RDRF.Core.ETN;

public static class EtnBlockMap
{
    public const int BlockSize = 256;

    public static List<byte[]> Build(byte[] data)
    {
        int blockCount = (data.Length + BlockSize - 1) / BlockSize;
        var hashes = new List<byte[]>(blockCount);
        for (int i = 0; i < blockCount; i++)
        {
            int offset = i * BlockSize;
            int len = Math.Min(BlockSize, data.Length - offset);
            byte[] hash = SHA256.HashData(data.AsSpan(offset, len));
            hashes.Add(hash);
        }
        return hashes;
    }

    public static bool Compare(List<byte[]> a, List<byte[]> b)
    {
        if (a.Count != b.Count) return false;
        for (int i = 0; i < a.Count; i++)
        {
            if (a[i].Length != b[i].Length) return false;
            if (!CryptographicOperations.FixedTimeEquals(a[i], b[i])) return false;
        }
        return true;
    }

    public static List<int> Diff(List<byte[]> actual, List<byte[]> expected)
    {
        var diff = new List<int>();
        int count = Math.Min(actual.Count, expected.Count);
        for (int i = 0; i < count; i++)
            if (!CryptographicOperations.FixedTimeEquals(actual[i], expected[i]))
                diff.Add(i);
        for (int i = count; i < actual.Count || i < expected.Count; i++)
            diff.Add(i);
        return diff;
    }

    public static byte[] HexToHash(string hex) => Convert.FromHexString(hex);
    public static string HashToHex(byte[] hash) => Convert.ToHexString(hash).ToLowerInvariant();
}
