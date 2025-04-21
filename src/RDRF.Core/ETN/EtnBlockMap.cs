using System.Security.Cryptography;

namespace RDRF.Core.ETN;

public static class EtnBlockMap
{
    public const int BlockSize = 256;
    public const int TrailerHashLen = 2;
    public const int SecondHashLen = 8;

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

    public static byte[] TruncateFirst(byte[] fullHash) => fullHash[..TrailerHashLen];
    public static byte[] TruncateSecond(byte[] fullHash) => fullHash[..SecondHashLen];

    public static List<int> DiffTrimmed(List<byte[]> actualFull, List<byte[]>? stored)
    {
        var diff = new List<int>();
        if (stored == null) return diff;
        int count = Math.Min(actualFull.Count, stored.Count);
        for (int i = 0; i < count; i++)
        {
            int len = Math.Min(actualFull[i].Length, stored[i].Length);
            if (!CryptographicOperations.FixedTimeEquals(
                    actualFull[i].AsSpan(0, len),
                    stored[i].AsSpan(0, len)))
                diff.Add(i);
        }
        for (int i = count; i < actualFull.Count || i < stored.Count; i++)
            diff.Add(i);
        return diff;
    }

    public static byte[] HashTrimmed(byte[] fullHash, int len)
    {
        var trimmed = new byte[len];
        Buffer.BlockCopy(fullHash, 0, trimmed, 0, len);
        return trimmed;
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

    public static bool IsFirstPassMatch(byte[] actualFull, byte[] storedTrailer)
        => actualFull[0] == storedTrailer[0] && actualFull[1] == storedTrailer[1];

    public static bool IsSecondPassMatch(byte[] actualFull, byte[] storedSecond)
    {
        int len = Math.Min(SecondHashLen, storedSecond.Length);
        for (int i = 0; i < len; i++)
            if (actualFull[i] != storedSecond[i]) return false;
        return true;
    }

    public static byte[] HexToHash(string hex) => Convert.FromHexString(hex);
    public static string HashToHex(byte[] hash) => Convert.ToHexString(hash).ToLowerInvariant();
}
