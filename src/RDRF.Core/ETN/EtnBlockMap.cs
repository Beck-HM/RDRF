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
        byte[][] hashes = new byte[blockCount][];
        for (int i = 0; i < blockCount; i++)
        {
            int offset = i * BlockSize;
            int len = Math.Min(BlockSize, data.Length - offset);
            byte[] h = new byte[32];
            SHA256.HashData(data.AsSpan(offset, len), h.AsSpan());
            hashes[i] = h;
        }
        return hashes.ToList();
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

    public static bool IsSecondPassMatch(byte[] actualFull, byte[] storedSecond)
    {
        int len = Math.Min(SecondHashLen, storedSecond.Length);
        return CryptographicOperations.FixedTimeEquals(
            actualFull.AsSpan(0, len), storedSecond.AsSpan(0, len));
    }

    public static byte[] HexToHash(string hex) => Convert.FromHexString(hex);

    public static string HashToHex(byte[] hash)
    {
        return string.Create(hash.Length * 2, hash, static (chars, bytes) =>
        {
            for (int i = 0; i < bytes.Length; i++)
            {
                byte b = bytes[i];
                chars[i * 2] = HexChar(b >> 4);
                chars[i * 2 + 1] = HexChar(b & 0xF);
            }
        });
    }

    private static char HexChar(int val) => (char)(val < 10 ? '0' + val : 'a' + val - 10);
}