using System.Security.Cryptography;

namespace RDRF.Core.ETN;

public static class EtnBlockMap
{
    public const int BlockSize = 256;
    public const int TrailerHashLen = 2;
    public const int SecondHashLen = 8;
    public const int FullHashLen = 32;

    public static int BlockCount(byte[] flat) => flat.Length / FullHashLen;

    public static byte[] Build(byte[] data)
    {
        int blockCount = (data.Length + BlockSize - 1) / BlockSize;
        byte[] flat = new byte[blockCount * FullHashLen];
        for (int i = 0; i < blockCount; i++)
        {
            int offset = i * BlockSize;
            int len = Math.Min(BlockSize, data.Length - offset);
            SHA256.HashData(data.AsSpan(offset, len), flat.AsSpan(i * FullHashLen, FullHashLen));
        }
        return flat;
    }

    public static byte[] TruncateFirst(byte[] flat, int blockIndex)
    {
        int off = blockIndex * FullHashLen;
        return new byte[] { flat[off], flat[off + 1] };
    }

    public static byte[] TruncateSecond(byte[] flat, int blockIndex)
    {
        int off = blockIndex * FullHashLen;
        byte[] result = new byte[SecondHashLen];
        Buffer.BlockCopy(flat, off, result, 0, SecondHashLen);
        return result;
    }

    public static byte[] FlattenFirst(byte[] fullFlat, int blockCount)
    {
        byte[] result = new byte[blockCount * TrailerHashLen];
        for (int i = 0; i < blockCount; i++)
        {
            result[i * TrailerHashLen] = fullFlat[i * FullHashLen];
            result[i * TrailerHashLen + 1] = fullFlat[i * FullHashLen + 1];
        }
        return result;
    }

    public static byte[] FlattenSecond(byte[] fullFlat, int blockCount)
    {
        byte[] result = new byte[blockCount * SecondHashLen];
        for (int i = 0; i < blockCount; i++)
            Buffer.BlockCopy(fullFlat, i * FullHashLen, result, i * SecondHashLen, SecondHashLen);
        return result;
    }

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

    public static List<int> DiffTrimmed(byte[] actualFlat, int blockCount, int hashLen, List<byte[]>? stored)
    {
        var diff = new List<int>();
        if (stored == null) return diff;
        int count = Math.Min(blockCount, stored.Count);
        for (int i = 0; i < count; i++)
        {
            int len = Math.Min(hashLen, stored[i].Length);
            if (!CryptographicOperations.FixedTimeEquals(
                    actualFlat.AsSpan(i * hashLen, len),
                    stored[i].AsSpan(0, len)))
                diff.Add(i);
        }
        for (int i = count; i < blockCount || i < stored.Count; i++)
            diff.Add(i);
        return diff;
    }

    public static List<int> DiffTrimmed(byte[] actualFlat, int blockCount, List<byte[]>? stored)
        => DiffTrimmed(actualFlat, blockCount, FullHashLen, stored);

    public static List<int> DiffTrimmed(List<byte[]> stored, byte[] actualFlat, int blockCount)
    {
        var diff = new List<int>();
        int count = Math.Min(blockCount, stored.Count);
        for (int i = 0; i < count; i++)
        {
            int len = Math.Min(FullHashLen, stored[i].Length);
            if (!CryptographicOperations.FixedTimeEquals(
                    actualFlat.AsSpan(i * FullHashLen, len),
                    stored[i].AsSpan(0, len)))
                diff.Add(i);
        }
        for (int i = count; i < blockCount || i < stored.Count; i++)
            diff.Add(i);
        return diff;
    }

    public static List<int> DiffTrimmed(byte[] flatA, int countA, byte[] flatB, int countB, int hashLen)
    {
        var diff = new List<int>();
        int count = Math.Min(countA, countB);
        for (int i = 0; i < count; i++)
            if (!CryptographicOperations.FixedTimeEquals(
                    flatA.AsSpan(i * hashLen, hashLen),
                    flatB.AsSpan(i * hashLen, hashLen)))
                diff.Add(i);
        for (int i = count; i < countA || i < countB; i++)
            diff.Add(i);
        return diff;
    }

    public static bool IsSecondPassMatch(byte[] actualFull, byte[] storedSecond)
    {
        int len = Math.Min(SecondHashLen, storedSecond.Length);
        return CryptographicOperations.FixedTimeEquals(
            actualFull.AsSpan(0, len), storedSecond.AsSpan(0, len));
    }

    public static bool IsSecondPassMatch(byte[] actualFlat, int blockIndex, byte[] storedSecond)
    {
        int off = blockIndex * FullHashLen;
        int len = Math.Min(SecondHashLen, storedSecond.Length);
        return CryptographicOperations.FixedTimeEquals(
            actualFlat.AsSpan(off, len), storedSecond.AsSpan(0, len));
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
