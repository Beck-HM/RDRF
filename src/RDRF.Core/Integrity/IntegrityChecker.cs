using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace RDRF.Core.Integrity;

/// <summary>
/// SHA256 hash computation, hex conversion, and constant-time comparison utilities.
/// </summary>

public static class IntegrityChecker
{
    public static string HashBytes(byte[] data)
    {
        // Stackalloc digest + hex avoids intermediate string builder per byte.
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(data, digest);
        return BytesToHex(digest);
    }

    /// <summary>SHA256 hex of a span (no extra array copy of source).</summary>
    public static string HashBytes(ReadOnlySpan<byte> data)
    {
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(data, digest);
        return BytesToHex(digest);
    }

    public static string HashFile(string filePath)
    {
        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
        byte[] hash = SHA256.HashData(stream);
        return BytesToHex(hash);
    }

    public static async Task<string> HashFileAsync(string filePath, CancellationToken ct = default)
    {
        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
        byte[] hash = await SHA256.HashDataAsync(stream, ct).ConfigureAwait(false);
        return BytesToHex(hash);
    }

    public static string HashFile(FileInfo filePath) => HashFile(filePath.FullName);

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static bool VerifyHash(string actualHash, string expectedHash)
    {
        if (string.IsNullOrEmpty(actualHash) || string.IsNullOrEmpty(expectedHash)) return false;
        if (actualHash.Length != expectedHash.Length) return false;
        byte[] aBytes = ConvertHexToBytes(actualHash);
        byte[] bBytes = ConvertHexToBytes(expectedHash);
        return CryptographicOperations.FixedTimeEquals(aBytes, bBytes);
    }

    public static bool VerifyFragment(byte[] fragmentData, string expectedHash)
    {
        string actualHash = HashBytes(fragmentData);
        return VerifyHash(actualHash, expectedHash);
    }

    public static bool VerifyFile(string filePath, string expectedHash)
    {
        string actualHash = HashFile(filePath);
        return VerifyHash(actualHash, expectedHash);
    }

    public static bool VerifyFile(FileInfo filePath, string expectedHash) => VerifyFile(filePath.FullName, expectedHash);

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static bool BytesEqual(byte[]? a, byte[]? b)
    {
        if (a == null || b == null) return a == b;
        if (a.Length != b.Length) return false;
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    private static byte[] ConvertHexToBytes(string hex)
    {
        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }

    private static string BytesToHex(byte[] bytes) => BytesToHex(bytes.AsSpan());

    private static string BytesToHex(ReadOnlySpan<byte> bytes)
    {
        // Lowercase hex without StringBuilder per-nibble format calls.
        Span<char> chars = stackalloc char[bytes.Length * 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            byte b = bytes[i];
            chars[i * 2] = ToHexNibble(b >> 4);
            chars[i * 2 + 1] = ToHexNibble(b & 0xF);
        }
        return new string(chars);
    }

    private static char ToHexNibble(int v) => (char)(v < 10 ? '0' + v : 'a' + (v - 10));
}

