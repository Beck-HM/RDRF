using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace RDRF.Core.Integrity;

public static class IntegrityChecker
{
    public static string HashBytes(byte[] data)
    {
        byte[] hash = SHA256.HashData(data);
        return BytesToHex(hash);
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
        byte[] actualBytes = ConvertHexToBytes(actualHash);
        byte[] expectedBytes = ConvertHexToBytes(expectedHash);
        return CryptographicOperations.FixedTimeEquals(actualBytes, expectedBytes);
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

    private static string BytesToHex(byte[] bytes)
    {
        StringBuilder sb = new StringBuilder(bytes.Length * 2);
        foreach (byte b in bytes)
            sb.Append(b.ToString("x2"));
        return sb.ToString();
    }
}
