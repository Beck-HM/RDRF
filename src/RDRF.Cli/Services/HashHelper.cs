using System.Security.Cryptography;

namespace RDRF.Cli.Services;

internal static class HashHelper
{
    /// <summary>
    /// Stream-hash a file (no full ReadAllBytes).
    /// </summary>
    public static string ComputeSha256Hex(string filePath)
    {
        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, 81920, FileOptions.SequentialScan);
        byte[] hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
