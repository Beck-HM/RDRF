using System.Security.Cryptography;

namespace RDRF.Cli.Services;

internal static class HashHelper
{
    public static string ComputeSha256Hex(string filePath)
    {
        byte[] bytes = File.ReadAllBytes(filePath);
        byte[] hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
