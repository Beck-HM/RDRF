namespace RDRF.Core.Abstractions;

/// <summary>
/// Efficient hex encoding utilities. Avoids the double-allocation
/// pattern of Convert.ToHexString() + .ToLowerInvariant().
/// </summary>
public static class Hex
{
    private static readonly char[] Lower = "0123456789abcdef".ToCharArray();

    /// <summary>Encodes bytes to lowercase hex string in a single allocation.</summary>
    public static string EncodeLower(byte[] bytes)
    {
        if (bytes == null || bytes.Length == 0) return "";
        var chars = new char[bytes.Length * 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            chars[i * 2] = Lower[bytes[i] >> 4];
            chars[i * 2 + 1] = Lower[bytes[i] & 0xF];
        }
        return new string(chars);
    }

    /// <summary>Encodes a span of bytes to lowercase hex string.</summary>
    public static string EncodeLower(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0) return "";
        var chars = new char[bytes.Length * 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            chars[i * 2] = Lower[bytes[i] >> 4];
            chars[i * 2 + 1] = Lower[bytes[i] & 0xF];
        }
        return new string(chars);
    }
}
