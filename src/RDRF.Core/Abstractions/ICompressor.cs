namespace RDRF.Core.Abstractions;

/// <summary>
/// Compression facade that delegates to the pluggable <see cref="Compression.CompressionRouter"/>.
/// Provides anti-expansion logic and magic byte detection for already-compressed formats.
/// </summary>
public interface ICompressor
{
    /// <summary>
    /// Compresses data using the specified method.
    /// <paramref name="options"/> carries algorithm-specific configuration (e.g. "5" for Zstd level).
    /// Returns original if compression expands.
    /// </summary>
    byte[] Compress(byte[] data, string? method = null, string? options = null);

    /// <summary>Decompresses data using the specified method.</summary>
    byte[] Decompress(byte[] data, string? method);

    /// <summary>Always compresses regardless of anti-expansion checks.</summary>
    byte[] AlwaysCompress(byte[] data, string? method = null, string? options = null);

    /// <summary>Returns true if the data starts with the LZ4 frame magic bytes.</summary>
    bool IsLz4Frame(byte[] data);
}
