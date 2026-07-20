namespace RDRF.Core.Compression;

/// <summary>
/// Pluggable compression algorithm. Implementations register with
/// <see cref="CompressionRouter"/> for automatic dispatch.
/// </summary>
public interface ICompressionAlgorithm
{
    /// <summary>Human-readable name of the compression algorithm.</summary>
    string Name { get; }

    /// <summary>
    /// Compresses raw data. May return the original array if compression is not beneficial.
    /// <paramref name="options"/> carries algorithm-specific configuration as a string
    /// (e.g. "5" for Zstd level 5, "3" for LZ4 level 3); each algorithm parses it internally.
    /// </summary>
    byte[] Compress(byte[] data, string? options = null);

    /// <summary>Decompresses data that was previously compressed with this algorithm.</summary>
    byte[] Decompress(byte[] data);

    /// <summary>Returns true if the data is likely compressed with this algorithm (magic byte detection).</summary>
    bool CanHandle(byte[] data);
}
