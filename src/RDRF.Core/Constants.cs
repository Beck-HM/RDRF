namespace RDRF.Core;

/// <summary>
/// Constants shared across RDRF core and FSS subsystem.
/// </summary>
public static class Constants
{
    // Fragment Configuration
    public const int DefaultFragmentSize = 1024 * 1024; // 1MB (legacy default, used when file size unknown)
    public const int MinFragmentSize = 256 * 1024;      // 256 KB
    public const int MaxFragmentSize = 64 * 1024 * 1024; // 64 MB
    public const int TargetFragmentCount = 50;           // aim for ~50 fragments
    public const int MaxSingleEncryptSize = 1024 * 1024 * 1024; // 1 GB per call (AES-CTR single-call safety)

    /// <summary>
    /// Computes an adaptive fragment size based on the source file size.
    /// If the caller provides a user-specified size (e.g., from CLI -size), that value is used directly.
    /// Otherwise, the fragment size is chosen to produce approximately <see cref="TargetFragmentCount"/> fragments,
    /// clamped between <see cref="MinFragmentSize"/> and <see cref="MaxFragmentSize"/>.
    /// </summary>
    public static int ComputeFragmentSize(long fileSize, int? userOverride = null)
    {
        if (userOverride > 0)
            return userOverride.Value;
        int computed = (int)(fileSize / TargetFragmentCount);
        return Math.Max(MinFragmentSize, Math.Min(MaxFragmentSize, computed));
    }

    // AES Encryption Parameters
    public const int NonceLength = 12;
    public const int KeyLength = 32;

    // RC Code
    public const int RcCodeLength = 32;

    // Index File
    public const string IndexFileSuffix = ".indrdrf";

    // Fragment File Naming
    public const string FragmentFilePattern = "{0}_{1}.rdrf";
    public const string FragmentFileSuffix = ".rdrf";

    // Salt Prefix for Index Files
    public const int SaltPrefixLength = 32;

    // Key Derivation Version (stored in index CBOR)
    public const int KdfLegacy = 0; // SHA256 only
    public const int KdfPbkdf2 = 1; // PBKDF2 + per-backup salt

    // Hash Algorithm
    public const string HashAlgorithm = "SHA256";

    // Storage & Cache
    public const int CacheExpiryMinutes = 60;
    public const string MetadataFileName = "rdrf_metadata.json";
    public const string RcFileSuffix = ".rdrc";

    // FSS Strategy Levels
    public const string FssLevel1 = "FSS1";
    public const string FssLevel2 = "FSS2";
    public const string FssLevel2R = "FSS2R";
    public const string FssLevel3 = "FSS3";
    public const string FssLevel5 = "FSS5";
    public const string FssLevel5P = "FSS5+";
    public const string FssLevel6 = "FSS6";
    public const string FssLevel61 = "FSS6.1";
    public const string FssLevel62 = "FSS6.2";

    // Compression
    public const string CompressionLz4 = "lz4";
    public const string CompressionLz4Hc = "lz4hc";
    public const string CompressionZstd = "zstd";
    public const string CompressionGzip = "gzip";
    public const string CompressionBrotli = "brotli";
    public const string CompressionLzma = "lzma2";
    public const string CompressionLzo = "lzo";
    public const string CompressionXpressHuff = "xpress_huff";
    public const string CompressionLzms = "lzms";
    public const string CompressionCkc = "ckc";
    public const string CompressionXz = "xz";

    // Parallelism
    /// <summary>CPU-bound parallel width for backup/restore fragment work.</summary>
    public static readonly int DefaultParallelism = Math.Max(2, Environment.ProcessorCount);

    public static readonly HashSet<string> FssLevels = new()
    {
        FssLevel1, FssLevel2, FssLevel2R, FssLevel3,
        FssLevel5, FssLevel5P, FssLevel6, FssLevel61, FssLevel62
    };
}
