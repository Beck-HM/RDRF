namespace RDRF.Core;

/// <summary>
/// Constants shared across RDRF core and FSS subsystem.
/// </summary>
public static class Constants
{
    // Fragment Configuration
    public const int DefaultFragmentSize = 1024 * 1024; // 1MB

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

    public static readonly HashSet<string> FssLevels = new()
    {
        FssLevel1, FssLevel2, FssLevel2R, FssLevel3,
        FssLevel5, FssLevel5P, FssLevel6, FssLevel61
    };

    // FSS Storage Overhead
    private static readonly Dictionary<string, double> FssOverhead = new()
    {
        { FssLevel1, 0.50 },
        { FssLevel2, 0.55 },
        { FssLevel2R, 0.57 },
        { FssLevel3, 0.86 },
        { FssLevel5, 2.00 },
        { FssLevel5P, 40.0 },
        { FssLevel6, 0.00008 },
        { FssLevel61, 0.05 },
    };
}
