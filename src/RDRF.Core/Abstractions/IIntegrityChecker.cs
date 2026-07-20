namespace RDRF.Core.Abstractions;

/// <summary>
/// Verifies data integrity through hashing (XxHash128) and equality checks.
/// </summary>
public interface IIntegrityChecker
{
    /// <summary>Computes the XxHash128 hash of a byte array.</summary>
    string HashBytes(byte[] data);

    /// <summary>Computes the XxHash128 hash of a file on disk.</summary>
    string HashFile(string filePath);

    /// <summary>Compares an actual hash string against the expected one (case-insensitive).</summary>
    bool VerifyHash(string actualHash, string expectedHash);

    /// <summary>Hashes a fragment and compares it against the expected hash.</summary>
    bool VerifyFragment(byte[] fragmentData, string expectedHash);

    /// <summary>Timing-safe byte array equality comparison.</summary>
    bool BytesEqual(byte[]? a, byte[]? b);
}
