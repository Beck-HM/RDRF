namespace RDRF.Core.Abstractions;

/// <summary>
/// Persists backup metadata and per-fragment status in a local database.
/// </summary>
public interface IMetadataManager
{
    /// <summary>Records a new backup with its fingerprint, filename, size, hash, strategy, and fragment hashes.</summary>
    void SaveBackup(string fileFingerprint, string originalFilename, long originalSize, string originalHash, string fssStrategy, List<string> fragmentHashes);

    /// <summary>Removes all metadata for the given backup fingerprint.</summary>
    void DeleteBackup(string fileFingerprint);

    /// <summary>Marks a fragment as verified and intact.</summary>
    void MarkFragmentOk(string fileFingerprint, int fragmentIndex);

    /// <summary>Marks a fragment as missing from storage.</summary>
    void MarkFragmentMissing(string fileFingerprint, int fragmentIndex);

    /// <summary>Marks a fragment as corrupted (hash mismatch).</summary>
    void MarkFragmentCorrupt(string fileFingerprint, int fragmentIndex);

    /// <summary>Returns the current status for all fragments of a backup.</summary>
    Dictionary<int, string> GetFragmentStatus(string fileFingerprint);
}
