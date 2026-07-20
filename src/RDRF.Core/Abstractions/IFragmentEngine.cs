namespace RDRF.Core.Abstractions;

/// <summary>
/// Handles fragment splitting, merging, naming, and fingerprint computation.
/// </summary>
public interface IFragmentEngine
{
    /// <summary>Generates the on-disk filename for a fragment.</summary>
    string FragmentFilename(string filePrefix, int index);

    /// <summary>Returns the number of fragments needed for the given file size.</summary>
    int GetFragmentCount(long fileSize, int fragmentSize = 0);

    /// <summary>Splits raw data into fixed-size fragments.</summary>
    List<byte[]> SplitData(byte[] data, int fragmentSize = 0);

    /// <summary>Merges fragments back into a single byte array.</summary>
    byte[] MergeFragments(List<byte[]> fragments);

    /// <summary>Computes the content-addressable fingerprint (XxHash128) of raw data.</summary>
    string ComputeFingerprint(byte[] data);
}
