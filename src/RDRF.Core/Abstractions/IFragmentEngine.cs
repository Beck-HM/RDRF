namespace RDRF.Core.Abstractions;

public interface IFragmentEngine
{
    string FragmentFilename(string filePrefix, int index);
    int GetFragmentCount(long fileSize, int fragmentSize = 0);
    List<byte[]> SplitData(byte[] data, int fragmentSize = 0);
    byte[] MergeFragments(List<byte[]> fragments);
    string ComputeFingerprint(byte[] data);
}
