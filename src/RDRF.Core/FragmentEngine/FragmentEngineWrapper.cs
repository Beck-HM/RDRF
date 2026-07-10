using RDRF.Core.Abstractions;

namespace RDRF.Core.FragmentEngine;

public class FragmentEngineWrapper : IFragmentEngine
{
    public string FragmentFilename(string filePrefix, int index) => Frags.FragmentFilename(filePrefix, index);
    public int GetFragmentCount(long fileSize, int fragmentSize = 0) => Frags.GetFragmentCount(fileSize, fragmentSize);
    public List<byte[]> SplitData(byte[] data, int fragmentSize = 0) => Frags.SplitData(data, fragmentSize);
    public byte[] MergeFragments(List<byte[]> fragments) => Frags.MergeFragments(fragments);
    public string ComputeFingerprint(byte[] data) => Frags.ComputeFingerprint(data);
}
