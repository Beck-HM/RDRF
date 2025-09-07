using RDRF.Core.Index;

namespace RDRF.Core.FSS;

public class Fss2RRepair : IFssStrategy
{
    private readonly Fss2Verify _fss2 = new();

    public string Level => Constants.FssLevel2R;

    public List<byte[]> Encode(List<byte[]> fragments) => _fss2.Encode(fragments);

    public Dictionary<int, byte[]> Decode(
        Dictionary<int, byte[]> available,
        List<int> missingIndices,
        int totalFragments,
        List<int>? originalSizes = null)
        => _fss2.Decode(available, missingIndices, totalFragments, originalSizes);

    public List<byte[]> Strip(
        Dictionary<int, byte[]> encodedFragments,
        int originalFragmentCount,
        List<int>? originalSizes = null)
        => _fss2.Strip(encodedFragments, originalFragmentCount, originalSizes);

    public byte[] StripSingle(byte[] encodedFragment, int index, List<int>? originalSizes = null)
        => _fss2.StripSingle(encodedFragment, index, originalSizes);
}
