using RDRF.Core.Index;

namespace RDRF.Core.FSS;

public interface IFssStrategy
{
    string Level { get; }

    List<byte[]> Encode(List<byte[]> fragments);

    Dictionary<int, byte[]> Decode(
        Dictionary<int, byte[]> available,
        List<int> missingIndices,
        int totalFragments,
        List<int>? originalSizes = null);

    List<byte[]> Strip(
        Dictionary<int, byte[]> encodedFragments,
        int originalFragmentCount,
        List<int>? originalSizes = null);

    byte[] StripSingle(byte[] encodedFragment, int index, List<int>? originalSizes = null);
}
