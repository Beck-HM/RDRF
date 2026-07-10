using RDRF.Core.FSS;

namespace RDRF.Core.Abstractions;

public interface IFSSEngine
{
    void RegisterStrategy(string level, IFssStrategy strategy);
    IFssStrategy GetStrategy(string level);
    List<byte[]> Encode(List<byte[]> fragments, string level);
    Dictionary<int, byte[]> Decode(Dictionary<int, byte[]> available, List<int> missingIndices, string level, int totalFragments, List<int>? originalSizes = null);
    List<byte[]> Strip(Dictionary<int, byte[]> fragments, string level, int originalCount, List<int>? originalSizes = null);
}
