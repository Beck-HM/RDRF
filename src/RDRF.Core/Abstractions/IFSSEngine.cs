using RDRF.Core.FSS;

namespace RDRF.Core.Abstractions;

/// <summary>
/// Registry and executor for FSS (Fragment Self-healing Strategy) encode/decode operations.
/// </summary>
public interface IFSSEngine
{
    /// <summary>Registers an FSS strategy implementation for a given identifier.</summary>
    void RegisterStrategy(string level, IFssStrategy strategy);

    /// <summary>Returns the registered strategy for the given level.</summary>
    IFssStrategy GetStrategy(string level);

    /// <summary>Encodes fragments using the specified FSS strategy, producing redundancy data.</summary>
    List<byte[]> Encode(List<byte[]> fragments, string level);

    /// <summary>Decodes available fragments to recover missing ones using the FSS repair data.</summary>
    Dictionary<int, byte[]> Decode(Dictionary<int, byte[]> available, List<int> missingIndices, string level, int totalFragments, List<int>? originalSizes = null);

    /// <summary>Strips FSS encoding overhead from fragments, returning the original data.</summary>
    List<byte[]> Strip(Dictionary<int, byte[]> fragments, string level, int originalCount, List<int>? originalSizes = null);
}
