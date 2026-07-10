using System;
using RDRF.Core.Abstractions;

namespace RDRF.Core.FSS;

public class FSSEngineWrapper : IFSSEngine
{
    private readonly FSSEngine _inner;

    public FSSEngineWrapper()
    {
        _inner = new FSSEngine();
    }

    public FSSEngineWrapper(FSSEngine inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    public void RegisterStrategy(string level, IFssStrategy strategy) => _inner.RegisterStrategy(level, strategy);
    public IFssStrategy GetStrategy(string level) => _inner.GetStrategy(level);
    public List<byte[]> Encode(List<byte[]> fragments, string level) => _inner.Encode(fragments, level);
    public Dictionary<int, byte[]> Decode(Dictionary<int, byte[]> available, List<int> missingIndices, string level, int totalFragments, List<int>? originalSizes = null)
        => _inner.Decode(available, missingIndices, level, totalFragments, originalSizes);
    public List<byte[]> Strip(Dictionary<int, byte[]> fragments, string level, int originalCount, List<int>? originalSizes = null)
        => _inner.Strip(fragments, level, originalCount, originalSizes);
}
