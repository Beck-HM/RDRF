namespace RDRF.Core.FSS;

/// <summary>
/// FSS strategy registry. Maps strategy name strings to IFssStrategy instances.
/// </summary>

public class FSSEngine
{
    private readonly Dictionary<string, IFssStrategy> _strategyMap = new();

    public FSSEngine()
    {
        RegisterStrategy(Constants.FssLevel1, new Fss1Neighbor());
        RegisterStrategy(Constants.FssLevel2, new Fss2Verify());
        RegisterStrategy(Constants.FssLevel2R, new Fss2RRepair());
        RegisterStrategy(Constants.FssLevel3, new Fss3ReedSolomon());
        RegisterStrategy(Constants.FssLevel5, new Fss5CrossRecovery());
        RegisterStrategy(Constants.FssLevel5P, new Fss5PSend());
        RegisterStrategy(Constants.FssLevel6, new Fss6Etn());
        RegisterStrategy(Constants.FssLevel61, new Fss61Etn());
        RegisterStrategy(Constants.FssLevel62, new Fss62Etn());
    }

    public void RegisterStrategy(string level, IFssStrategy strategy)
        => _strategyMap[level] = strategy;

    public IFssStrategy GetStrategy(string level)
        => _strategyMap.TryGetValue(level, out var strategy)
            ? strategy
            : throw new ArgumentException($"Unknown FSS strategy: {level}");

    public List<byte[]> Encode(List<byte[]> fragments, string level)
        => GetStrategy(level).Encode(fragments);

    public Dictionary<int, byte[]> Decode(
        Dictionary<int, byte[]> available,
        List<int> missingIndices,
        string level,
        int totalFragments,
        List<int>? originalSizes = null)
        => GetStrategy(level).Decode(available, missingIndices, totalFragments, originalSizes);

    public List<byte[]> Strip(
        Dictionary<int, byte[]> encodedFragments,
        string level,
        int originalFragmentCount,
        List<int>? originalSizes = null)
        => GetStrategy(level).Strip(encodedFragments, originalFragmentCount, originalSizes);
}

