namespace RDRF.Core.Diff;

public class DiffEngine
{
    private readonly List<IDiffStrategy> _strategies;

    public DiffEngine()
    {
        _strategies =
        [
            new Strategies.JsonDiffStrategy(),
            new Strategies.IniDiffStrategy(),
            new Strategies.TextGenericStrategy(),
            new Strategies.BinaryDefaultStrategy(),
        ];
    }

    public DiffEngine(IEnumerable<IDiffStrategy> additionalStrategies)
    {
        _strategies = new List<IDiffStrategy>
        {
            new Strategies.JsonDiffStrategy(),
            new Strategies.IniDiffStrategy(),
            new Strategies.TextGenericStrategy(),
            new Strategies.BinaryDefaultStrategy(),
        };
        if (additionalStrategies != null)
            _strategies.AddRange(additionalStrategies);
    }

    public IDiffStrategy SelectStrategy(string? fileName, ReadOnlySpan<byte> sample)
    {
        IDiffStrategy best = _strategies[^1];
        double bestScore = -1;

        foreach (var s in _strategies)
        {
            double score = s.MatchScore(fileName, sample);
            if (score > bestScore)
            {
                bestScore = score;
                best = s;
            }
        }

        return best;
    }

    public DiffResult ComputeDiff(byte[] oldData, byte[] newData, string? label = null)
    {
        var sample = newData.Length > 0 ? newData.AsSpan(0, Math.Min(newData.Length, 1024)) : ReadOnlySpan<byte>.Empty;
        var strategy = SelectStrategy(label, sample);
        var result = strategy.ComputeDiff(oldData, newData, label);
        return result;
    }
}
