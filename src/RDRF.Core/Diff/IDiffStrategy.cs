namespace RDRF.Core.Diff;

public interface IDiffStrategy
{
    string Name { get; }

    double MatchScore(string? fileName, ReadOnlySpan<byte> sample);

    DiffResult ComputeDiff(byte[] oldData, byte[] newData, string? label);
}
