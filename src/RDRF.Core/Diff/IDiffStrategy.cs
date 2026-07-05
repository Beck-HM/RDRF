namespace RDRF.Core.Diff;

/// <summary>
/// Interface for diff strategies (MatchScore/ComputeDiff/FormatRaw).
/// </summary>

public interface IDiffStrategy
{
    string Name { get; }

    double MatchScore(string? fileName, ReadOnlySpan<byte> sample);

    DiffResult ComputeDiff(byte[] oldData, byte[] newData, string? label);
}

