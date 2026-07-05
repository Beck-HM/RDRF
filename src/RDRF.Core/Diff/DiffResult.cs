namespace RDRF.Core.Diff;

/// <summary>
/// DTOs: DiffResult, DiffLine, DiffLineType enum for diff output.
/// </summary>

public enum DiffLineType
{
    Header,
    Context,
    Addition,
    Deletion
}

/// <summary>
/// DTOs: DiffResult, DiffLine, DiffLineType enum for diff output.
/// </summary>

public class DiffLine
{
    public DiffLineType Type { get; set; }
    public string Text { get; set; } = "";
}

/// <summary>
/// DTOs: DiffResult, DiffLine, DiffLineType enum for diff output.
/// </summary>

public class DiffResult
{
    public string? Label { get; set; }
    public bool IsBinary { get; set; }
    public long AddedBytes { get; set; }
    public long RemovedBytes { get; set; }
    public int AddedLines { get; set; }
    public int RemovedLines { get; set; }
    public int ChangedLines { get; set; }
    public List<DiffLine> Lines { get; set; } = new();
    public string HumanDiff { get; set; } = "";
    public string? DetectedFileType { get; set; }
    public long OriginalSize { get; set; }
    public string? OriginalHash { get; set; }
    public double ChangeRatio { get; set; }
    public Dictionary<string, object>? Metadata { get; set; }
}

