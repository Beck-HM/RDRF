namespace RDRF.Core.Versioning;

public enum DiffLineType
{
    Header,
    Context,
    Addition,
    Deletion
}

public class DiffLine
{
    public DiffLineType Type { get; set; }
    public string Text { get; set; } = "";
}

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
}
