namespace RDRF.Core.Versioning;

public class FileEntry
{
    public string Path { get; set; } = string.Empty;
    public string ChangeType { get; set; } = "modified";
    public string Diff { get; set; } = string.Empty;
}

public class VersionRecord
{
    public int Version { get; set; }
    public string UserMessage { get; set; } = string.Empty;
    public string SystemDiff { get; set; } = string.Empty;
    public long CreatedAt { get; set; }
    public string FileFingerprint { get; set; } = string.Empty;
    public byte[]? Salt { get; set; }
    public List<FileEntry>? Files { get; set; }
}
