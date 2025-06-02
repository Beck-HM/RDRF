namespace RDRF.Core.Versioning;

public class VersionRecord
{
    public int Version { get; set; }
    public string UserMessage { get; set; } = string.Empty;
    public string SystemDiff { get; set; } = string.Empty;
    public long CreatedAt { get; set; }
    public string FileFingerprint { get; set; } = string.Empty;
}
