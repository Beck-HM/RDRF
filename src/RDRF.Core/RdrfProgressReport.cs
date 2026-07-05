namespace RDRF.Core;

/// <summary>
/// Progress report DTO for backup/restore operations.
/// </summary>

public class RdrfProgressReport
{
    public string Stage { get; set; } = string.Empty;
    public int CurrentItem { get; set; }
    public int TotalItems { get; set; }
    public long CurrentBytes { get; set; }
    public long TotalBytes { get; set; }
}

