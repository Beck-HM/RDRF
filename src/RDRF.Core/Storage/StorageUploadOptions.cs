namespace RDRF.Storage;

public class StorageUploadOptions
{
    public string FileType { get; set; } = string.Empty;
    public long FileSize { get; set; }

    public string? OriginalFileName { get; set; }
    public string? ForceBackend { get; set; }
    public List<string>? ExcludeBackends { get; set; }
    public string? OverridePolicy { get; set; }
    public string? Note { get; set; }
    public int? Priority { get; set; }
}
