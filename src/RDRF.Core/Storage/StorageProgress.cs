namespace RDRF.Core.DSAA;

public enum StorageProgressStage
{
    Upload,
    Download,
}

public class StorageProgress
{
    public string BackendName { get; set; } = string.Empty;
    public string CurrentFile { get; set; } = string.Empty;
    public long BytesTransferred { get; set; }
    public long TotalBytes { get; set; }
    public StorageProgressStage Stage { get; set; }
}
