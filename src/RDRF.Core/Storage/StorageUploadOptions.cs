namespace RDRF.Dssa;

public class StorageUploadOptions
{
    public string Fingerprint { get; set; } = string.Empty;
    public string FileType { get; set; } = string.Empty;
    public long FileSize { get; set; }
    public int FragmentCount { get; set; }
    public int FragmentIndex { get; set; } = -1;
    public int VersionNumber { get; set; }

    public string? OriginalFileName { get; set; }
    public string? ForceBackend { get; set; }
    public List<string>? ExcludeBackends { get; set; }
    public string? OverridePolicy { get; set; }
    public string? Note { get; set; }
    public int? Priority { get; set; }

    public List<string>? Backends { get; set; }
    public Dictionary<string, Dictionary<string, string>>? BackendOverrides { get; set; }
}
