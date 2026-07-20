namespace RDRF.Server;

public static class FragmentStore
{
    public static string StoragePath { get; set; } = "storage";

    public static byte[]? ReadFragment(string name)
    {
        string path = Resolve(name);
        return File.Exists(path) ? File.ReadAllBytes(path) : null;
    }

    public static async Task<byte[]?> ReadFragmentAsync(string name, CancellationToken ct = default)
    {
        string path = Resolve(name);
        if (!File.Exists(path)) return null;
        return await File.ReadAllBytesAsync(path, ct).ConfigureAwait(false);
    }

    public static void WriteFragment(string name, byte[] data)
    {
        string path = Resolve(name);
        string tmp = Path.Combine(StoragePath, Path.GetRandomFileName());
        try
        {
            File.WriteAllBytes(tmp, data);
            File.Move(tmp, path, overwrite: true);
        }
        catch { try { File.Delete(tmp); } catch { } throw; }
    }

    public static Stream OpenResumeStream(string name, long offset)
    {
        string partPath = PartPath(name);
        var dir = Path.GetDirectoryName(partPath)!;
        Directory.CreateDirectory(dir);
        return new FileStream(partPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None)
        {
            Position = offset
        };
    }

    public static void FinalizeChunk(string name, long totalSize)
    {
        string partPath = PartPath(name);
        string finalPath = Resolve(name);
        if (new FileInfo(partPath).Length >= totalSize)
            File.Move(partPath, finalPath, overwrite: true);
    }

    public static bool Exists(string name) => File.Exists(Resolve(name));
    public static void Delete(string name) { var p = Resolve(name); if (File.Exists(p)) File.Delete(p); }

    public static List<int> ListIndices(string prefix)
    {
        var result = new List<int>();
        var files = Directory.GetFiles(StoragePath, $"{prefix}_*.rdrf");
        foreach (var f in files)
        {
            string name = Path.GetFileNameWithoutExtension(f);
            int lastUs = name.LastIndexOf('_');
            if (lastUs > 0 && int.TryParse(name[(lastUs + 1)..], out int idx))
                result.Add(idx);
        }
        result.Sort();
        return result;
    }

    public static void CleanupParts(double timeoutHours)
    {
        var cutoff = DateTime.UtcNow.AddHours(-timeoutHours);
        var parts = Directory.GetFiles(StoragePath, "*.part", SearchOption.AllDirectories);
        foreach (var p in parts)
            if (File.GetLastWriteTimeUtc(p) < cutoff)
                try { File.Delete(p); } catch { }
    }

    public static string PartPath(string name) => Path.Combine(StoragePath, name + ".part");
    private static string Resolve(string name) => Path.Combine(StoragePath, name);
}
