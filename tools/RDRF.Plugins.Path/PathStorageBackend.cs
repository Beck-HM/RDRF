using RDRF.Core.Dssa;

namespace RDRF.Plugins.Path;

public class PathStorageBackend : IStorageBackend
{
    private readonly string _basePath;

    public PathStorageBackend(string basePath)
    {
        _basePath = basePath;
        Directory.CreateDirectory(_basePath);
    }

    public string Name => "PathStorage";

    public Task<Stream> OpenWriteAsync(string path, long fileSize,
        IProgress<StorageProgress>? progress = null)
    {
        var fullPath = GetFullPath(path);
        System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(fullPath)!);
        return Task.FromResult<Stream>(
            new FileStream(fullPath, FileMode.Create, FileAccess.Write, FileShare.None, 65536, true));
    }

    public Task<Stream> OpenReadAsync(string path)
    {
        var fullPath = GetFullPath(path);
        return Task.FromResult<Stream>(
            new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, true));
    }

    public Task DeleteAsync(string path)
    {
        var fullPath = GetFullPath(path);
        if (File.Exists(fullPath))
            File.Delete(fullPath);
        return Task.CompletedTask;
    }

    public Task<bool> ExistsAsync(string path)
    {
        var fullPath = GetFullPath(path);
        return Task.FromResult(File.Exists(fullPath));
    }

    public Task<bool> PingAsync()
    {
        return Task.FromResult(Directory.Exists(_basePath));
    }

    private string GetFullPath(string relativePath)
    {
        if (relativePath.Contains(".."))
            throw new ArgumentException("Path traversal detected in: " + relativePath);
        return System.IO.Path.Combine(_basePath, relativePath);
    }
}

