namespace RDRF.Core.DSAA;

/// <summary>
/// Storage backend that provides async stream-based read/write/delete
/// operations for remote or local storage targets.
/// </summary>
public interface IStorageBackend
{
    /// <summary>Human-readable name of this backend.</summary>
    string Name { get; }

    /// <summary>Opens a write stream to the given path with an optional progress reporter.</summary>
    Task<Stream> OpenWriteAsync(string path, long fileSize,
        IProgress<StorageProgress>? progress = null);

    /// <summary>Opens a read stream from the given path.</summary>
    Task<Stream> OpenReadAsync(string path);

    /// <summary>Deletes the resource at the given path.</summary>
    Task DeleteAsync(string path);

    /// <summary>Returns true if the resource exists at the given path.</summary>
    Task<bool> ExistsAsync(string path);

    /// <summary>Health check to verify the backend is reachable.</summary>
    Task<bool> PingAsync();
}
