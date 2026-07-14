namespace RDRF.Core.DSAA;

public interface IStorageBackend
{
    string Name { get; }

    Task<Stream> OpenWriteAsync(string path, long fileSize,
        IProgress<StorageProgress>? progress = null);

    Task<Stream> OpenReadAsync(string path);

    Task DeleteAsync(string path);

    Task<bool> ExistsAsync(string path);

    Task<bool> PingAsync();
}
