namespace RDRF.Storage;

public class StorageOrchestrator
{
    private readonly Dictionary<string, IStorageBackend> _backends = new();

    public IReadOnlyDictionary<string, IStorageBackend> Backends => _backends;

    public void RegisterBackend(string name, IStorageBackend backend)
    {
        _backends[name] = backend ?? throw new ArgumentNullException(nameof(backend));
    }

    public Task WriteFragmentAsync(byte[] data, StorageUploadOptions options,
        IProgress<StorageProgress>? progress = null)
    {
        throw new NotImplementedException();
    }

    public Task WriteRcAsync(byte[] data, StorageUploadOptions options,
        IProgress<StorageProgress>? progress = null)
    {
        throw new NotImplementedException();
    }

    public Task<byte[]> ReadAllFragmentsAsync(string fingerprint, int version)
    {
        throw new NotImplementedException();
    }

    public Task<byte[]> ReadRcAsync(string fingerprint, int version)
    {
        throw new NotImplementedException();
    }

    public Task<Stream> OpenFragmentStreamAsync(string fingerprint,
        int version, int fragmentIndex)
    {
        throw new NotImplementedException();
    }

    public async Task<bool> PingAllAsync()
    {
        foreach (var (name, backend) in _backends)
        {
            if (!await backend.PingAsync().ConfigureAwait(false))
                return false;
        }
        return true;
    }
}
