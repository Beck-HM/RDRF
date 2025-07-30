using System.Security.Cryptography;

namespace RDRF.Storage;

public class StorageOrchestrator
{
    private readonly List<string> _backendOrder = new();
    private readonly Dictionary<string, IStorageBackend> _backends = new();
    private readonly ManagementFile _management;

    public IReadOnlyList<string> BackendNames => _backendOrder;
    public ManagementFile Management => _management;

    public StorageOrchestrator(string? managementDir = null)
    {
        _management = new ManagementFile(managementDir);
    }

    public void RegisterBackend(string name, IStorageBackend backend)
    {
        ArgumentNullException.ThrowIfNull(backend);
        _backends[name] = backend;
        _backendOrder.Add(name);
    }

    public async Task<bool> PingAllAsync()
    {
        foreach (var (_, backend) in _backends)
            if (!await backend.PingAsync().ConfigureAwait(false))
                return false;
        return true;
    }

    public async Task WriteFragmentAsync(byte[] data, StorageUploadOptions options,
        IProgress<StorageProgress>? progress = null)
    {
        var backend = SelectBackend(options);
        var path = BuildPath(options.Fingerprint, options.FragmentCount, options.FragmentIndex);
        var hash = SHA256.HashData(data);
        var hashHex = Convert.ToHexString(hash).ToLowerInvariant();

        await using var stream = await backend.OpenWriteAsync(path, data.Length, progress)
            .ConfigureAwait(false);
        await stream.WriteAsync(data).ConfigureAwait(false);

        _management.RecordFragment(options.Fingerprint, options.FragmentCount,
            options.FragmentIndex, backend.Name, path, data.Length, hashHex, options.Note);
    }

    public async Task WriteRcAsync(byte[] data, StorageUploadOptions options,
        IProgress<StorageProgress>? progress = null)
    {
        var backend = SelectBackendForRc(options);
        var path = BuildRcPath(options.Fingerprint, options.FragmentCount);
        var hash = SHA256.HashData(data);
        var hashHex = Convert.ToHexString(hash).ToLowerInvariant();

        await using var stream = await backend.OpenWriteAsync(path, data.Length, progress)
            .ConfigureAwait(false);
        await stream.WriteAsync(data).ConfigureAwait(false);

        _management.RecordRc(options.Fingerprint, options.FragmentCount,
            backend.Name, path, data.Length, hashHex, options.Note);
    }

    public async Task<byte[]> ReadAllFragmentsAsync(string fingerprint, int version)
    {
        var records = _management.Lookup(fingerprint, version);
        var fragments = new byte[records.Count][];

        var tasks = records.Select(async record =>
        {
            if (!_backends.TryGetValue(record.BackendName, out var backend))
                throw new InvalidOperationException(
                    $"Backend '{record.BackendName}' not registered");

            await using var stream = await backend.OpenReadAsync(record.RemotePath)
                .ConfigureAwait(false);
            using var ms = new MemoryStream();
            await stream.CopyToAsync(ms).ConfigureAwait(false);
            return (record.FragmentIndex, Data: ms.ToArray());
        }).ToList();

        var results = await Task.WhenAll(tasks).ConfigureAwait(false);
        foreach (var (idx, data) in results.OrderBy(r => r.FragmentIndex))
            fragments[idx] = data;

        return fragments.SelectMany(f => f).ToArray();
    }

    public async Task<byte[]> ReadRcAsync(string fingerprint, int version)
    {
        var records = _management.Lookup(fingerprint, version);
        var rcRecord = records.FirstOrDefault(r => r.ContentType == "rc");
        if (rcRecord == null)
            throw new InvalidOperationException($"RC file not found for {fingerprint} v{version}");

        if (!_backends.TryGetValue(rcRecord.BackendName, out var backend))
            throw new InvalidOperationException(
                $"Backend '{rcRecord.BackendName}' not registered");

        await using var stream = await backend.OpenReadAsync(rcRecord.RemotePath)
            .ConfigureAwait(false);
        using var ms = new MemoryStream();
        await stream.CopyToAsync(ms).ConfigureAwait(false);
        return ms.ToArray();
    }

    public async Task<Stream> OpenFragmentStreamAsync(string fingerprint,
        int version, int fragmentIndex)
    {
        var record = _management.LookupSingle(fingerprint, version, fragmentIndex)
            ?? throw new InvalidOperationException(
                $"Fragment {fragmentIndex} not found for {fingerprint} v{version}");

        if (!_backends.TryGetValue(record.BackendName, out var backend))
            throw new InvalidOperationException(
                $"Backend '{record.BackendName}' not registered");

        return await backend.OpenReadAsync(record.RemotePath).ConfigureAwait(false);
    }

    public async Task DeleteVersionAsync(string fingerprint, int version)
    {
        var records = _management.Lookup(fingerprint, version);
        var errors = new List<string>();

        foreach (var record in records)
        {
            try
            {
                if (_backends.TryGetValue(record.BackendName, out var backend))
                    await backend.DeleteAsync(record.RemotePath).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                errors.Add($"{record.BackendName}/{record.RemotePath}: {ex.Message}");
            }
        }

        _management.DeleteVersion(fingerprint, version);

        if (errors.Count > 0)
            throw new AggregateException(
                $"Failed to delete some fragments for {fingerprint} v{version}", errors.Select(e => new Exception(e)));
    }

    private IStorageBackend SelectBackend(StorageUploadOptions options)
    {
        if (options.ForceBackend != null)
            return ResolveBackend(options.ForceBackend);

        var candidates = GetCandidates(options.ExcludeBackends);
        if (candidates.Count == 0)
            throw new InvalidOperationException("No available backends");

        if (options.FragmentCount <= 0 || candidates.Count == 0)
            return candidates[0];

        return candidates[options.FragmentIndex % candidates.Count];
    }

    private IStorageBackend SelectBackendForRc(StorageUploadOptions options)
    {
        if (options.ForceBackend != null)
            return ResolveBackend(options.ForceBackend);

        // RC goes to the first available backend
        var candidates = GetCandidates(options.ExcludeBackends);
        if (candidates.Count == 0)
            throw new InvalidOperationException("No available backends");
        return candidates[0];
    }

    private List<IStorageBackend> GetCandidates(List<string>? exclude)
    {
        if (_backendOrder.Count == 0)
            throw new InvalidOperationException("No backends registered");

        var excludeSet = exclude?.ToHashSet(StringComparer.OrdinalIgnoreCase)
            ?? new HashSet<string>();

        return _backendOrder
            .Where(n => !excludeSet.Contains(n))
            .Select(n => _backends[n])
            .ToList();
    }

    private IStorageBackend ResolveBackend(string name)
    {
        if (_backends.TryGetValue(name, out var backend))
            return backend;
        throw new InvalidOperationException($"Backend '{name}' not registered");
    }

    private static string BuildPath(string fingerprint, int version, int fragmentIndex)
        => $"{fingerprint}_v{version}_{fragmentIndex}.rdrf";

    private static string BuildRcPath(string fingerprint, int version)
        => $"{fingerprint}_v{version}.rdrc";
}
