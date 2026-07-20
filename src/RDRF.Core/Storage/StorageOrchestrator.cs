using RDRF.Core.Abstractions;
using System.Security.Cryptography;

namespace RDRF.Core.DSAA;

/// <summary>
/// Multi-backend fragment orchestration: write, read, delete, ping across registered backends.
/// </summary>

public class StorageOrchestrator
{
    private readonly List<string> _backendOrder = new();
    private readonly Dictionary<string, IStorageBackend> _backends = new();
    private readonly Dictionary<IStorageBackend, string> _backendNames = new();
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
        _backendNames[backend] = name;
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
        EnsureConfigured(options);
        var backend = SelectBackend(options);
        var path = BuildPath(options.Fingerprint, options.VersionNumber, options.FragmentIndex);
        var hash = SHA256.HashData(data);
        var hashHex = Hex.EncodeLower(hash);

        await using var stream = await backend.OpenWriteAsync(path, data.Length, progress)
            .ConfigureAwait(false);
        await stream.WriteAsync(data).ConfigureAwait(false);

        _management.RecordFragment(options.Fingerprint, options.VersionNumber,
            options.FragmentIndex, _backendNames[backend], path, data.Length, hashHex, options.Note);
    }

    /// <summary>
    /// Stream a local file to remote (hash-while-copy; no full-file buffer).
    /// </summary>
    public async Task WriteFragmentFromFileAsync(string localPath, StorageUploadOptions options,
        IProgress<StorageProgress>? progress = null, CancellationToken ct = default)
    {
        EnsureConfigured(options);
        var backend = SelectBackend(options);
        var path = BuildPath(options.Fingerprint, options.VersionNumber, options.FragmentIndex);
        long size = new FileInfo(localPath).Length;
        if (options.FileSize <= 0)
            options.FileSize = size;

        await using var input = new FileStream(localPath, FileMode.Open, FileAccess.Read, FileShare.Read,
            256 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        await using var remote = await backend.OpenWriteAsync(path, size, progress).ConfigureAwait(false);
        await CopyAndHashAsync(input, remote, hasher, ct).ConfigureAwait(false);
        var hashHex = Hex.EncodeLower(hasher.GetHashAndReset());

        _management.RecordFragment(options.Fingerprint, options.VersionNumber,
            options.FragmentIndex, _backendNames[backend], path, size, hashHex, options.Note);
    }

    public async Task WriteRcAsync(byte[] data, StorageUploadOptions options,
        IProgress<StorageProgress>? progress = null)
    {
        EnsureConfigured(options);
        var backend = SelectBackendForRc(options);
        var path = BuildRcPath(options.Fingerprint, options.VersionNumber);
        var hash = SHA256.HashData(data);
        var hashHex = Hex.EncodeLower(hash);

        await using var stream = await backend.OpenWriteAsync(path, data.Length, progress)
            .ConfigureAwait(false);
        await stream.WriteAsync(data).ConfigureAwait(false);

        _management.RecordRc(options.Fingerprint, options.VersionNumber,
            _backendNames[backend], path, data.Length, hashHex, options.Note);
    }

    /// <summary>
    /// Stream a local RC file to remote (hash-while-copy; no full-file buffer).
    /// </summary>
    public async Task WriteRcFromFileAsync(string localPath, StorageUploadOptions options,
        IProgress<StorageProgress>? progress = null, CancellationToken ct = default)
    {
        EnsureConfigured(options);
        var backend = SelectBackendForRc(options);
        var path = BuildRcPath(options.Fingerprint, options.VersionNumber);
        long size = new FileInfo(localPath).Length;
        if (options.FileSize <= 0)
            options.FileSize = size;

        await using var input = new FileStream(localPath, FileMode.Open, FileAccess.Read, FileShare.Read,
            256 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        await using var remote = await backend.OpenWriteAsync(path, size, progress).ConfigureAwait(false);
        await CopyAndHashAsync(input, remote, hasher, ct).ConfigureAwait(false);
        var hashHex = Hex.EncodeLower(hasher.GetHashAndReset());

        _management.RecordRc(options.Fingerprint, options.VersionNumber,
            _backendNames[backend], path, size, hashHex, options.Note);
    }

    private static async Task CopyAndHashAsync(Stream input, Stream output, IncrementalHash hasher,
        CancellationToken ct)
    {
        var buffer = new byte[256 * 1024];
        int read;
        while ((read = await input.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false)) > 0)
        {
            hasher.AppendData(buffer.AsSpan(0, read));
            await output.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
        }
    }

    public async Task<byte[]> ReadAllFragmentsAsync(string fingerprint, int version)
    {
        var records = _management.Lookup(fingerprint, version);
        var fragments = new Dictionary<int, byte[]>();

        var tasks = records.Select(async record =>
        {
            if (!_backends.TryGetValue(record.BackendName, out var backend))
                throw new RdrfException(ErrorCode.StorageBackendUnavailable, 
                    $"Backend '{record.BackendName}' not registered");

            await using var stream = await backend.OpenReadAsync(record.RemotePath)
                .ConfigureAwait(false);
            using var ms = new MemoryStream();
            await stream.CopyToAsync(ms).ConfigureAwait(false);
            return (record.FragmentIndex, Data: ms.ToArray());
        }).ToList();

        var results = await Task.WhenAll(tasks).ConfigureAwait(false);
        foreach (var (idx, data) in results)
            fragments[idx] = data;

        return fragments.OrderBy(k => k.Key).SelectMany(kv => kv.Value).ToArray();
    }

    public async Task<byte[]> ReadRcAsync(string fingerprint, int version)
    {
        var records = _management.Lookup(fingerprint, version);
        var rcRecord = records.FirstOrDefault(r => r.ContentType == "rc");
        if (rcRecord == null)
            throw new RdrfException(ErrorCode.StorageBackendUnavailable, $"RC file not found for {fingerprint} v{version}");

        if (!_backends.TryGetValue(rcRecord.BackendName, out var backend))
            throw new RdrfException(ErrorCode.StorageBackendUnavailable, 
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
            ?? throw new RdrfException(ErrorCode.StorageBackendUnavailable, 
                $"Fragment {fragmentIndex} not found for {fingerprint} v{version}");

        if (!_backends.TryGetValue(record.BackendName, out var backend))
            throw new RdrfException(ErrorCode.StorageBackendUnavailable, 
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

    private void EnsureConfigured(StorageUploadOptions options)
    {
        if (options.Backends != null)
        {
            foreach (var name in options.Backends)
            {
                if (!_backends.TryGetValue(name, out var backend))
                    throw new RdrfException(ErrorCode.StorageBackendUnavailable, 
                        $"Backend '{name}' not registered. Call RegisterBackend first.");

                var existing = _management.GetRemote(name);
                if (existing == null)
                {
                    var overrides = options.BackendOverrides?.GetValueOrDefault(name);
                    var config = overrides ?? new Dictionary<string, string>(
                        StringComparer.OrdinalIgnoreCase);
                    _management.RecordRemote(name, name, config);
                }
            }
        }
    }

    private IStorageBackend SelectBackend(StorageUploadOptions options)
    {
        if (options.ForceBackend != null)
            return ResolveBackend(options.ForceBackend);

        var candidates = GetCandidates(options.Backends, options.ExcludeBackends);
        if (candidates.Count == 0)
            throw new RdrfException(ErrorCode.StorageBackendUnavailable, "No available backends");

        if (options.FragmentCount <= 0)
            return candidates[0];

        int idx = options.FragmentIndex <= 0 ? 0 : options.FragmentIndex % candidates.Count;
        return candidates[idx];
    }

    private IStorageBackend SelectBackendForRc(StorageUploadOptions options)
    {
        if (options.ForceBackend != null)
            return ResolveBackend(options.ForceBackend);

        var candidates = GetCandidates(options.Backends, options.ExcludeBackends);
        if (candidates.Count == 0)
            throw new RdrfException(ErrorCode.StorageBackendUnavailable, "No available backends");
        return candidates[0];
    }

    private List<IStorageBackend> GetCandidates(List<string>? backends,
        List<string>? exclude)
    {
        var names = backends ?? _backendOrder;

        if (names.Count == 0)
            throw new RdrfException(ErrorCode.StorageBackendUnavailable, "No backends specified");

        var excludeSet = exclude?.ToHashSet(StringComparer.OrdinalIgnoreCase)
            ?? new HashSet<string>();

        return names
            .Where(n => !excludeSet.Contains(n) && _backends.ContainsKey(n))
            .Select(n => _backends[n])
            .ToList();
    }

    private IStorageBackend ResolveBackend(string name)
    {
        if (_backends.TryGetValue(name, out var backend))
            return backend;
        throw new RdrfException(ErrorCode.StorageBackendUnavailable, $"Backend '{name}' not registered");
    }

    private static string BuildPath(string fingerprint, int version, int fragmentIndex)
        => $"{fingerprint}_v{version}_{fragmentIndex}.rdrf";

    private static string BuildRcPath(string fingerprint, int version)
        => $"{fingerprint}_v{version}.rdrc";
}



