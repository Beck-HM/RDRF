namespace RDRF.Core.Dssa;

public abstract class DssaAdapter
{
    // ── Synchronous API ──
    public abstract byte[] ReadFragment(string filename);
    public abstract void WriteFragment(string filename, byte[] data);
    public abstract bool FragmentExists(string filename);
    public abstract void DeleteFragment(string filename);
    public abstract List<string> ListFragments();
    public abstract byte[] ReadIndex(string fileFingerprint);
    public abstract void WriteIndex(string fileFingerprint, byte[] data);
    public abstract bool IndexExists(string fileFingerprint);
    public abstract byte[] ReadRc(string fileFingerprint);
    public abstract void WriteRc(string fileFingerprint, byte[] data);
    public abstract bool RcExists(string fileFingerprint);

    // ── Asynchronous API (defaults fall back to sync) ──
    public virtual Task<byte[]> ReadFragmentAsync(string filename, CancellationToken ct = default)
        => Task.Run(() => ReadFragment(filename), ct);
    public virtual Task WriteFragmentAsync(string filename, byte[] data, CancellationToken ct = default)
        => Task.Run(() => WriteFragment(filename, data), ct);
    public virtual Task<bool> FragmentExistsAsync(string filename, CancellationToken ct = default)
        => Task.Run(() => FragmentExists(filename), ct);
    public virtual Task<byte[]> ReadIndexAsync(string fileFingerprint, CancellationToken ct = default)
        => Task.FromResult(ReadIndex(fileFingerprint));
    public virtual Task WriteIndexAsync(string fileFingerprint, byte[] data, CancellationToken ct = default)
    { WriteIndex(fileFingerprint, data); return Task.CompletedTask; }
    public virtual Task<bool> IndexExistsAsync(string fileFingerprint, CancellationToken ct = default)
        => Task.FromResult(IndexExists(fileFingerprint));
    public virtual Task<byte[]> ReadRcAsync(string fileFingerprint, CancellationToken ct = default)
        => Task.FromResult(ReadRc(fileFingerprint));
    public virtual Task WriteRcAsync(string fileFingerprint, byte[] data, CancellationToken ct = default)
    { WriteRc(fileFingerprint, data); return Task.CompletedTask; }
    public virtual Task<bool> RcExistsAsync(string fileFingerprint, CancellationToken ct = default)
        => Task.FromResult(RcExists(fileFingerprint));

    // ── Stream-based API ──
    public virtual Stream OpenReadFragment(string filename)
        => throw new NotSupportedException();
    public virtual Stream OpenWriteFragment(string filename)
        => throw new NotSupportedException();
}

/// <summary>
/// Abstract DssaAdapter + LocalDssaAdapter for local filesystem fragment/index/RC storage.
/// </summary>

public class LocalDssaAdapter : DssaAdapter
{
    private readonly string _basePath;

    public LocalDssaAdapter(string basePath)
    {
        _basePath = basePath ?? throw new ArgumentNullException(nameof(basePath));
        Directory.CreateDirectory(_basePath);
    }

    private static string ResolvePath(string basePath, string filename)
    {
        if (string.IsNullOrEmpty(filename))
            throw new ArgumentException("Filename must not be null or empty.", nameof(filename));
        if (filename.Contains('/') || filename.Contains('\\'))
            throw new ArgumentException("Filename must not contain directory separators.", nameof(filename));
        if (filename.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            throw new ArgumentException("Filename contains invalid characters.", nameof(filename));

        string full = Path.GetFullPath(Path.Combine(basePath, filename));
        string baseFull = Path.GetFullPath(basePath) + Path.DirectorySeparatorChar;
        if (!full.StartsWith(baseFull, StringComparison.Ordinal))
            throw new ArgumentException("Path traversal detected.", nameof(filename));
        return full;
    }

    public override byte[] ReadFragment(string filename)
    {
        return File.ReadAllBytes(ResolvePath(_basePath, filename));
    }

    public override void WriteFragment(string filename, byte[] data)
    {
        string path = ResolvePath(_basePath, filename);
        string tmp = Path.Combine(_basePath, Path.GetRandomFileName());
        try
        {
            File.WriteAllBytes(tmp, data);
            File.Move(tmp, path, overwrite: true);
        }
        catch
        {
            try { File.Delete(tmp); } catch { }
            throw;
        }
    }

    public override bool FragmentExists(string filename)
        => File.Exists(ResolvePath(_basePath, filename));

    public override async Task<byte[]> ReadFragmentAsync(string filename, CancellationToken ct = default)
        => await File.ReadAllBytesAsync(ResolvePath(_basePath, filename), ct).ConfigureAwait(false);

    public override async Task WriteFragmentAsync(string filename, byte[] data, CancellationToken ct = default)
        => await File.WriteAllBytesAsync(ResolvePath(_basePath, filename), data, ct).ConfigureAwait(false);

    public override Task<bool> FragmentExistsAsync(string filename, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        return Task.FromResult(File.Exists(ResolvePath(_basePath, filename)));
    }

    public override void DeleteFragment(string filename)
    {
        string full = ResolvePath(_basePath, filename);
        if (File.Exists(full)) File.Delete(full);
    }

    public override List<string> ListFragments()
    {
        if (!Directory.Exists(_basePath)) return new List<string>();
        return Directory.GetFiles(_basePath, "*.rdrf")
            .Select(Path.GetFileName)
            .Where(f => f != null && !f.EndsWith(".indrdrf"))
            .Select(f => f!)
            .ToList();
    }

    public override byte[] ReadIndex(string fileFingerprint)
        => File.ReadAllBytes(ResolvePath(_basePath, fileFingerprint + Constants.IndexFileSuffix));

    public override void WriteIndex(string fileFingerprint, byte[] data)
        => File.WriteAllBytes(ResolvePath(_basePath, fileFingerprint + Constants.IndexFileSuffix), data);

    public override bool IndexExists(string fileFingerprint)
        => File.Exists(ResolvePath(_basePath, fileFingerprint + Constants.IndexFileSuffix));

    public override async Task<byte[]> ReadIndexAsync(string fileFingerprint, CancellationToken ct = default)
        => await File.ReadAllBytesAsync(ResolvePath(_basePath, fileFingerprint + Constants.IndexFileSuffix), ct).ConfigureAwait(false);

    public override async Task WriteIndexAsync(string fileFingerprint, byte[] data, CancellationToken ct = default)
        => await File.WriteAllBytesAsync(ResolvePath(_basePath, fileFingerprint + Constants.IndexFileSuffix), data, ct).ConfigureAwait(false);

    public override Task<bool> IndexExistsAsync(string fileFingerprint, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        return Task.FromResult(File.Exists(ResolvePath(_basePath, fileFingerprint + Constants.IndexFileSuffix)));
    }

    // ── RC (cross-validation) file methods ──

    public override byte[] ReadRc(string fileFingerprint)
        => File.ReadAllBytes(ResolvePath(_basePath, fileFingerprint + Constants.RcFileSuffix));

    public override void WriteRc(string fileFingerprint, byte[] data)
        => File.WriteAllBytes(ResolvePath(_basePath, fileFingerprint + Constants.RcFileSuffix), data);

    public override bool RcExists(string fileFingerprint)
        => File.Exists(ResolvePath(_basePath, fileFingerprint + Constants.RcFileSuffix));

    // ── Stream-based overrides ──

    public override Stream OpenReadFragment(string filename)
        => File.OpenRead(ResolvePath(_basePath, filename));

    public override Stream OpenWriteFragment(string filename)
        => File.OpenWrite(ResolvePath(_basePath, filename));

    public string GetBasePath() => _basePath;
}

