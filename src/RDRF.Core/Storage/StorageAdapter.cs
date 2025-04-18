namespace RDRF.Core.Storage;

public abstract class StorageAdapter
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

public class LocalFileAdapter : StorageAdapter
{
    private readonly string _basePath;

    public LocalFileAdapter(string basePath)
    {
        _basePath = basePath ?? throw new ArgumentNullException(nameof(basePath));
        Directory.CreateDirectory(_basePath);
    }

    private static void ValidateFilename(string filename)
    {
        if (string.IsNullOrEmpty(filename))
            throw new ArgumentException("Filename must not be null or empty.", nameof(filename));
        if (filename.Contains(".."))
            throw new ArgumentException("Filename must not contain '..' (path traversal).", nameof(filename));
        if (filename.Contains('/') || filename.Contains('\\'))
            throw new ArgumentException("Filename must not contain directory separators.", nameof(filename));
        if (filename.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            throw new ArgumentException("Filename contains invalid characters.", nameof(filename));
    }

    public override byte[] ReadFragment(string filename)
    {
        ValidateFilename(filename);
        return File.ReadAllBytes(Path.Combine(_basePath, filename));
    }

    public override void WriteFragment(string filename, byte[] data)
    {
        ValidateFilename(filename);
        File.WriteAllBytes(Path.Combine(_basePath, filename), data);
    }

    public override bool FragmentExists(string filename)
    {
        ValidateFilename(filename);
        return File.Exists(Path.Combine(_basePath, filename));
    }

    public override void DeleteFragment(string filename)
    {
        ValidateFilename(filename);
        string path = Path.Combine(_basePath, filename);
        if (File.Exists(path)) File.Delete(path);
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
    {
        string filename = fileFingerprint + Constants.IndexFileSuffix;
        ValidateFilename(filename);
        return File.ReadAllBytes(Path.Combine(_basePath, filename));
    }

    public override void WriteIndex(string fileFingerprint, byte[] data)
    {
        string filename = fileFingerprint + Constants.IndexFileSuffix;
        ValidateFilename(filename);
        File.WriteAllBytes(Path.Combine(_basePath, filename), data);
    }

    public override bool IndexExists(string fileFingerprint)
    {
        string filename = fileFingerprint + Constants.IndexFileSuffix;
        ValidateFilename(filename);
        return File.Exists(Path.Combine(_basePath, filename));
    }

    public override async Task<byte[]> ReadIndexAsync(string fileFingerprint, CancellationToken ct = default)
    {
        string filename = fileFingerprint + Constants.IndexFileSuffix;
        ValidateFilename(filename);
        string path = Path.Combine(_basePath, filename);
        return await File.ReadAllBytesAsync(path, ct).ConfigureAwait(false);
    }

    public override async Task WriteIndexAsync(string fileFingerprint, byte[] data, CancellationToken ct = default)
    {
        string filename = fileFingerprint + Constants.IndexFileSuffix;
        ValidateFilename(filename);
        string path = Path.Combine(_basePath, filename);
        await File.WriteAllBytesAsync(path, data, ct).ConfigureAwait(false);
    }

    public override Task<bool> IndexExistsAsync(string fileFingerprint, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        string filename = fileFingerprint + Constants.IndexFileSuffix;
        ValidateFilename(filename);
        string path = Path.Combine(_basePath, filename);
        return Task.FromResult(File.Exists(path));
    }

    // ── RC (cross-validation) file methods ──

    public override byte[] ReadRc(string fileFingerprint)
    {
        string filename = fileFingerprint + Constants.RcFileSuffix;
        ValidateFilename(filename);
        return File.ReadAllBytes(Path.Combine(_basePath, filename));
    }

    public override void WriteRc(string fileFingerprint, byte[] data)
    {
        string filename = fileFingerprint + Constants.RcFileSuffix;
        ValidateFilename(filename);
        File.WriteAllBytes(Path.Combine(_basePath, filename), data);
    }

    public override bool RcExists(string fileFingerprint)
    {
        string filename = fileFingerprint + Constants.RcFileSuffix;
        ValidateFilename(filename);
        return File.Exists(Path.Combine(_basePath, filename));
    }

    // ── Stream-based overrides ──

    public override Stream OpenReadFragment(string filename)
    {
        ValidateFilename(filename);
        return File.OpenRead(Path.Combine(_basePath, filename));
    }

    public override Stream OpenWriteFragment(string filename)
    {
        ValidateFilename(filename);
        return File.OpenWrite(Path.Combine(_basePath, filename));
    }

    public string GetBasePath() => _basePath;
}
