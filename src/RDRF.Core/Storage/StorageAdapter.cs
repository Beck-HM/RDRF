using System.Diagnostics;

namespace RDRF.Core.DSAA;

public abstract class DSAAAdapter
{
    // -- Synchronous API --
    public abstract byte[] ReadFragment(string filename);
    public abstract void WriteFragment(string filename, byte[] data);
    public abstract bool FragmentExists(string filename);
    public abstract void DeleteFragment(string filename);
    public abstract List<string> ListFragments();
    public abstract byte[] ReadIndex(string fileFingerprint);
    public abstract void WriteIndex(string fileFingerprint, byte[] data);
    public abstract bool IndexExists(string fileFingerprint);
    public virtual void DeleteIndex(string fileFingerprint)
        => DeleteFragment(fileFingerprint + Constants.IndexFileSuffix);
    public abstract byte[] ReadRc(string fileFingerprint);
    public abstract void WriteRc(string fileFingerprint, byte[] data);
    public abstract bool RcExists(string fileFingerprint);
    public virtual void DeleteRc(string fileFingerprint)
        => DeleteFragment(fileFingerprint + Constants.RcFileSuffix);

    // -- Asynchronous API (defaults fall back to sync) --
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

    // -- Stream-based API --
    public virtual string? FindLatestIndex() => null;

    public virtual Stream OpenReadFragment(string filename)
        => new MemoryStream(ReadFragment(filename));

    public virtual Stream OpenWriteFragment(string filename)
        => new WriteBackMemoryStream(data => WriteFragment(filename, data));

    /// <summary>
    /// Open fragment for sequential read (async-friendly FileStream on local).
    /// Caller must dispose the stream.
    /// </summary>
    public virtual Task<Stream> OpenReadFragmentAsync(string filename, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        return Task.FromResult(OpenReadFragment(filename));
    }

    /// <summary>
    /// Write a fragment via a producer that streams into a temp file then atomic-moves.
    /// Default: buffer producer into MemoryStream then WriteFragment.
    /// </summary>
    public virtual async Task WriteFragmentViaStreamAsync(
        string filename, Func<Stream, CancellationToken, Task> producer, CancellationToken ct = default)
    {
        await using var ms = new MemoryStream();
        await producer(ms, ct).ConfigureAwait(false);
        await WriteFragmentAsync(filename, ms.ToArray(), ct).ConfigureAwait(false);
    }
}

internal sealed class WriteBackMemoryStream : MemoryStream
{
    private readonly Action<byte[]> _onClose;

    public WriteBackMemoryStream(Action<byte[]> onClose)
    {
        _onClose = onClose;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _onClose(ToArray());
        }
        base.Dispose(disposing);
    }
}

/// <summary>
/// Abstract DSAAAdapter + LocalDSAAAdapter for local filesystem fragment/index/RC storage.
/// </summary>

public class LocalDSAAAdapter : DSAAAdapter
{
    private readonly string _basePath;

    public LocalDSAAAdapter(string basePath)
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
            try { File.Delete(tmp); } catch (Exception ex) { Debug.WriteLine($"[LocalDSAAAdapter] Cleanup failed: {ex.Message}"); }
            throw;
        }
    }

    public override bool FragmentExists(string filename)
        => File.Exists(ResolvePath(_basePath, filename));

    public override async Task<byte[]> ReadFragmentAsync(string filename, CancellationToken ct = default)
        => await File.ReadAllBytesAsync(ResolvePath(_basePath, filename), ct).ConfigureAwait(false);

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
    {
        string path = ResolvePath(_basePath, fileFingerprint + Constants.IndexFileSuffix);
        string tmp = Path.Combine(_basePath, Path.GetRandomFileName());
        try
        {
            File.WriteAllBytes(tmp, data);
            File.Move(tmp, path, overwrite: true);
        }
        catch
        {
            try { File.Delete(tmp); } catch (Exception ex) { Debug.WriteLine($"[LocalDSAAAdapter] Cleanup failed: {ex.Message}"); }
            throw;
        }
    }

    public override bool IndexExists(string fileFingerprint)
        => File.Exists(ResolvePath(_basePath, fileFingerprint + Constants.IndexFileSuffix));

    public override async Task<byte[]> ReadIndexAsync(string fileFingerprint, CancellationToken ct = default)
        => await File.ReadAllBytesAsync(ResolvePath(_basePath, fileFingerprint + Constants.IndexFileSuffix), ct).ConfigureAwait(false);

    public override async Task WriteIndexAsync(string fileFingerprint, byte[] data, CancellationToken ct = default)
    {
        string path = ResolvePath(_basePath, fileFingerprint + Constants.IndexFileSuffix);
        string tmp = Path.Combine(_basePath, Path.GetRandomFileName());
        try
        {
            await File.WriteAllBytesAsync(tmp, data, ct).ConfigureAwait(false);
            File.Move(tmp, path, overwrite: true);
        }
        catch
        {
            try { File.Delete(tmp); } catch (Exception ex) { Debug.WriteLine($"[LocalDSAAAdapter] Cleanup failed: {ex.Message}"); }
            throw;
        }
    }

    public override Task<bool> IndexExistsAsync(string fileFingerprint, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        return Task.FromResult(File.Exists(ResolvePath(_basePath, fileFingerprint + Constants.IndexFileSuffix)));
    }

    // -- RC (cross-validation) file methods --

    public override byte[] ReadRc(string fileFingerprint)
        => File.ReadAllBytes(ResolvePath(_basePath, fileFingerprint + Constants.RcFileSuffix));

    public override void WriteRc(string fileFingerprint, byte[] data)
    {
        string path = ResolvePath(_basePath, fileFingerprint + Constants.RcFileSuffix);
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

    public override bool RcExists(string fileFingerprint)
        => File.Exists(ResolvePath(_basePath, fileFingerprint + Constants.RcFileSuffix));

    public override void DeleteIndex(string fileFingerprint)
    {
        string path = ResolvePath(_basePath, fileFingerprint + Constants.IndexFileSuffix);
        if (File.Exists(path)) File.Delete(path);
    }

    public override void DeleteRc(string fileFingerprint)
    {
        string path = ResolvePath(_basePath, fileFingerprint + Constants.RcFileSuffix);
        if (File.Exists(path)) File.Delete(path);
    }

    // -- Stream-based overrides --

    public override Stream OpenReadFragment(string filename)
        => new FileStream(ResolvePath(_basePath, filename), FileMode.Open, FileAccess.Read, FileShare.Read,
            256 * 1024, FileOptions.SequentialScan);

    public override Stream OpenWriteFragment(string filename)
        => File.OpenWrite(ResolvePath(_basePath, filename));

    public override Task<Stream> OpenReadFragmentAsync(string filename, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        Stream s = new FileStream(ResolvePath(_basePath, filename), FileMode.Open, FileAccess.Read, FileShare.Read,
            256 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        return Task.FromResult(s);
    }

    public override async Task WriteFragmentViaStreamAsync(
        string filename, Func<Stream, CancellationToken, Task> producer, CancellationToken ct = default)
    {
        string path = ResolvePath(_basePath, filename);
        string tmp = Path.Combine(_basePath, Path.GetRandomFileName());
        try
        {
            await using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None,
                256 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                await producer(fs, ct).ConfigureAwait(false);
                await fs.FlushAsync(ct).ConfigureAwait(false);
            }
            File.Move(tmp, path, overwrite: true);
        }
        catch
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch (Exception ex) { Debug.WriteLine($"[LocalDSAAAdapter] Cleanup failed: {ex.Message}"); }
            throw;
        }
    }

    public override async Task WriteFragmentAsync(string filename, byte[] data, CancellationToken ct = default)
    {
        // Stream write via FileStream (same atomic tmp+move; avoids WriteAllBytes intermediate copies).
        string path = ResolvePath(_basePath, filename);
        string tmp = Path.Combine(_basePath, Path.GetRandomFileName());
        try
        {
            await using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None,
                256 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                await fs.WriteAsync(data.AsMemory(0, data.Length), ct).ConfigureAwait(false);
                await fs.FlushAsync(ct).ConfigureAwait(false);
            }
            File.Move(tmp, path, overwrite: true);
        }
        catch
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch (Exception ex) { Debug.WriteLine($"[LocalDSAAAdapter] Cleanup failed: {ex.Message}"); }
            throw;
        }
    }

    public override string? FindLatestIndex()
    {
        string dir = _basePath;
        if (!Directory.Exists(dir)) return null;
        return Directory.GetFiles(dir, "*" + Constants.IndexFileSuffix)
            .OrderByDescending(f => File.GetLastWriteTime(f))
            .Select(f => Path.GetFileNameWithoutExtension(f))
            .FirstOrDefault();
    }

    public string GetBasePath() => _basePath;
}


