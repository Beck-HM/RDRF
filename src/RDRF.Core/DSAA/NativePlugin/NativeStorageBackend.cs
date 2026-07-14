using System.Runtime.InteropServices;
using RDRF.Core.DSAA.Abi;

namespace RDRF.Core.DSAA.NativePlugin;

public class NativeStorageBackend : IStorageBackend
{
    private readonly NativeFunctions _funcs;
    private readonly IntPtr _handle;
    private bool _disposed;

    public string Name { get; }

    public NativeStorageBackend(string name, NativeFunctions funcs, IntPtr handle)
    {
        Name = name;
        _funcs = funcs;
        _handle = handle;
    }

    public Task<Stream> OpenWriteAsync(string path, long fileSize,
        IProgress<StorageProgress>? progress = null)
    {
        var pathPtr = Marshal.StringToCoTaskMemUTF8(path);
        try
        {
            int result = _funcs.OpenWrite!(_handle, pathPtr, fileSize, out IntPtr stream);
            if (result != 0 || stream == IntPtr.Zero)
                throw new IOException($"Native open_write failed for '{path}'");
            return Task.FromResult<Stream>(
                new NativeWriteStream(stream, _funcs.StreamWrite!, _funcs.StreamClose!));
        }
        finally
        {
            Marshal.FreeCoTaskMem(pathPtr);
        }
    }

    public Task<Stream> OpenReadAsync(string path)
    {
        var pathPtr = Marshal.StringToCoTaskMemUTF8(path);
        try
        {
            int result = _funcs.OpenRead!(_handle, pathPtr, out IntPtr stream);
            if (result != 0 || stream == IntPtr.Zero)
                throw new FileNotFoundException($"Native open_read failed for '{path}'");
            return Task.FromResult<Stream>(
                new NativeReadStream(stream, _funcs.StreamRead!, _funcs.StreamClose!));
        }
        finally
        {
            Marshal.FreeCoTaskMem(pathPtr);
        }
    }

    public Task DeleteAsync(string path)
    {
        var pathPtr = Marshal.StringToCoTaskMemUTF8(path);
        try
        {
            _funcs.Delete!(_handle, pathPtr);
            return Task.CompletedTask;
        }
        finally
        {
            Marshal.FreeCoTaskMem(pathPtr);
        }
    }

    public Task<bool> ExistsAsync(string path)
    {
        var pathPtr = Marshal.StringToCoTaskMemUTF8(path);
        try
        {
            _funcs.Exists!(_handle, pathPtr, out bool result);
            return Task.FromResult(result);
        }
        finally
        {
            Marshal.FreeCoTaskMem(pathPtr);
        }
    }

    public Task<bool> PingAsync()
    {
        _funcs.Ping!(_handle, out bool alive);
        return Task.FromResult(alive);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _funcs.Destroy!(_handle);
            DsaaStorageAbi.UnloadLibrary(_funcs.LibraryHandle);
            _disposed = true;
        }
    }
}
