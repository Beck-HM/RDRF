using System.Runtime.InteropServices;

namespace RDRF.Core.DSAA.Abi;

public static class DsaaStorageAbi
{
    // -- Native library loading --
    public static IntPtr LoadLibrary(string path)
    {
        if (OperatingSystem.IsWindows())
            return NativeLibrary.Load(path);
        else
            return NativeLibrary.Load(path);
    }

    public static void UnloadLibrary(IntPtr lib)
    {
        NativeLibrary.Free(lib);
    }

    public static T? GetDelegate<T>(IntPtr lib, string name) where T : Delegate
    {
        if (NativeLibrary.TryGetExport(lib, name, out IntPtr ptr))
            return Marshal.GetDelegateForFunctionPointer<T>(ptr);
        return null;
    }

    // -- Delegates for storage plugin ABI --
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr CreateDelegate(IntPtr configJson);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void DestroyDelegate(IntPtr handle);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int OpenWriteDelegate(IntPtr handle, IntPtr path,
        long fileSize, out IntPtr outStream);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int OpenReadDelegate(IntPtr handle, IntPtr path,
        out IntPtr outStream);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int DeleteDelegate(IntPtr handle, IntPtr path);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int ExistsDelegate(IntPtr handle, IntPtr path,
        out bool outExists);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int PingDelegate(IntPtr handle, out bool outAlive);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate long StreamReadDelegate(IntPtr stream, byte[] buf, long count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate long StreamWriteDelegate(IntPtr stream, byte[] buf, long count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void StreamCloseDelegate(IntPtr stream);
}
