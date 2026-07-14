using System.Runtime.InteropServices;
using RDRF.Core.DSAA.Abi;
using RDRF.Core.Logging;

namespace RDRF.Core.DSAA.NativePlugin;

public static class NativePluginLoader
{
    public static List<IStorageBackendFactory> Load(string directory)
    {
        var factories = new List<IStorageBackendFactory>();
        if (!Directory.Exists(directory)) return factories;

        foreach (string libPath in GetNativeLibraries(directory))
        {
            try
            {
                var factory = LoadSingle(libPath);
                if (factory != null)
                    factories.Add(factory);
            }
            catch (Exception ex)
            {
                RdrfLogger.Default.Warn("NativePluginLoader",
                    $"Failed to load native plugin '{Path.GetFileName(libPath)}': {ex.Message}");
            }
        }
        return factories;
    }

    private static IStorageBackendFactory? LoadSingle(string libPath)
    {
        IntPtr lib = DsaaStorageAbi.LoadLibrary(libPath);
        if (lib == IntPtr.Zero) return null;

        var create = DsaaStorageAbi.GetDelegate<DsaaStorageAbi.CreateDelegate>(lib, "dsaa_storage_create");
        var destroy = DsaaStorageAbi.GetDelegate<DsaaStorageAbi.DestroyDelegate>(lib, "dsaa_storage_destroy");
        var openWrite = DsaaStorageAbi.GetDelegate<DsaaStorageAbi.OpenWriteDelegate>(lib, "dsaa_open_write");
        var openRead = DsaaStorageAbi.GetDelegate<DsaaStorageAbi.OpenReadDelegate>(lib, "dsaa_open_read");
        var delete = DsaaStorageAbi.GetDelegate<DsaaStorageAbi.DeleteDelegate>(lib, "dsaa_delete");
        var exists = DsaaStorageAbi.GetDelegate<DsaaStorageAbi.ExistsDelegate>(lib, "dsaa_exists");
        var ping = DsaaStorageAbi.GetDelegate<DsaaStorageAbi.PingDelegate>(lib, "dsaa_ping");
        var streamRead = DsaaStorageAbi.GetDelegate<DsaaStorageAbi.StreamReadDelegate>(lib, "dsaa_stream_read");
        var streamWrite = DsaaStorageAbi.GetDelegate<DsaaStorageAbi.StreamWriteDelegate>(lib, "dsaa_stream_write");
        var streamClose = DsaaStorageAbi.GetDelegate<DsaaStorageAbi.StreamCloseDelegate>(lib, "dsaa_stream_close");

        if (create == null || destroy == null)
        {
            DsaaStorageAbi.UnloadLibrary(lib);
            return null;
        }

        var functions = new NativeFunctions
        {
            Create = create,
            Destroy = destroy,
            OpenWrite = openWrite,
            OpenRead = openRead,
            Delete = delete,
            Exists = exists,
            Ping = ping,
            StreamRead = streamRead,
            StreamWrite = streamWrite,
            StreamClose = streamClose,
            LibraryHandle = lib,
        };

        return new NativeStorageBackendFactory(libPath, functions);
    }

    private static string[] GetNativeLibraries(string directory)
    {
        var patterns = OperatingSystem.IsWindows()
            ? new[] { "*.dll" }
            : OperatingSystem.IsMacOS()
                ? new[] { "*.dylib", "*.so" }
                : new[] { "*.so" };

        var files = new List<string>();
        foreach (var pattern in patterns)
        {
            foreach (var f in Directory.GetFiles(directory, pattern))
            {
                // Skip .NET assemblies (managed DLLs have a 4-byte DOS header + 'MZ')
                try
                {
                    using var fs = new FileStream(f, FileMode.Open, FileAccess.Read);
                    byte[] header = new byte[2];
                    if (fs.Read(header, 0, 2) == 2 && header[0] == 0x4D && header[1] == 0x5A)
                    {
                        // Check if it's .NET by looking for the PE signature
                        fs.Seek(0x3C, SeekOrigin.Begin);
                        byte[] peOff = new byte[4];
                        fs.Read(peOff, 0, 4);
                        int peOffset = BitConverter.ToInt32(peOff, 0);
                        fs.Seek(peOffset, SeekOrigin.Begin);
                        byte[] peSig = new byte[4];
                        fs.Read(peSig, 0, 4);
                        if (peSig[0] == 0x50 && peSig[1] == 0x45) // "PE\0\0"
                            continue; // .NET assembly, skip
                    }
                }
                catch { /* best effort */ }
                files.Add(f);
            }
        }
        return files.ToArray();
    }
}

public class NativeFunctions
{
    public IntPtr LibraryHandle { get; set; }
    public DsaaStorageAbi.CreateDelegate? Create { get; set; }
    public DsaaStorageAbi.DestroyDelegate? Destroy { get; set; }
    public DsaaStorageAbi.OpenWriteDelegate? OpenWrite { get; set; }
    public DsaaStorageAbi.OpenReadDelegate? OpenRead { get; set; }
    public DsaaStorageAbi.DeleteDelegate? Delete { get; set; }
    public DsaaStorageAbi.ExistsDelegate? Exists { get; set; }
    public DsaaStorageAbi.PingDelegate? Ping { get; set; }
    public DsaaStorageAbi.StreamReadDelegate? StreamRead { get; set; }
    public DsaaStorageAbi.StreamWriteDelegate? StreamWrite { get; set; }
    public DsaaStorageAbi.StreamCloseDelegate? StreamClose { get; set; }
}
