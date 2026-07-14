using RDRF.Core.DSAA.Abi;
using System.Runtime.InteropServices;

namespace RDRF.Core.DSAA.NativePlugin;

public class NativeBackendConfigFactory : IStorageBackendFactory
{
    public string Type => "native";

    public IStorageBackend Create(Dictionary<string, object> config)
    {
        string? libPath = config.TryGetValue("library", out var path)
            ? path?.ToString()
            : null;

        if (string.IsNullOrEmpty(libPath))
            throw new ArgumentException("'library' parameter is required for native backend");

        if (!File.Exists(libPath))
            throw new FileNotFoundException($"Native plugin library not found: {libPath}");

        IntPtr lib = DsaaStorageAbi.LoadLibrary(libPath);
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
            throw new InvalidOperationException($"Native plugin '{libPath}' missing required symbols (dsaa_storage_create/destroy)");

        var funcs = new NativeFunctions
        {
            LibraryHandle = lib,
            Create = create, Destroy = destroy,
            OpenWrite = openWrite, OpenRead = openRead,
            Delete = delete, Exists = exists, Ping = ping,
            StreamRead = streamRead, StreamWrite = streamWrite,
            StreamClose = streamClose,
        };

        string configJson = System.Text.Json.JsonSerializer.Serialize(config);
        var configPtr = Marshal.StringToCoTaskMemUTF8(configJson);
        try
        {
            IntPtr handle = create(configPtr);
            if (handle == IntPtr.Zero)
                throw new InvalidOperationException($"Native plugin '{libPath}' returned null handle");

            string name = Path.GetFileNameWithoutExtension(libPath);
            return new NativeStorageBackend(name, funcs, handle);
        }
        finally
        {
            Marshal.FreeCoTaskMem(configPtr);
        }
    }
}
