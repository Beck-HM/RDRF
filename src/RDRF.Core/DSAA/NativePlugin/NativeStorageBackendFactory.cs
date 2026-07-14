using System.Runtime.InteropServices;
using RDRF.Core.DSAA.Abi;

namespace RDRF.Core.DSAA.NativePlugin;

public class NativeStorageBackendFactory : IStorageBackendFactory
{
    private readonly string _libPath;
    private readonly NativeFunctions _funcs;

    public string Type => "native";

    public NativeStorageBackendFactory(string libPath, NativeFunctions funcs)
    {
        _libPath = libPath;
        _funcs = funcs;
    }

    public IStorageBackend Create(Dictionary<string, object> config)
    {
        string configJson = System.Text.Json.JsonSerializer.Serialize(config);
        var configPtr = Marshal.StringToCoTaskMemUTF8(configJson);
        try
        {
            IntPtr handle = _funcs.Create!(configPtr);
            if (handle == IntPtr.Zero)
                throw new InvalidOperationException($"Native plugin '{_libPath}' returned null handle");

            string name = Path.GetFileNameWithoutExtension(_libPath);
            return new NativeStorageBackend(name, _funcs, handle);
        }
        finally
        {
            Marshal.FreeCoTaskMem(configPtr);
        }
    }
}
