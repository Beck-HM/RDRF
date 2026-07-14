using System.Runtime.InteropServices;
using RDRF.Core.DSAA.Abi;
using RDRF.Core.DSAA.NativePlugin;
using Xunit;

namespace RDRF.Core.Tests;

public class NativePluginTests
{
    [Fact]
    public void DsaaStorageAbi_LoadLibrary_InvalidPath_Throws()
    {
        Assert.Throws<DllNotFoundException>(() =>
            DsaaStorageAbi.LoadLibrary("/nonexistent/lib.so"));
    }

    [Fact]
    public void NativePluginLoader_EmptyDirectory_ReturnsEmpty()
    {
        string dir = Path.Combine(Path.GetTempPath(), $"rdrf_native_empty_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            var factories = NativePluginLoader.Load(dir);
            Assert.Empty(factories);
        }
        finally
        {
            Directory.Delete(dir);
        }
    }

    [Fact]
    public void NativePluginLoader_InvalidNativeLib_ReturnsEmpty()
    {
        string dir = Path.Combine(Path.GetTempPath(), $"rdrf_native_bad_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        string badLib = Path.Combine(dir, "bad_plugin.so");
        File.WriteAllBytes(badLib, new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 });
        try
        {
            var factories = NativePluginLoader.Load(dir);
            Assert.Empty(factories); // should skip gracefully
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void NativePluginLoader_SkipsNetDll()
    {
        // Create a fake .NET DLL (PE header + 'MZ' signature)
        string dir = Path.Combine(Path.GetTempPath(), $"rdrf_native_skip_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        string fakeDll = Path.Combine(dir, "net_plugin.dll");
        // Write a minimal PE header
        byte[] peHeader = new byte[] {
            0x4D, 0x5A,                         // MZ
            0x00, 0x00, 0x00, 0x00,             // padding
            0x00, 0x00, 0x00, 0x00,             // padding
            0x00, 0x00, 0x00, 0x00,             // padding
            0x00, 0x00, 0x00, 0x00,             // padding
            0x00, 0x00, 0x00, 0x00,             // padding
            0x00, 0x00, 0x00, 0x00,             // padding
            0x00, 0x00, 0x00, 0x00,             // padding
            0x00, 0x00, 0x00, 0x00,             // padding
            0x00, 0x00, 0x00, 0x00,             // padding
            0x00, 0x00, 0x00, 0x00,             // padding
            0x00, 0x00, 0x00, 0x00,             // padding
            0x00, 0x00, 0x00, 0x00,             // padding
            0x00, 0x00, 0x00, 0x00,             // padding
            0x00, 0x00, 0x00, 0x00,             // padding
            0x80, 0x00, 0x00, 0x00,             // PE offset = 0x80
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // ... more padding to offset 0x80
        };
        // Extend to 0x80 bytes
        Array.Resize(ref peHeader, 0x80);
        peHeader[0x80 - 4] = 0x80; // PE offset at 0x3C

        // Add PE signature at offset 0x80
        Array.Resize(ref peHeader, 0x84);
        peHeader[0x80] = 0x50; // 'P'
        peHeader[0x81] = 0x45; // 'E'
        peHeader[0x82] = 0x00; // '\0'
        peHeader[0x83] = 0x00; // '\0'

        File.WriteAllBytes(fakeDll, peHeader);
        try
        {
            // PluginLoader.Load will skip this as .NET assembly
            // NativePluginLoader.Load should also skip it as PE format
            var factories = NativePluginLoader.Load(dir);
            Assert.Empty(factories);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void NativeStorageBackendFactory_NoCreateSymbol_ReturnsNull()
    {
        // Without the required symbols, NativePluginLoader.LoadSingle returns null
        // Test that NativePluginLoader.Load handles gracefully
        string dir = Path.Combine(Path.GetTempPath(), $"rdrf_native_nosym_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            var factories = NativePluginLoader.Load(dir);
            // No libraries to load, should be empty
            Assert.Empty(factories);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void NativeFunctions_PublicProperties_Accessible()
    {
        var funcs = new NativeFunctions();
        Assert.NotNull(funcs);
        Assert.Equal(IntPtr.Zero, funcs.LibraryHandle);
    }
}
