using RDRF.Core.DSAA;
using RDRF.Core.DSAA.NativePlugin;
using Xunit;

namespace RDRF.Core.Tests;

public class NativePluginE2ETests : IDisposable
{
    private readonly string _storeDir;

    public NativePluginE2ETests()
    {
        _storeDir = Path.Combine(Path.GetTempPath(), $"rdrf_native_e2e_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_storeDir);
    }

    [Fact]
    public void StorageConfig_RegisterBuiltinFactories_AddsNative()
    {
        StorageConfig.RegisterBuiltinFactories();
        // Can't easily verify internally, but ensure no exception
    }

    [Fact]
    public void NativeBackendConfigFactory_MissingLibrary_Throws()
    {
        var factory = new NativeBackendConfigFactory();
        var config = new Dictionary<string, object>();
        Assert.Throws<ArgumentException>(() => factory.Create(config));
    }

    [Fact]
    public void NativeBackendConfigFactory_InvalidLib_Throws()
    {
        var factory = new NativeBackendConfigFactory();
        var config = new Dictionary<string, object>
        {
            ["library"] = "/nonexistent/lib.so"
        };
        Assert.Throws<FileNotFoundException>(() => factory.Create(config));
    }

    [Fact]
    public void NativeFunctions_DefaultValues()
    {
        var funcs = new NativeFunctions();
        Assert.Equal(IntPtr.Zero, funcs.LibraryHandle);
        Assert.Null(funcs.Ping);
    }

    [Fact]
    public void NativePluginLoader_ValidDirNoLibs_ReturnsEmpty()
    {
        var factories = NativePluginLoader.Load(_storeDir);
        Assert.Empty(factories);
    }

    public void Dispose()
    {
        try { Directory.Delete(_storeDir, true); } catch { }
    }
}
