using RDRF.Core.Configuration;
using Xunit;

namespace RDRF.Core.Tests;

public class RdrfConfigTests : IDisposable
{
    private readonly string _pointerPath;

    public RdrfConfigTests()
    {
        _pointerPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".rdrfpointer");
        // Remove any existing pointer for clean test
        if (File.Exists(_pointerPath))
            File.Delete(_pointerPath);
    }

    [Fact]
    public void RootDir_DefaultsToUserProfile()
    {
        string expected = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".rdrf");
        Assert.Equal(expected, RdrfConfig.RootDir);
    }

    [Fact]
    public void LogDir_IsSubdirectory()
    {
        Assert.EndsWith("log", RdrfConfig.LogDir.Replace('\\', '/'));
    }

    [Fact]
    public void MoveTo_UpdatesRootDir()
    {
        string testDir = Path.Combine(Path.GetTempPath(), $"rdrf_config_test_{Guid.NewGuid():N}");
        try
        {
            RdrfConfig.MoveTo(testDir);
            Assert.Equal(Path.GetFullPath(testDir), RdrfConfig.RootDir);
        }
        finally
        {
            if (Directory.Exists(testDir)) Directory.Delete(testDir, true);
        }
    }

    [Fact]
    public void MoveTo_PersistsAcrossCalls()
    {
        string testDir = Path.Combine(Path.GetTempPath(), $"rdrf_config_test2_{Guid.NewGuid():N}");
        try
        {
            RdrfConfig.MoveTo(testDir);
            // Re-initialize to simulate restart
            RdrfConfig.Initialize();
            Assert.Equal(Path.GetFullPath(testDir), RdrfConfig.RootDir);
        }
        finally
        {
            if (Directory.Exists(testDir)) Directory.Delete(testDir, true);
        }
    }

    [Fact]
    public void MoveTo_WritesPointerFile()
    {
        string testDir = Path.Combine(Path.GetTempPath(), $"rdrf_config_test3_{Guid.NewGuid():N}");
        try
        {
            RdrfConfig.MoveTo(testDir);
            Assert.True(File.Exists(_pointerPath));
        }
        finally
        {
            if (Directory.Exists(testDir)) Directory.Delete(testDir, true);
        }
    }

    public void Dispose()
    {
        try { if (File.Exists(_pointerPath)) File.Delete(_pointerPath); } catch { }
    }
}
