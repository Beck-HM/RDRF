using RDRF.Core.DSAA;
using Xunit;

namespace RDRF.Core.Tests;

public class ConfigManagerTests : IDisposable
{
    private readonly string _configDir;

    public ConfigManagerTests()
    {
        _configDir = Path.Combine(Path.GetTempPath(), $"rdrf_config_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_configDir);
    }

    [Fact]
    public void Load_MissingFile_ReturnsEmptyList()
    {
        string path = Path.Combine(_configDir, "nonexistent.yaml");
        var backends = ConfigManager.Load(path);
        Assert.Empty(backends);
    }

    [Fact]
    public void Load_ValidYaml_ParsesCorrectly()
    {
        string path = Path.Combine(_configDir, "test.yaml");
        File.WriteAllText(path, @"
backends:
  - name: local
    type: path
    base_path: ./backups
");
        var backends = ConfigManager.Load(path);
        Assert.Single(backends);
        Assert.Equal("local", backends[0].Name);
    }

    [Fact]
    public void AddBackend_ThenRemove_Success()
    {
        var entry = new BackendConfigEntry
        {
            Name = "test_backend",
            Type = "path",
            Parameters = new Dictionary<string, string> { ["base_path"] = "./tmp" }
        };

        ConfigManager.AddBackend(entry);
        ConfigManager.RemoveBackend("test_backend");
    }

    [Fact]
    public void AddBackend_ThenUpdate_Success()
    {
        string path = Path.Combine(_configDir, "update.yaml");
        var entry = new BackendConfigEntry
        {
            Name = "update_backend",
            Type = "path",
            Parameters = new Dictionary<string, string> { ["base_path"] = "./old" }
        };
        ConfigManager.AddBackend(entry, path);

        var updated = new BackendConfigEntry
        {
            Name = "update_backend",
            Type = "path",
            Parameters = new Dictionary<string, string> { ["base_path"] = "./new" }
        };
        ConfigManager.UpdateBackend("update_backend", updated, path);

        ConfigManager.RemoveBackend("update_backend", path);
    }

    public void Dispose()
    {
        try { Directory.Delete(_configDir, recursive: true); } catch { }
    }
}
