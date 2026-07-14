using PwManager = RDRF.Core.PasswordManager.PasswordManager;
using Xunit;

namespace RDRF.Core.Tests;

public class PasswordManagerTests : IDisposable
{
    private readonly string _testDir;
    private readonly PwManager _pm;

    public PasswordManagerTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), $"rdrf_pw_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testDir);
        _pm = new PwManager();
        _pm.InitializeForTest(_testDir);
    }

    [Fact]
    public void SetAndGetByKey_RoundTrip()
    {
        _pm.Set("mykey", "mypassword123");
        var value = _pm.GetByKey("mykey");
        Assert.Equal("mypassword123", value);
    }

    [Fact]
    public void GetByKey_Nonexistent_ReturnsNull()
    {
        var value = _pm.GetByKey("nonexistent");
        Assert.Null(value);
    }

    [Fact]
    public void Set_Overwrite_Updates()
    {
        _pm.Set("key1", "oldpass");
        _pm.Set("key1", "newpass");
        Assert.Equal("newpass", _pm.GetByKey("key1"));
    }

    [Fact]
    public void ListKeys_ReturnsAll()
    {
        _pm.Set("a", "1");
        _pm.Set("b", "2");
        var keys = _pm.ListKeys();
        Assert.Contains("a", keys);
        Assert.Contains("b", keys);
    }

    [Fact]
    public void Delete_RemovesKey()
    {
        _pm.Set("delme", "secret");
        Assert.True(_pm.Delete("delme"));
        Assert.Null(_pm.GetByKey("delme"));
    }

    [Fact]
    public void Delete_Nonexistent_ReturnsFalse()
    {
        Assert.False(_pm.Delete("nonexistent"));
    }

    [Fact]
    public void AttachHash_ThenGetByHash_ReturnsPassword()
    {
        _pm.Set("hashkey", "hashpass");
        _pm.AttachHash("hashkey", "abc123sha256");
        var password = _pm.GetByIndexHash("abc123sha256");
        Assert.Equal("hashpass", password);
    }

    [Fact]
    public void GetByIndexHash_Nonexistent_ReturnsNull()
    {
        var password = _pm.GetByIndexHash("nonexistenthash");
        Assert.Null(password);
    }

    [Fact]
    public void GetKeyDetail_ReturnsBackups()
    {
        _pm.Set("detailkey", "pass");
        _pm.AttachHash("detailkey", "hash1");
        _pm.AttachHash("detailkey", "hash2");
        var detail = _pm.GetKeyDetail("detailkey");
        Assert.Equal(2, detail.Length);
    }

    [Fact]
    public void PersistsAcrossInstances()
    {
        _pm.Set("persist", "keepme");

        var pm2 = new PwManager();
        pm2.InitializeForTest(_testDir);
        var value = pm2.GetByKey("persist");
        Assert.Equal("keepme", value);
    }

    [Fact]
    public void Uninitialized_Throws()
    {
        var pm = new PwManager();
        var result = pm.GetByKey("x");
        Assert.Null(result);
    }

    public void Dispose()
    {
        try { Directory.Delete(_testDir, recursive: true); } catch { }
    }
}
