using RDRF.Core.Metadata;
using Xunit;

namespace RDRF.Core.Tests;

public class MetadataManagerTests : IDisposable
{
    private readonly string _dbPath;
    private readonly MetadataManager _meta;

    public MetadataManagerTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"rdrf_meta_test_{Guid.NewGuid():N}.db");
        _meta = new MetadataManager(_dbPath);
    }

    [Fact]
    public void SaveAndGetBackup_RoundTrip()
    {
        _meta.SaveBackup("fp1", "test.bin", 1024, "hash1", "FSS1",
            new List<string> { "fh1", "fh2" });

        var backup = _meta.GetBackup("fp1");
        Assert.NotNull(backup);
        Assert.Equal("test.bin", backup["original_filename"]);
        Assert.Equal(1024L, backup["original_size"]);
    }

    [Fact]
    public void ListBackups_ReturnsSaved()
    {
        _meta.SaveBackup("fp_a", "a.bin", 100, "ha", "FSS1", new List<string>());
        _meta.SaveBackup("fp_b", "b.bin", 200, "hb", "FSS2", new List<string>());

        var list = _meta.ListBackups(10);
        Assert.Equal(2, list.Count);
    }

    [Fact]
    public void DeleteBackup_RemovesRecord()
    {
        _meta.SaveBackup("fp_del", "del.bin", 64, "h", "FSS1", new List<string>());
        Assert.NotNull(_meta.GetBackup("fp_del"));

        _meta.DeleteBackup("fp_del");
        Assert.Null(_meta.GetBackup("fp_del"));
    }

    [Fact]
    public void GetBackup_Nonexistent_ReturnsNull()
    {
        Assert.Null(_meta.GetBackup("nonexistent"));
    }

    [Fact]
    public void FragmentStatus_DoesNotThrow()
    {
        _meta.SaveBackup("fp_frag", "f.bin", 128, "h", "FSS1", new List<string>());

        _meta.MarkFragmentOk("fp_frag", 0);
        _meta.MarkFragmentMissing("fp_frag", 1);
        _meta.MarkFragmentCorrupt("fp_frag", 2);

        var status = _meta.GetFragmentStatus("fp_frag");
        Assert.NotNull(status);
    }

    [Fact]
    public void ListBackups_RespectsLimit()
    {
        for (int i = 0; i < 5; i++)
            _meta.SaveBackup($"fp_{i}", $"{i}.bin", i * 100, $"h{i}", "FSS1", new List<string>());

        var list = _meta.ListBackups(3);
        Assert.Equal(3, list.Count);
    }

    public void Dispose()
    {
        try { File.Delete(_dbPath); } catch { }
    }
}
