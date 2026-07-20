using RDRF.Core.DSAA;
using Xunit;

namespace RDRF.Core.Tests;

public class StorageAdapterTests : IDisposable
{
    private readonly string _testDir;
    private readonly LocalDSAAAdapter _adapter;

    public StorageAdapterTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), $"rdrf_dsaa_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testDir);
        _adapter = new LocalDSAAAdapter(_testDir);
    }

    [Fact]
    public void WriteAndReadFragment_RoundTrip()
    {
        byte[] data = new byte[] { 1, 2, 3, 4, 5 };
        _adapter.WriteFragment("test_0.rdrf", data);
        var read = _adapter.ReadFragment("test_0.rdrf");
        Assert.Equal(data, read);
    }

    [Fact]
    public void FragmentExists_ReturnsTrue_AfterWrite()
    {
        _adapter.WriteFragment("exists_0.rdrf", new byte[] { 1 });
        Assert.True(_adapter.FragmentExists("exists_0.rdrf"));
    }

    [Fact]
    public void FragmentExists_ReturnsFalse_ForNonexistent()
    {
        Assert.False(_adapter.FragmentExists("nonexistent.rdrf"));
    }

    [Fact]
    public void DeleteFragment_RemovesFile()
    {
        _adapter.WriteFragment("del_0.rdrf", new byte[] { 1 });
        _adapter.DeleteFragment("del_0.rdrf");
        Assert.False(_adapter.FragmentExists("del_0.rdrf"));
    }

    [Fact]
    public void ListFragments_ReturnsWritten()
    {
        _adapter.WriteFragment("list_0.rdrf", new byte[] { 1 });
        _adapter.WriteFragment("list_1.rdrf", new byte[] { 2 });
        var list = _adapter.ListFragments();
        Assert.Contains("list_0.rdrf", list);
        Assert.Contains("list_1.rdrf", list);
    }

    [Fact]
    public void WriteAndReadIndex_RoundTrip()
    {
        string fp = "test_index_fp";
        byte[] data = new byte[] { 10, 20, 30 };
        _adapter.WriteIndex(fp, data);
        var read = _adapter.ReadIndex(fp);
        Assert.Equal(data, read);
    }

    [Fact]
    public void IndexExists_ReturnsCorrectly()
    {
        string fp = "exists_idx";
        _adapter.WriteIndex(fp, new byte[] { 1 });
        Assert.True(_adapter.IndexExists(fp));
        Assert.False(_adapter.IndexExists("nonexistent_idx"));
    }

    [Fact]
    public void PathSeparatorInFilename_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            _adapter.WriteFragment("sub\\file.rdrf", new byte[] { 1 }));
        Assert.Throws<ArgumentException>(() =>
            _adapter.WriteFragment("sub/file.rdrf", new byte[] { 1 }));
    }

    [Fact]
    public void InvalidFilenameChars_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            _adapter.WriteFragment("file<>.rdrf", new byte[] { 1 }));
    }

    [Fact]
    public async Task AsyncReadWrite_RoundTrip()
    {
        byte[] data = new byte[] { 100, 200 };
        await _adapter.WriteFragmentAsync("async_0.rdrf", data);
        var read = await _adapter.ReadFragmentAsync("async_0.rdrf");
        Assert.Equal(data, read);
    }

    [Fact]
    public void ReadFragment_Nonexistent_Throws()
    {
        Assert.Throws<FileNotFoundException>(() =>
            _adapter.ReadFragment("no_file.rdrf"));
    }

    [Fact]
    public void WriteAndReadRc_RoundTrip()
    {
        string fp = "test_rc_fp";
        byte[] data = new byte[] { 1, 2, 3 };
        _adapter.WriteRc(fp, data);
        var read = _adapter.ReadRc(fp);
        Assert.Equal(data, read);
    }

    [Fact]
    public async Task WriteFragmentAsync_IsAtomic()
    {
        var data = new byte[4096];
        new Random(42).NextBytes(data);

        await _adapter.WriteFragmentAsync("atomic_test.rdrf", data);

        Assert.True(_adapter.FragmentExists("atomic_test.rdrf"));
        var read = await _adapter.ReadFragmentAsync("atomic_test.rdrf");
        Assert.Equal(data, read);
    }

    [Fact]
    public async Task ReadFragmentAsync_Nonexistent_ShouldReturnEmptyOrThrow()
    {
        await Assert.ThrowsAsync<FileNotFoundException>(() =>
            _adapter.ReadFragmentAsync("nonexistent_frag.rdrf"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_testDir, recursive: true); } catch { }
    }
}
