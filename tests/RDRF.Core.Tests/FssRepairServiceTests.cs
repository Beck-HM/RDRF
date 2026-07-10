using RDRF.Core.Abstractions;
using RDRF.Core.FSS;
using RDRF.Core.Index;
using Xunit;

namespace RDRF.Core.Tests;

public class FssRepairServiceTests
{
    [Fact]
    public void SplitToBlocks_EvenSplit()
    {
        byte[] data = new byte[16];
        for (int i = 0; i < 16; i++) data[i] = (byte)i;

        var blocks = FssRepairService.SplitToBlocks(data, 4);
        Assert.Equal(4, blocks.Length);
        Assert.Equal(4, blocks[0].Length);
    }

    [Fact]
    public void SplitToBlocks_UnevenSplit()
    {
        byte[] data = new byte[10];
        var blocks = FssRepairService.SplitToBlocks(data, 4);
        Assert.Equal(3, blocks.Length); // 4+4+2
    }

    [Fact]
    public void SplitToBlocks_EmptyData()
    {
        var blocks = FssRepairService.SplitToBlocks([], 4);
        Assert.Empty(blocks);
    }

    [Fact]
    public void MergeBlocks_ReversesSplit()
    {
        byte[] data = new byte[16];
        for (int i = 0; i < 16; i++) data[i] = (byte)i;

        var blocks = FssRepairService.SplitToBlocks(data, 4);
        var merged = FssRepairService.MergeBlocks(blocks, 16, 4);
        Assert.Equal(data, merged);
    }

    [Fact]
    public void MergeBlocks_TruncatesToExactSize()
    {
        byte[] data = new byte[10];
        for (int i = 0; i < 10; i++) data[i] = (byte)i;

        var blocks = FssRepairService.SplitToBlocks(data, 4);
        var merged = FssRepairService.MergeBlocks(blocks, 10, 4);
        Assert.Equal(10, merged.Length);
        Assert.Equal(data, merged);
    }

    [Fact]
    public void TryRepair61_NoCorruption_ReturnsFalse()
    {
        var idx = new RdrfIndex { FileFingerprint = "test" };
        byte[] rc = [];
        var fragments = new Dictionary<int, byte[]>();
        var cv = new CrossValidationResult();

        bool result = FssRepairService.TryRepair61(idx, ref rc, fragments, cv);
        Assert.False(result);
    }

    [Fact]
    public void TryRepair62_NoCorruption_ReturnsFalse()
    {
        var idx = new RdrfIndex { FileFingerprint = "test" };
        byte[] rc = [];
        var fragments = new Dictionary<int, byte[]>();
        var cv = new CrossValidationResult();

        bool result = FssRepairService.TryRepair62(idx, ref rc, fragments, cv);
        Assert.False(result);
    }

    [Fact]
    public void TryRepair61_WithIIndexManager_DoesNotThrow()
    {
        var idxMgr = new IndexManagerWrapper();
        var idx = new RdrfIndex
        {
            FileFingerprint = "test",
            OriginalName = "test.bin",
            OriginalHash = "abc123",
        };
        byte[] rc = [];
        var fragments = new Dictionary<int, byte[]>();
        var cv = new CrossValidationResult();

        bool result = FssRepairService.TryRepair61(idx, ref rc, fragments, cv, idxMgr);
        Assert.False(result);
    }

    [Fact]
    public void TryRepair62_WithIIndexManager_DoesNotThrow()
    {
        var idxMgr = new IndexManagerWrapper();
        var idx = new RdrfIndex
        {
            FileFingerprint = "test",
            OriginalName = "test.bin",
            OriginalHash = "abc123",
        };
        byte[] rc = [];
        var fragments = new Dictionary<int, byte[]>();
        var cv = new CrossValidationResult();

        bool result = FssRepairService.TryRepair62(idx, ref rc, fragments, cv, idxMgr);
        Assert.False(result);
    }
}
