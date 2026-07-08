using RDRF.Core.FragmentEngine;
using Xunit;

namespace RDRF.Core.Tests;

public class FragmentEngineTests
{
    [Fact]
    public void FragmentFilename_ProducesCorrectPattern()
    {
        var name = Frags.FragmentFilename("abc123fingerprint", 0);
        Assert.Equal("abc123fingerprint_0.rdrf", name);
    }

    [Fact]
    public void FragmentFilename_Index5_ProducesCorrectName()
    {
        var name = Frags.FragmentFilename("fp", 5);
        Assert.Equal("fp_5.rdrf", name);
    }

    [Fact]
    public void FragmentFilename_CustomName_UsesCustomPrefix()
    {
        var name = Frags.FragmentFilename("mybackup", 1);
        Assert.Equal("mybackup_1.rdrf", name);
    }

    [Fact]
    public void MergeFileData_CombinesAllFragments()
    {
        var fragments = new List<byte[]>
        {
            new byte[] { 0x01, 0x02 },
            new byte[] { 0x03, 0x04 },
            new byte[] { 0x05 },
        };
        var merged = Frags.MergeFragments(fragments);
        Assert.Equal(5, merged.Length);
        Assert.Equal(0x01, merged[0]);
        Assert.Equal(0x05, merged[4]);
    }

    [Fact]
    public void MergeFragments_SingleFragment_ReturnsCopy()
    {
        var data = new byte[] { 0xAA, 0xBB };
        var merged = Frags.MergeFragments(new List<byte[]> { data });
        Assert.Equal(data, merged);
    }

    [Fact]
    public void SplitData_ReturnsCorrectFragments()
    {
        var data = new byte[2500]; // 2.5 fragments at 1KB
        new Random(42).NextBytes(data);
        var fragments = Frags.SplitData(data, 1024);
        Assert.Equal(3, fragments.Count); // 3 fragments: 1024 + 1024 + 452
        Assert.Equal(1024, fragments[0].Length);
        Assert.Equal(1024, fragments[1].Length);
        Assert.Equal(452, fragments[2].Length);
    }

    [Fact]
    public void SplitData_ExactFit_ReturnsExactCount()
    {
        var data = new byte[2048];
        new Random(42).NextBytes(data);
        var fragments = Frags.SplitData(data, 1024);
        Assert.Equal(2, fragments.Count);
        Assert.Equal(1024, fragments[0].Length);
        Assert.Equal(1024, fragments[1].Length);
    }

    [Fact]
    public void ComputeFingerprint_IsDeterministic()
    {
        var data = new byte[] { 0x01, 0x02, 0x03 };
        var fp1 = Frags.ComputeFingerprint(data);
        var fp2 = Frags.ComputeFingerprint(data);
        Assert.Equal(fp1, fp2);
    }
}
