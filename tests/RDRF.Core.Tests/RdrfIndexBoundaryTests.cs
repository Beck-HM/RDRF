using RDRF.Core.Index;
using Xunit;

namespace RDRF.Core.Tests;

public class RdrfIndexBoundaryTests
{
    [Fact]
    public void BuildIndex_ZeroFragments_Succeeds()
    {
        var index = IndexManager.BuildIndex(
            fileFingerprint: "fp",
            originalFilename: "empty.bin",
            originalSize: 0,
            fragmentHashes: [],
            originalHash: "hash",
            fssStrategy: "FSS1",
            originalFragmentSizes: [],
            originalFragmentCount: 0);

        Assert.Equal(0, index.FragmentCount);
    }

    [Fact]
    public void BuildIndex_SingleFragment_Succeeds()
    {
        var index = IndexManager.BuildIndex(
            fileFingerprint: "fp1",
            originalFilename: "single.bin",
            originalSize: 4,
            fragmentHashes: ["h1"],
            originalHash: "hash",
            fssStrategy: "FSS1",
            originalFragmentSizes: [4],
            originalFragmentCount: 1);

        Assert.Equal(1, index.FragmentCount);
        Assert.Equal("FSS1", index.FssStrategy);
    }

    [Fact]
    public void BuildIndex_ManyFragments_Succeeds()
    {
        int count = 100;
        var hashes = Enumerable.Range(0, count).Select(i => $"h{i:D4}").ToList();
        var sizes = Enumerable.Range(0, count).Select(i => 1024).ToList();

        var index = IndexManager.BuildIndex(
            fileFingerprint: "fp100",
            originalFilename: "many.bin",
            originalSize: count * 1024,
            fragmentHashes: hashes,
            originalHash: "hash",
            fssStrategy: "FSS5",
            originalFragmentSizes: sizes,
            originalFragmentCount: count);

        Assert.Equal(count, index.FragmentCount);
        Assert.Equal(count, index.Fragments!.Count);
    }

    [Fact]
    public void SerializeDeserialize_MaxSizeIndex_Succeeds()
    {
        int count = 500;
        var hashes = Enumerable.Range(0, count).Select(i => $"h{i:D4}").ToList();
        var sizes = Enumerable.Range(0, count).Select(i => 1024).ToList();

        var original = IndexManager.BuildIndex(
            fileFingerprint: "fp_max",
            originalFilename: "max.bin",
            originalSize: count * 1024,
            fragmentHashes: hashes,
            originalHash: "hash",
            fssStrategy: "FSS6",
            originalFragmentSizes: sizes,
            originalFragmentCount: count);

        byte[] cbor = IndexManager.SerializeIndex(original);
        var restored = IndexManager.DeserializeIndex(cbor);

        Assert.Equal(original.FragmentCount, restored.FragmentCount);
        Assert.Equal(original.Fragments!.Count, restored.Fragments!.Count);
    }

    [Fact]
    public void FragmentInfo_InvalidIndex_Throws()
    {
        var index = new RdrfIndex { FragmentCount = 5 };
        var info = IndexManager.GetFragmentInfo(index, 99);
        Assert.Null(info);
    }
}
