using System.Security.Cryptography;
using RDRF.Core.FSS;
using RDRF.Core.Index;
using Xunit;

namespace RDRF.Core.Tests;

public class IndexManagerTests
{
    private static RdrfIndex MakeIndex()
    {
        var hashes = new List<string> { "hash0", "hash1", "hash2" };
        var nonces = new List<string> { "nonce0", "nonce1", "nonce2" };
        return IndexManager.BuildIndex(
            fileFingerprint: "fp123",
            originalFilename: "test.bin",
            originalSize: 1000,
            fragmentHashes: hashes,
            fragmentNonces: nonces,
            originalHash: "orig_hash_abc",
            fssStrategy: "FSS1",
            originalFragmentSizes: new List<int> { 500, 500, 200 },
            originalFragmentCount: 3);
    }

    [Fact]
    public void BuildIndex_SetsFields()
    {
        var idx = MakeIndex();
        Assert.Equal("fp123", idx.FileFingerprint);
        Assert.Equal("test.bin", idx.OriginalName);
        Assert.Equal(1000, idx.FileSize);
        Assert.Equal(3, idx.FragmentCount);
        Assert.Equal(3, idx.OriginalFragmentCount);
        Assert.Equal("FSS1", idx.FssStrategy);
        Assert.Equal(500, idx.OriginalFragmentSizes[0]);
        Assert.Equal(200, idx.OriginalFragmentSizes[2]);
    }

    [Fact]
    public void SerializeDeserialize_RoundTrip()
    {
        var idx = MakeIndex();
        byte[] cbor = IndexManager.SerializeIndex(idx);
        var idx2 = IndexManager.DeserializeIndex(cbor);

        Assert.NotNull(idx2);
        Assert.Equal(idx.FileFingerprint, idx2.FileFingerprint);
        Assert.Equal(idx.OriginalName, idx2.OriginalName);
        Assert.Equal(idx.FileSize, idx2.FileSize);
        Assert.Equal(idx.FragmentCount, idx2.FragmentCount);
        Assert.Equal(idx.OriginalFragmentCount, idx2.OriginalFragmentCount);
        Assert.Equal(idx.FssStrategy, idx2.FssStrategy);
        Assert.Equal(idx.OriginalHash, idx2.OriginalHash);
        Assert.Equal(idx.OriginalFragmentSizes, idx2.OriginalFragmentSizes);
    }

    [Fact]
    public void SerializeDeserialize_FragmentHashes()
    {
        var idx = MakeIndex();
        byte[] cbor = IndexManager.SerializeIndex(idx);
        var idx2 = IndexManager.DeserializeIndex(cbor);

        Assert.Equal(3, idx2.Fragments?.Count);
        Assert.Equal("hash0", idx2.Fragments[0].Hash);
        Assert.Equal("hash2", idx2.Fragments[2].Hash);
    }

    [Fact]
    public void SerializeDeserialize_CustomName()
    {
        var idx = MakeIndex();
        idx.CustomName = "my_custom_name";
        byte[] cbor = IndexManager.SerializeIndex(idx);
        var idx2 = IndexManager.DeserializeIndex(cbor);
        Assert.Equal("my_custom_name", idx2.CustomName);
    }

    [Fact]
    public void SerializeDeserialize_Compression()
    {
        var idx = MakeIndex();
        idx.Compression = "lz4";
        byte[] cbor = IndexManager.SerializeIndex(idx);
        var idx2 = IndexManager.DeserializeIndex(cbor);
        Assert.Equal("lz4", idx2.Compression);
    }

    [Fact]
    public void SerializeDeserialize_Fss6Fields()
    {
        var idx = MakeIndex();
        idx.Fss6FragmentBlockMaps = new List<List<string>>
        {
            new() { "a", "b" },
            new() { "c" },
        };
        idx.Fss6RcBlockMap = new List<string> { "x", "y", "z" };
        byte[] cbor = IndexManager.SerializeIndex(idx);
        var idx2 = IndexManager.DeserializeIndex(cbor);

        Assert.Equal(2, idx2.Fss6FragmentBlockMaps.Count);
        Assert.Equal("a", idx2.Fss6FragmentBlockMaps[0][0]);
        Assert.Equal("y", idx2.Fss6RcBlockMap[1]);
    }

    [Fact]
    public void SerializeDeserialize_FssParams()
    {
        var idx = MakeIndex();
        idx.FssParams = new Dictionary<string, object>
        {
            ["key1"] = "value1",
            ["key2"] = 42,
        };
        byte[] cbor = IndexManager.SerializeIndex(idx);
        var idx2 = IndexManager.DeserializeIndex(cbor);

        Assert.NotNull(idx2.FssParams);
        Assert.True(idx2.FssParams.ContainsKey("key1"));
    }

    [Fact]
    public void Deserialize_CorruptData_Throws()
    {
        byte[] corrupt = [0x00, 0x01, 0x02, 0x03];
        Assert.Throws<System.InvalidOperationException>(() =>
            IndexManager.DeserializeIndex(corrupt));
    }

    [Fact]
    public void SerializeDeserialize_Fss61RepairB()
    {
        var idx = MakeIndex();
        idx.Fss61RepairB = new Fss61RepairData
        {
            Seed = 42,
            BlockCount = 10,
            BlockSize = 256,
            Data = [1, 2, 3, 4, 5],
        };
        byte[] cbor = IndexManager.SerializeIndex(idx);
        var idx2 = IndexManager.DeserializeIndex(cbor);

        Assert.NotNull(idx2.Fss61RepairB);
        Assert.Equal(42, idx2.Fss61RepairB.Seed);
        Assert.Equal(10, idx2.Fss61RepairB.BlockCount);
        Assert.Equal(256, idx2.Fss61RepairB.BlockSize);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, idx2.Fss61RepairB.Data);
    }

    [Fact]
    public void GetFragmentInfo_ByIndex()
    {
        var idx = MakeIndex();
        var info = IndexManager.GetFragmentInfo(idx, 1);
        Assert.NotNull(info);
        Assert.Equal(1, info.Index);
        Assert.Equal("hash1", info.Hash);
    }

    [Fact]
    public void GetFragmentInfo_OutOfRange_ReturnsNull()
    {
        var idx = MakeIndex();
        var info = IndexManager.GetFragmentInfo(idx, 99);
        Assert.Null(info);
    }
}
