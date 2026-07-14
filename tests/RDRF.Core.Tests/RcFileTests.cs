using RDRF.Core.DSAA;
using Xunit;

namespace RDRF.Core.Tests;

public class RcFileTests
{
    [Fact]
    public void ToCborBytes_FromCbor_RoundTrip()
    {
        var original = new RcFile
        {
            Version = 3,
            FileFingerprint = "test_fp",
            IndexBlockMap = new List<string> { "a", "b" },
            FragmentBlockMaps = new List<List<string>>
            {
                new List<string> { "c" },
                new List<string> { "d" },
            },
            CreatedAt = 1234567890,
        };

        byte[] cbor = original.ToCborBytes();
        var restored = RcFile.FromCbor(cbor);

        Assert.Equal(original.Version, restored.Version);
        Assert.Equal(original.FileFingerprint, restored.FileFingerprint);
        Assert.Equal(original.IndexBlockMap.Count, restored.IndexBlockMap.Count);
        Assert.Equal(original.FragmentBlockMaps.Count, restored.FragmentBlockMaps.Count);
        Assert.Equal(original.CreatedAt, restored.CreatedAt);
    }

    [Fact]
    public void FromCbor_EmptyBytes_Throws()
    {
        Assert.ThrowsAny<System.Exception>(() => RcFile.FromCbor([]));
    }

    [Fact]
    public void FromCbor_InvalidCbor_Throws()
    {
        Assert.ThrowsAny<System.Exception>(() =>
            RcFile.FromCbor(new byte[] { 0xFF, 0xFF, 0xFF }));
    }

    [Fact]
    public void ToCborBytes_DefaultValues_RoundTrip()
    {
        var original = new RcFile();
        byte[] cbor = original.ToCborBytes();
        var restored = RcFile.FromCbor(cbor);

        Assert.Equal(1, restored.Version);
        Assert.Empty(restored.IndexBlockMap);
    }

    [Fact]
    public void RepairA_RoundTrip()
    {
        var rc = new RcFile
        {
            Version = 2,
            RepairA = new FSS.Fss61RepairData { Data = new byte[] { 10, 20 }, BlockSize = 4, Seed = 42, BlockCount = 3 },
        };

        byte[] cbor = rc.ToCborBytes();
        var restored = RcFile.FromCbor(cbor);

        Assert.NotNull(restored.RepairA);
        Assert.Equal(rc.RepairA.BlockSize, restored.RepairA.BlockSize);
        Assert.Equal(rc.RepairA.Seed, restored.RepairA.Seed);
        Assert.Equal(rc.RepairA.Data, restored.RepairA.Data);
    }

    [Fact]
    public void Repair62A_RoundTrip()
    {
        var rc = new RcFile
        {
            Repair62A = new FSS.Fss62RepairData
            {
                Data = new byte[] { 1, 2, 3 },
                EntropySamples = new byte[] { 4, 5 },
                BlockSize = 8, Seed = 99, BlockCount = 2,
            },
        };

        byte[] cbor = rc.ToCborBytes();
        var restored = RcFile.FromCbor(cbor);

        Assert.NotNull(restored.Repair62A);
        Assert.Equal(rc.Repair62A.Data, restored.Repair62A.Data);
        Assert.Equal(rc.Repair62A.EntropySamples, restored.Repair62A.EntropySamples);
    }
}
