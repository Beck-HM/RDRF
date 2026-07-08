using RDRF.Core.FSS;
using Xunit;

namespace RDRF.Core.Tests;

public static class TestData
{
    public static List<byte[]> MakeFragments(int count, int size)
    {
        var rng = new Random(42);
        var list = new List<byte[]>();
        for (int i = 0; i < count; i++)
        {
            var b = new byte[size];
            rng.NextBytes(b);
            list.Add(b);
        }
        return list;
    }
}

public class FSSEngineTests
{
    private readonly FSSEngine _engine = new();

    [Theory]
    [InlineData("FSS1")]
    [InlineData("FSS2")]
    [InlineData("FSS2R")]
    [InlineData("FSS3")]
    [InlineData("FSS5")]
    [InlineData("FSS5+")]
    [InlineData("FSS6")]
    [InlineData("FSS6.1")]
    [InlineData("FSS6.2")]
    public void GetStrategy_AllLevels_ReturnsImplementation(string level)
    {
        var strategy = _engine.GetStrategy(level);
        Assert.NotNull(strategy);
        Assert.IsAssignableFrom<IFssStrategy>(strategy);
    }

    [Fact]
    public void GetStrategy_UnknownLevel_Throws()
    {
        var ex = Assert.ThrowsAny<Exception>(() => _engine.GetStrategy("FSS99"));
        // The actual exception type can be ArgumentException or KeyNotFoundException
        Assert.True(ex is KeyNotFoundException || ex is ArgumentException);
    }

    [Fact]
    public void Encode_FSS1_ReturnsSameCount()
    {
        var fragments = TestData.MakeFragments(4, 1024);
        var encoded = _engine.Encode(fragments, "FSS1");
        // FSS1 duplicates neighbor, so count stays the same
        Assert.Equal(fragments.Count, encoded.Count);
    }

    [Fact]
    public void Encode_FSS3_ReturnsMoreFragments()
    {
        var fragments = TestData.MakeFragments(4, 1024);
        var encoded = _engine.Encode(fragments, "FSS3");
        // FSS3 adds row+col parity fragments
        Assert.True(encoded.Count > fragments.Count);
    }
}
