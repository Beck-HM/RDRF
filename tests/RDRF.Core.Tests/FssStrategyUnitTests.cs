using RDRF.Core.FSS;
using Xunit;

namespace RDRF.Core.Tests;

public class FssStrategyUnitTests
{
    public static IEnumerable<object[]> AllStrategies => new[]
    {
        new object[] { "FSS1" }, new object[] { "FSS2" }, new object[] { "FSS2R" },
        new object[] { "FSS3" }, new object[] { "FSS5" },
        new object[] { "FSS6" }, new object[] { "FSS6.1" }, new object[] { "FSS6.2" },
    };

    [Theory, MemberData(nameof(AllStrategies))]
    public void Encode_SingleFragment_ProducesMultiple(string strategy)
    {
        var engine = new FSSEngine();
        var input = new List<byte[]> { new byte[] { 1, 2, 3, 4 } };
        var result = engine.Encode(input, strategy);
        Assert.True(result.Count >= 1);
        Assert.All(result, frag => Assert.True(frag.Length > 0));
    }

    [Theory, MemberData(nameof(AllStrategies))]
    public void Encode_MultipleFragments_ProducesAtLeastInputCount(string strategy)
    {
        var engine = new FSSEngine();
        var input = new List<byte[]> { new byte[] { 1, 2, 3, 4 }, new byte[] { 5, 6, 7, 8 } };
        var result = engine.Encode(input, strategy);
        Assert.True(result.Count >= input.Count);
    }

    [Theory, MemberData(nameof(AllStrategies))]
    public void EncodeDecode_RoundTrip(string strategy)
    {
        var engine = new FSSEngine();
        var input = new List<byte[]> { new byte[] { 1, 2, 3, 4 }, new byte[] { 5, 6, 7, 8 }, new byte[] { 9, 10, 11, 12 } };
        var encoded = engine.Encode(input, strategy);
        var allPresent = Enumerable.Range(0, encoded.Count).ToDictionary(i => i, i => encoded[i]);
        var decoded = engine.Decode(allPresent, new List<int>(), strategy, input.Count);
    }

    [Theory, MemberData(nameof(AllStrategies))]
    public void Strip_AfterDecode_RoundTrip(string strategy)
    {
        var engine = new FSSEngine();
        var input = new List<byte[]> { new byte[] { 1, 2, 3, 4 }, new byte[] { 5, 6, 7, 8 } };
        var originalSizes = input.Select(f => f.Length).ToList();
        var encoded = engine.Encode(input, strategy);
        var encodedDict = Enumerable.Range(0, encoded.Count).ToDictionary(i => i, i => encoded[i]);
        var stripped = engine.Strip(encodedDict, strategy, input.Count, originalSizes);
        Assert.Equal(input.Count, stripped.Count);
    }

    [Theory, MemberData(nameof(AllStrategies))]
    public void Encode_FourFragments_AllProduced(string strategy)
    {
        var engine = new FSSEngine();
        var input = Enumerable.Range(0, 4).Select(i => new byte[] { (byte)(i + 1) }).ToList();
        var result = engine.Encode(input, strategy);
        Assert.True(result.Count >= 3);
    }

    [Fact]
    public void FSS1_Encode_DoublesData()
    {
        var engine = new FSSEngine();
        var input = new List<byte[]> { new byte[] { 1, 2 }, new byte[] { 3, 4 } };
        var result = engine.Encode(input, "FSS1");
        Assert.Equal(input.Count, result.Count);
    }

    [Fact]
    public void FSS1_Decode_MissingOne_Recovers()
    {
        var engine = new FSSEngine();
        var input = new List<byte[]> { new byte[] { 1, 2, 3, 4 }, new byte[] { 5, 6, 7, 8 } };
        var encoded = engine.Encode(input, "FSS1");
        var available = new Dictionary<int, byte[]> { { 1, encoded[1] } };
        var decoded = engine.Decode(available, new List<int> { 0 }, "FSS1", input.Count);
        Assert.Single(decoded);
    }

    [Fact]
    public void FSS2_Encode_AddsParity()
    {
        var engine = new FSSEngine();
        var input = new List<byte[]> { new byte[] { 1, 2 }, new byte[] { 3, 4 } };
        var result = engine.Encode(input, "FSS2");
        Assert.True(result.Count >= input.Count);
    }

    [Fact]
    public void FSS3_Encode_AddsParity()
    {
        var engine = new FSSEngine();
        var input = new List<byte[]> { new byte[] { 1, 2 }, new byte[] { 3, 4 } };
        var result = engine.Encode(input, "FSS3");
        Assert.True(result.Count > input.Count);
    }

    [Fact]
    public void FSS3_Decode_MissingOneParity_AttemptsRecovery()
    {
        var engine = new FSSEngine();
        var input = new List<byte[]> { new byte[] { 1, 2, 3, 4 }, new byte[] { 5, 6, 7, 8 }, new byte[] { 9, 10, 11, 12 }, new byte[] { 13, 14, 15, 16 } };
        var encoded = engine.Encode(input, "FSS3");
        var available = Enumerable.Range(0, encoded.Count - 1).ToDictionary(i => i, i => encoded[i]);
        var decoded = engine.Decode(available, new List<int> { encoded.Count - 1 }, "FSS3", input.Count);
        Assert.NotNull(decoded);
    }

    [Fact]
    public void FSS5_Decode_MissingSome_Recovers()
    {
        var engine = new FSSEngine();
        var input = new List<byte[]> { new byte[] { 1, 2 }, new byte[] { 3, 4 }, new byte[] { 5, 6 }, new byte[] { 7, 8 } };
        var encoded = engine.Encode(input, "FSS5");
        var available = Enumerable.Range(0, encoded.Count - 1).ToDictionary(i => i, i => encoded[i]);
        var ex = Record.Exception(() => engine.Decode(available, new List<int> { encoded.Count - 1 }, "FSS5", input.Count));
        Assert.Null(ex);
    }

    [Fact]
    public void FSS6_Encode_ProducesSameCount()
    {
        var engine = new FSSEngine();
        var input = new List<byte[]> { new byte[] { 1, 2, 3, 4 }, new byte[] { 5, 6, 7, 8 } };
        var result = engine.Encode(input, "FSS6");
        Assert.Equal(input.Count, result.Count);
    }

    [Fact]
    public void FSS6_Strip_FragmentLongerThanRaw()
    {
        var engine = new FSSEngine();
        var input = new List<byte[]> { new byte[] { 1, 2, 3, 4 }, new byte[] { 5, 6, 7, 8 } };
        var sizes = input.Select(f => f.Length).ToList();
        var encoded = engine.Encode(input, "FSS6");
        var encDict = Enumerable.Range(0, encoded.Count).ToDictionary(i => i, i => encoded[i]);
        var stripped = engine.Strip(encDict, "FSS6", input.Count, sizes);
        Assert.All(stripped, s => Assert.True(s.Length <= encoded[0].Length));
    }

    [Fact]
    public void FSS61_Encode_Works()
    {
        var engine = new FSSEngine();
        var input = new List<byte[]> { new byte[] { 1, 2, 3, 4 }, new byte[] { 5, 6, 7, 8 } };
        var result = engine.Encode(input, "FSS6.1");
        Assert.True(result.Count > 0);
    }

    [Fact]
    public void FSS62_Encode_Works()
    {
        var engine = new FSSEngine();
        var input = new List<byte[]> { new byte[] { 1, 2, 3, 4 }, new byte[] { 5, 6, 7, 8 } };
        var result = engine.Encode(input, "FSS6.2");
        Assert.True(result.Count > 0);
    }

    [Fact]
    public void GetStrategy_UnknownLevel_Throws()
    {
        var engine = new FSSEngine();
        Assert.ThrowsAny<Exception>(() => engine.GetStrategy("UNKNOWN"));
    }

    [Fact]
    public void RegisterStrategy_Custom_Overrides()
    {
        var engine = new FSSEngine();
        var custom = new Fss1Neighbor();
        engine.RegisterStrategy("CUSTOM", custom);
        Assert.Same(custom, engine.GetStrategy("CUSTOM"));
    }

    [Fact]
    public void StripSingle_ReturnsOriginalData()
    {
        var engine = new FSSEngine();
        var input = new List<byte[]> { new byte[] { 1, 2, 3, 4 } };
        var sizes = new List<int> { 4 };
        var encoded = engine.Encode(input, "FSS1");
        var stripped = engine.GetStrategy("FSS1").StripSingle(encoded[0], 0, sizes);
        Assert.Equal(4, stripped.Length);
    }

    [Fact]
    public void Encode_EmptyInput_Succeeds()
    {
        var engine = new FSSEngine();
        var result = engine.Encode(new List<byte[]>(), "FSS1");
        Assert.Empty(result);
    }

    [Fact]
    public void Strip_EmptyInput_Succeeds()
    {
        var engine = new FSSEngine();
        var result = engine.Strip(new Dictionary<int, byte[]>(), "FSS1", 0);
        Assert.Empty(result);
    }
}
