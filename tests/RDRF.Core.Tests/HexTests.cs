using RDRF.Core.Abstractions;
using Xunit;

namespace RDRF.Core.Tests;

public class HexTests
{
    [Fact]
    public void EncodeLower_Empty_ReturnsEmpty()
    {
        Assert.Equal("", Hex.EncodeLower(Array.Empty<byte>()));
        Assert.Equal("", Hex.EncodeLower(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void EncodeLower_Null_ReturnsEmpty()
    {
        Assert.Equal("", Hex.EncodeLower((byte[])null!));
    }

    [Fact]
    public void EncodeLower_SingleByte_ReturnsCorrectHex()
    {
        Assert.Equal("00", Hex.EncodeLower(new byte[] { 0x00 }));
        Assert.Equal("ff", Hex.EncodeLower(new byte[] { 0xFF }));
        Assert.Equal("ab", Hex.EncodeLower(new byte[] { 0xAB }));
        Assert.Equal("7f", Hex.EncodeLower(new byte[] { 0x7F }));
    }

    [Fact]
    public void EncodeLower_MultiByte_MatchesToHexStringLower()
    {
        var bytes = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        var expected = Convert.ToHexString(bytes).ToLowerInvariant();
        Assert.Equal(expected, Hex.EncodeLower(bytes));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(256)]
    [InlineData(1024)]
    public void EncodeLower_RandomBytes_MatchesReference(int length)
    {
        var rng = new Random(42);
        var bytes = new byte[length];
        rng.NextBytes(bytes);
        var expected = Convert.ToHexString(bytes).ToLowerInvariant();
        var actual = Hex.EncodeLower(bytes);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void EncodeLower_ReadOnlySpan_MatchesByteArray()
    {
        var bytes = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
        ReadOnlySpan<byte> span = bytes;
        Assert.Equal(Hex.EncodeLower(bytes), Hex.EncodeLower(span));
    }
}
