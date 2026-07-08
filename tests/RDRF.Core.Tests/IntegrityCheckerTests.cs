using RDRF.Core.Integrity;
using Xunit;

namespace RDRF.Core.Tests;

public class IntegrityCheckerTests
{
    [Fact]
    public void HashBytes_Produces64CharHex()
    {
        var hash = IntegrityChecker.HashBytes(new byte[] { 0x01, 0x02, 0x03 });
        Assert.Equal(64, hash.Length);
    }

    [Fact]
    public void HashBytes_DifferentInputs_DifferentHashes()
    {
        var h1 = IntegrityChecker.HashBytes(new byte[] { 0x01 });
        var h2 = IntegrityChecker.HashBytes(new byte[] { 0x02 });
        Assert.NotEqual(h1, h2);
    }

    [Fact]
    public void HashBytes_SameInput_SameHash()
    {
        var data = new byte[] { 0xAB, 0xCD };
        var h1 = IntegrityChecker.HashBytes(data);
        var h2 = IntegrityChecker.HashBytes(data);
        Assert.Equal(h1, h2);
    }

    [Fact]
    public void HashBytes_EmptyInput_ReturnsValidHash()
    {
        var hash = IntegrityChecker.HashBytes(Array.Empty<byte>());
        Assert.Equal(64, hash.Length);
        // SHA256 of empty
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash);
    }

    [Fact]
    public void VerifyHash_Match_ReturnsTrue()
    {
        var data = new byte[] { 0x12, 0x34, 0x56 };
        var hash = IntegrityChecker.HashBytes(data);
        Assert.True(IntegrityChecker.VerifyHash(hash, hash));
    }

    [Fact]
    public void VerifyHash_Mismatch_ReturnsFalse()
    {
        var h1 = IntegrityChecker.HashBytes(new byte[] { 0x01 });
        var h2 = IntegrityChecker.HashBytes(new byte[] { 0x02 });
        Assert.False(IntegrityChecker.VerifyHash(h1, h2));
    }

    [Fact]
    public void BytesEqual_SameContent_ReturnsTrue()
    {
        Assert.True(IntegrityChecker.BytesEqual(new byte[] { 0x01, 0x02 }, new byte[] { 0x01, 0x02 }));
        Assert.False(IntegrityChecker.BytesEqual(new byte[] { 0x01 }, new byte[] { 0x02 }));
    }

    [Fact]
    public void BytesEqual_Null_ReturnsFalse()
    {
        Assert.False(IntegrityChecker.BytesEqual(null, new byte[] { 0x01 }));
        Assert.False(IntegrityChecker.BytesEqual(new byte[] { 0x01 }, null));
    }
}
