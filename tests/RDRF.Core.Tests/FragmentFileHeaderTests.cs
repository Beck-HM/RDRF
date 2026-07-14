using RDRF.Core.DSAA;
using RDRF.Core.Encryption;
using RDRF.Core.Index;
using Xunit;

namespace RDRF.Core.Tests;

public class FragmentFileHeaderTests
{
    private byte[] MakeEmbeddedIndex()
    {
        var index = new RdrfIndex
        {
            FileFingerprint = "test_fp",
            OriginalName = "test.bin",
            FileSize = 100,
            FssStrategy = "FSS1",
        };
        return IndexManager.SerializeIndex(index);
    }

    [Fact]
    public void HasHeader_ValidHeader_ReturnsTrue()
    {
        byte[] aesKey = EncryptionLayer.DeriveKeyLegacy(EncryptionLayer.GenerateRcCode(32));
        byte[] data = new byte[] { 1, 2, 3, 4 };
        byte[] encrypted = FragmentFileHeader.EncryptWithEmbeddedIndex(data, MakeEmbeddedIndex(), aesKey, []);

        Assert.True(FragmentFileHeader.HasHeader(encrypted));
    }

    [Fact]
    public void HasHeader_RawData_ReturnsFalse()
    {
        Assert.False(FragmentFileHeader.HasHeader(new byte[] { 0, 1, 2 }));
        Assert.False(FragmentFileHeader.HasHeader([]));
    }

    [Fact]
    public void DecryptWithEmbeddedIndex_RoundTrip()
    {
        byte[] aesKey = EncryptionLayer.DeriveKeyLegacy(EncryptionLayer.GenerateRcCode(32));
        byte[] originalData = new byte[] { 10, 20, 30, 40, 50 };

        byte[] encrypted = FragmentFileHeader.EncryptWithEmbeddedIndex(originalData, MakeEmbeddedIndex(), aesKey, []);
        var (embeddedIndex, fragmentData, salt) = FragmentFileHeader.DecryptWithEmbeddedIndex(encrypted, aesKey);

        Assert.NotNull(embeddedIndex);
        Assert.Equal(originalData, fragmentData);
    }

    [Fact]
    public void GetTotalHeaderSize_ReturnsPositive()
    {
        byte[] aesKey = EncryptionLayer.DeriveKeyLegacy(EncryptionLayer.GenerateRcCode(32));
        byte[] encrypted = FragmentFileHeader.EncryptWithEmbeddedIndex(new byte[] { 1 }, MakeEmbeddedIndex(), aesKey, []);

        int size = FragmentFileHeader.GetTotalHeaderSize(encrypted);
        Assert.True(size > 0);
        Assert.True(size < encrypted.Length);
    }

    [Fact]
    public void EncryptWithEmbeddedIndex_EmptyData_Succeeds()
    {
        byte[] aesKey = EncryptionLayer.DeriveKeyLegacy(EncryptionLayer.GenerateRcCode(32));
        byte[] encrypted = FragmentFileHeader.EncryptWithEmbeddedIndex([], MakeEmbeddedIndex(), aesKey, []);
        Assert.NotNull(encrypted);
        Assert.True(encrypted.Length > 0);
    }
}
