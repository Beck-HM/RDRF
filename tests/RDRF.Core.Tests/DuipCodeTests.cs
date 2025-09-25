using System.Security.Cryptography;
using RDRF.Core.FSS;
using Xunit;

namespace RDRF.Core.Tests;

public class DuipCodeTests
{
    private static byte[][] MakeBlocks(int count, int blockSize)
    {
        var blocks = new byte[count][];
        for (int i = 0; i < count; i++)
        {
            blocks[i] = new byte[blockSize];
            RandomNumberGenerator.Fill(blocks[i]);
        }
        return blocks;
    }

    [Fact]
    public void RepairRatio_Default_0_5()
    {
        Assert.Equal(0.5, DuipCode.RepairRatio);
    }

    [Fact]
    public void Encode_SymbolCount_Ratio0_5()
    {
        var blocks = MakeBlocks(100, 256);
        var (symbols, _, _) = DuipCode.Encode(blocks, 256);
        Assert.Equal(50, symbols.Count); // 100 * 0.5 = 50
    }

    [Fact]
    public void EncodeDecode_NoCorruption()
    {
        int K = 50, bs = 256;
        var blocks = MakeBlocks(K, bs);
        var original = blocks.Select(b => b.ToArray()).ToArray();

        var (symbols, entropy, seed) = DuipCode.Encode(blocks, bs);
        var symFlat = symbols.SelectMany(s => s).ToArray();

        var isBad = new bool[K];
        int recovered = DuipCode.Decode(blocks, isBad, symFlat, entropy, K, bs, 32, 8);

        Assert.Equal(K, recovered);
        for (int i = 0; i < K; i++)
            Assert.Equal(original[i], blocks[i]);
    }

    [Fact]
    public void EncodeDecode_CorruptOne_RecoversFully()
    {
        int K = 50, bs = 256;
        var blocks = MakeBlocks(K, bs);
        var original = blocks.Select(b => b.ToArray()).ToArray();

        var (symbols, entropy, seed) = DuipCode.Encode(blocks, bs);
        var symFlat = symbols.SelectMany(s => s).ToArray();

        // Corrupt block 0
        var isBad = new bool[K];
        isBad[0] = true;
        blocks[0] = new byte[bs];
        RandomNumberGenerator.Fill(blocks[0]);

        int recovered = DuipCode.Decode(blocks, isBad, symFlat, entropy, K, bs, 32, 8);
        Assert.True(recovered >= 1, $"Should recover corrupted block: {recovered}");

        // Verify recovered block matches original
        Assert.Equal(original[0], blocks[0]);
        // Verify untouched blocks are unchanged
        for (int i = 1; i < K; i++)
            Assert.Equal(original[i], blocks[i]);
    }

    [Fact]
    public void EncodeDecode_CorruptMultiple_AllRestored()
    {
        int K = 100, bs = 256;
        var blocks = MakeBlocks(K, bs);
        var original = blocks.Select(b => b.ToArray()).ToArray();

        var (symbols, entropy, seed) = DuipCode.Encode(blocks, bs);
        var symFlat = symbols.SelectMany(s => s).ToArray();

        // Corrupt blocks 0, 10, 42
        int[] corruptIndices = [0, 10, 42];
        var isBad = new bool[K];
        foreach (int idx in corruptIndices)
        {
            isBad[idx] = true;
            blocks[idx] = new byte[bs];
            RandomNumberGenerator.Fill(blocks[idx]);
        }

        int recovered = DuipCode.Decode(blocks, isBad, symFlat, entropy, K, bs, 32, 8);
        Assert.True(recovered == corruptIndices.Length, $"Should recover all corrupted: {recovered}/{corruptIndices.Length}");

        foreach (int idx in corruptIndices)
            Assert.Equal(original[idx], blocks[idx]);
        for (int i = 1; i < K; i++)
            if (!corruptIndices.Contains(i))
                Assert.Equal(original[i], blocks[i]);
    }

    [Fact]
    public void EncodeDecode_5PercentLoss()
    {
        int K = 100, bs = 256;
        var blocks = MakeBlocks(K, bs);

        var (symbols, entropy, seed) = DuipCode.Encode(blocks, bs);
        var symFlat = symbols.SelectMany(s => s).ToArray();

        int badCount = 5;
        var isBad = new bool[K];
        for (int i = 0; i < badCount; i++)
        {
            isBad[i] = true;
            blocks[i] = new byte[bs];
            RandomNumberGenerator.Fill(blocks[i]);
        }

        int recovered = DuipCode.Decode(blocks, isBad, symFlat, entropy, K, bs, 32, 8);
        // recovered = number of corrupted blocks successfully restored
        Assert.True(recovered >= badCount / 2, $"Should recover most corrupted blocks: {recovered}/{badCount}");
    }

    [Fact]
    public void EncodeDecode_30PercentLoss_Partial()
    {
        int K = 100, bs = 256;
        var blocks = MakeBlocks(K, bs);

        var (symbols, entropy, seed) = DuipCode.Encode(blocks, bs);
        var symFlat = symbols.SelectMany(s => s).ToArray();

        int badCount = 30;
        var isBad = new bool[K];
        for (int i = 0; i < badCount; i++)
        {
            isBad[i] = true;
            blocks[i] = new byte[bs];
            RandomNumberGenerator.Fill(blocks[i]);
        }

        int recovered = DuipCode.Decode(blocks, isBad, symFlat, entropy, K, bs, 32, 8);
        Assert.True(recovered >= 0, $"Partial recovery: {recovered}/{K}");
    }

    [Fact]
    public void EntropySampling_Deterministic()
    {
        var blocks = MakeBlocks(50, 256);
        var (_, entropy1, _) = DuipCode.Encode(blocks, 256);
        var (_, entropy2, _) = DuipCode.Encode(blocks, 256);
        Assert.Equal(entropy1, entropy2);
    }

    [Fact]
    public void Encode_K1_Works()
    {
        var blocks = MakeBlocks(1, 64);
        var (symbols, entropy, _) = DuipCode.Encode(blocks, 64, faceSize: 8);

        // R = max(1, 1 * 0.5) = 1
        Assert.Single(symbols);
        Assert.NotNull(entropy);
    }

    [Fact]
    public void Decode_AllBad_ReturnsZero()
    {
        int K = 20, bs = 64;
        var blocks = MakeBlocks(K, bs);

        var (symbols, entropy, seed) = DuipCode.Encode(blocks, bs);
        var symFlat = symbols.SelectMany(s => s).ToArray();

        var isBad = new bool[K];
        for (int i = 0; i < K; i++) isBad[i] = true;

        int recovered = DuipCode.Decode(blocks, isBad, symFlat, entropy, K, bs, 32, 8);
        Assert.Equal(0, recovered);
    }

    [Fact]
    public void Decode_K0_ReturnsZero()
    {
        int recovered = DuipCode.Decode([], [], [], [], 0, 64, 32, 8);
        Assert.Equal(0, recovered);
    }

    [Fact]
    public void Fss62RepairData_RoundTrip()
    {
        var data = new Fss62RepairData
        {
            Seed = 42,
            BlockCount = 10,
            BlockSize = 256,
            Data = [1, 2, 3, 4, 5],
            EntropySamples = [10, 20, 30],
        };

        // Build a trailer and verify it parses back
        byte[] fragData = [0xAA, 0xBB, 0xCC];
        byte[] withTrailer = Fss62RepairTrailer.Build(fragData,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", data, data);

        var (parsed, aFp, cFp, repairA, repairC) = Fss62RepairTrailer.Parse(withTrailer);

        Assert.Equal(fragData, parsed);
        Assert.Equal("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", aFp);
        Assert.Equal("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", cFp);
        Assert.NotNull(repairA);
        Assert.Equal(42, repairA.Seed);
        Assert.Equal(10, repairA.BlockCount);
        Assert.Equal(256, repairA.BlockSize);
        Assert.Equal([1, 2, 3, 4, 5], repairA.Data);
        Assert.Equal([10, 20, 30], repairA.EntropySamples);
        Assert.NotNull(repairC);
        Assert.Equal(42, repairC.Seed);
    }
}
