using System.Security.Cryptography;
using RDRF.Core.FSS;
using Xunit;

namespace RDRF.Core.Tests;

public class PrecodeTests
{
    [Fact]
    public void Encode_Size_Kto2K()
    {
        var src = MakeBlocks(5, 256);
        var inter = Precode.Encode(src, 256);
        Assert.Equal(10, inter.Length);
    }

    [Fact]
    public void Encode_Ladder_MatchesDefinition()
    {
        var src = MakeBlocks(4, 64);
        var inter = Precode.Encode(src, 64);

        for (int i = 0; i < 3; i++)
        {
            byte[] expected = Xor(src[i], src[i + 1], 64);
            Assert.Equal(expected, inter[4 + i]);
        }
    }

    [Fact]
    public void Encode_Global_XorOfAll()
    {
        var src = MakeBlocks(3, 32);
        var inter = Precode.Encode(src, 32);

        byte[] expected = new byte[32];
        for (int i = 0; i < 3; i++)
            expected = Xor(expected, src[i], 32);

        Assert.Equal(expected, inter[5]);
    }

    [Fact]
    public void Derive_Ladder_WhenSourcesKnown()
    {
        int K = 4, bs = 16;
        var src = MakeBlocks(K, bs);
        var inter = Precode.Encode(src, bs);

        var known = new bool[2 * K];
        for (int i = 0; i < K; i++) known[i] = true;

        var derived = new byte[2 * K][];
        for (int i = 0; i < K; i++)
            derived[i] = inter[i];

        Precode.Derive(derived, known, K, bs);

        Assert.True(known[K]);     // ladder[0] derived
        Assert.True(known[K + 1]); // ladder[1] derived
    }

    [Fact]
    public void Derive_Global_WhenAllSourcesKnown()
    {
        int K = 3, bs = 16;
        var src = MakeBlocks(K, bs);
        var inter = Precode.Encode(src, bs);

        var known = new bool[2 * K];
        for (int i = 0; i < K; i++) known[i] = true;
        var derived = new byte[2 * K][];
        for (int i = 0; i < K; i++) derived[i] = inter[i];

        Precode.Derive(derived, known, K, bs);

        Assert.True(known[2 * K - 1]);
    }

    [Fact]
    public void Unlock_LadderForward()
    {
        int K = 3, bs = 32;
        var src = MakeBlocks(K, bs);
        var inter = Precode.Encode(src, bs);

        var known = new bool[2 * K];
        var srcKnown = new bool[K];
        var allBlocks = MakeBlocks(K, bs);
        for (int i = 0; i < K; i++) Buffer.BlockCopy(src[i], 0, allBlocks[i], 0, bs);

        known[0] = true; srcKnown[0] = true;
        known[K] = true;  // ladder[0] = s0 XOR s1

        int recovered = Precode.Unlock(inter, known, srcKnown, allBlocks, K, bs);

        Assert.True(recovered >= 1);
        Assert.True(srcKnown[1]);
    }

    [Fact]
    public void Unlock_LadderBackward()
    {
        int K = 3, bs = 32;
        var src = MakeBlocks(K, bs);
        var inter = Precode.Encode(src, bs);

        var known = new bool[2 * K];
        var srcKnown = new bool[K];
        var allBlocks = MakeBlocks(K, bs);
        for (int i = 0; i < K; i++) Buffer.BlockCopy(src[i], 0, allBlocks[i], 0, bs);

        known[2] = true; srcKnown[2] = true;
        known[K + 1] = true; // ladder[1] = s1 XOR s2

        int recovered = Precode.Unlock(inter, known, srcKnown, allBlocks, K, bs);

        Assert.True(recovered >= 1);
        Assert.True(srcKnown[1]);
    }

    [Fact]
    public void Unlock_Global()
    {
        int K = 4, bs = 16;
        var src = MakeBlocks(K, bs);
        var inter = Precode.Encode(src, bs);

        var known = new bool[2 * K];
        var srcKnown = new bool[K];
        var allBlocks = MakeBlocks(K, bs);
        for (int i = 0; i < K; i++) Buffer.BlockCopy(src[i], 0, allBlocks[i], 0, bs);

        for (int i = 0; i < K - 1; i++) { known[i] = true; srcKnown[i] = true; }
        known[2 * K - 1] = true; // global

        int recovered = Precode.Unlock(inter, known, srcKnown, allBlocks, K, bs);

        Assert.True(recovered >= 1);
        Assert.True(srcKnown[K - 1]);
    }

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

    private static byte[] Xor(byte[] a, byte[] b, int len)
    {
        if (a.Length == 0) return (byte[])b.Clone();
        byte[] r = new byte[len];
        for (int i = 0; i < len; i++)
            r[i] = (byte)(a[i] ^ b[i]);
        return r;
    }
}
