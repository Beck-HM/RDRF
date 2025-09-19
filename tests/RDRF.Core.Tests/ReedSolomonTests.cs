using System.Security.Cryptography;
using RDRF.Core.FSS;
using Xunit;

namespace RDRF.Core.Tests;

public class ReedSolomonTests
{
    [Fact]
    public void Encode_ProducesCorrectShardCount()
    {
        int k = 4, p = 2;
        var rs = new ReedSolomon(k, p);
        var shards = MakeShards(k, p, 64);
        rs.Encode(shards);
        Assert.Equal(k + p, shards.Length);
    }

    [Fact]
    public void Encode_ParityShards_AreNonZero()
    {
        int k = 3, p = 2;
        var rs = new ReedSolomon(k, p);
        var shards = MakeShards(k, p, 32);
        rs.Encode(shards);
        for (int i = k; i < k + p; i++)
            Assert.Contains(shards[i], b => b != 0);
    }

    [Fact]
    public void Decode_SingleErasure_Recovers()
    {
        int k = 4, p = 2;
        var rs = new ReedSolomon(k, p);
        var original = MakeShards(k, p, 64);
        var shards = CloneShards(original);

        rs.Encode(shards);

        // Corrupt data shard 1
        var erasures = new List<int> { 1 };
        RandomNumberGenerator.Fill(shards[1]);

        bool ok = rs.Decode(shards, erasures);
        Assert.True(ok);
        Assert.Equal(original[1], shards[1]);
    }

    [Fact]
    public void Decode_MultipleErasures_Recovers()
    {
        int k = 5, p = 3;
        var rs = new ReedSolomon(k, p);
        var original = MakeShards(k, p, 64);
        var shards = CloneShards(original);

        rs.Encode(shards);
        var encoded = CloneShards(shards); // snapshot after encode

        var erasures = new List<int> { 0, 2, k + 1 };
        foreach (int idx in erasures)
            RandomNumberGenerator.Fill(shards[idx]);

        bool ok = rs.Decode(shards, erasures);
        Assert.True(ok);
        foreach (int idx in erasures)
            Assert.Equal(encoded[idx], shards[idx]);
    }

    [Fact]
    public void Decode_TooManyErasures_ReturnsFalse()
    {
        int k = 3, p = 1;
        var rs = new ReedSolomon(k, p);
        var shards = MakeShards(k, p, 32);
        rs.Encode(shards);

        // 2 erasures but only 1 parity → should fail
        var erasures = new List<int> { 0, 1 };
        bool ok = rs.Decode(shards, erasures);
        Assert.False(ok);
    }

    [Fact]
    public void Decode_IdentityMatrix_WhenParityOnlyLost()
    {
        int k = 4, p = 2;
        var rs = new ReedSolomon(k, p);
        var original = MakeShards(k, p, 64);
        var shards = CloneShards(original);

        rs.Encode(shards);
        var encoded = CloneShards(shards); // snapshot after encode

        // Only parity shards lost → identity decode path
        var erasures = new List<int> { k, k + 1 };
        for (int i = k; i < k + p; i++)
            RandomNumberGenerator.Fill(shards[i]);

        bool ok = rs.Decode(shards, erasures);
        Assert.True(ok);
        // Recovered parity should match encoded parity
        Assert.Equal(encoded[k], shards[k]);
        Assert.Equal(encoded[k + 1], shards[k + 1]);
    }

    [Fact]
    public void Decode_CacheKey_ReusesInvertedMatrix()
    {
        int k = 4, p = 2;
        var rs = new ReedSolomon(k, p);
        var original = MakeShards(k, p, 32);
        var shards = CloneShards(original);
        rs.Encode(shards);

        // Decode with same erasure pattern twice
        var erasures = new List<int> { 0, k };
        RandomNumberGenerator.Fill(shards[0]);
        RandomNumberGenerator.Fill(shards[k]);
        bool ok1 = rs.Decode(shards, erasures);
        Assert.True(ok1);

        // Reset and decode same pattern
        var shards2 = CloneShards(original);
        rs.Encode(shards2);
        RandomNumberGenerator.Fill(shards2[0]);
        RandomNumberGenerator.Fill(shards2[k]);
        bool ok2 = rs.Decode(shards2, erasures);
        Assert.True(ok2);
        Assert.Equal(original[0], shards2[0]);
    }

    [Fact]
    public void EncodeDecode_RoundTrip_LargeShards()
    {
        int k = 6, p = 2, shardSize = 1024;
        var rs = new ReedSolomon(k, p);
        var original = MakeShards(k, p, shardSize);
        var shards = CloneShards(original);

        rs.Encode(shards);

        var erasures = new List<int> { 2, 3 };
        RandomNumberGenerator.Fill(shards[2]);
        RandomNumberGenerator.Fill(shards[3]);

        bool ok = rs.Decode(shards, erasures);
        Assert.True(ok);
        Assert.Equal(original[2], shards[2]);
        Assert.Equal(original[3], shards[3]);
    }

    private static byte[][] MakeShards(int dataShards, int parityShards, int shardSize)
    {
        var shards = new byte[dataShards + parityShards][];
        for (int i = 0; i < dataShards + parityShards; i++)
        {
            shards[i] = new byte[shardSize];
            if (i < dataShards)
                RandomNumberGenerator.Fill(shards[i]);
        }
        return shards;
    }

    private static byte[][] CloneShards(byte[][] shards)
    {
        var clone = new byte[shards.Length][];
        for (int i = 0; i < shards.Length; i++)
        {
            clone[i] = new byte[shards[i].Length];
            Buffer.BlockCopy(shards[i], 0, clone[i], 0, shards[i].Length);
        }
        return clone;
    }
}
