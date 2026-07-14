using System.Buffers;
using RDRF.Core.Logging;using System.Diagnostics;
using System.IO.Hashing;
using RDRF.Core.Index;

namespace RDRF.Core.FSS;

/// <summary>
/// FSS5+: seed-based RS(K,K). Any single fragment can rebuild all data.
/// </summary>

public class Fss5PSend : IFssStrategy
{
    public string Level => Constants.FssLevel5P;

    [ThreadStatic]
    private static List<byte[]>? t_cache;
    [ThreadStatic]
    private static byte[]? t_cacheKey;

    public List<byte[]> Encode(List<byte[]> fragments)
    {
        int K = fragments.Count;
        int blockSize = fragments[0].Length;

        byte[] fileBytes = ArrayPool<byte>.Shared.Rent(K * blockSize);
        byte[][] dataBlocks = new byte[K][];
        byte[][] allBlocks = new byte[2 * K][];
        try
        {
            int offset = 0;
            foreach (var f in fragments)
            {
                Buffer.BlockCopy(f, 0, fileBytes, offset, f.Length);
                offset += f.Length;
            }

            for (int i = 0; i < K; i++)
            {
                dataBlocks[i] = ArrayPool<byte>.Shared.Rent(blockSize);
                int srcOff = i * blockSize;
                int copyLen = Math.Min(blockSize, K * blockSize - srcOff);
                Buffer.BlockCopy(fileBytes, srcOff, dataBlocks[i], 0, copyLen);
            }

            var rs = new ReedSolomon(K, K);
            for (int i = 0; i < K; i++)
                allBlocks[i] = dataBlocks[i];
            // rs.Encode allocates parity shards internally
            rs.Encode(allBlocks);

            int seedDataSize = K * blockSize;
            int fingerprintSize = K * 8;
            byte[] template = new byte[seedDataSize + fingerprintSize];

            for (int b = 0; b < K; b++)
                Buffer.BlockCopy(allBlocks[b], 0, template, b * blockSize, blockSize);

            for (int b = 0; b < K; b++)
            {
                var hash = XxHash128.Hash(allBlocks[b]);
                Buffer.BlockCopy(hash, 0, template, seedDataSize + b * 8, 8);
            }

            var result = new List<byte[]>(K);
            for (int s = 0; s < K; s++)
            {
                byte[] clone = new byte[template.Length];
                Buffer.BlockCopy(template, 0, clone, 0, template.Length);
                result.Add(clone);
            }

            return result;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(fileBytes);
            for (int i = 0; i < K; i++)
                if (dataBlocks[i] != null)
                    ArrayPool<byte>.Shared.Return(dataBlocks[i]);
        }
    }

    private List<byte[]>? DecodeFromSeed(byte[] seed, int K, int blockSize, List<int>? originalSizes = null)
    {
        int seedDataSize = K * blockSize;

        for (int b = 0; b < K; b++)
        {
            var actualHash = XxHash128.Hash(seed.AsSpan(b * blockSize, blockSize));
            if (!actualHash.AsSpan(0, 8).SequenceEqual(
                seed.AsSpan(seedDataSize + b * 8, 8)))
            {
                RdrfLogger.Default.Debug("",$"[Fss5PSend] Seed block {b} fingerprint mismatch");
                return null;
            }
        }

        var result = new List<byte[]>(K);
        for (int i = 0; i < K; i++)
        {
            int rawOff = i * blockSize;
            int actualSize = originalSizes != null && i < originalSizes.Count
                ? originalSizes[i]
                : blockSize;

            if (actualSize < blockSize)
            {
                byte[] trimmed = new byte[actualSize];
                Buffer.BlockCopy(seed, rawOff, trimmed, 0, actualSize);
                result.Add(trimmed);
            }
            else
            {
                byte[] frag = new byte[blockSize];
                Buffer.BlockCopy(seed, rawOff, frag, 0, blockSize);
                result.Add(frag);
            }
        }

        return result;
    }

    public Dictionary<int, byte[]> Decode(
        Dictionary<int, byte[]> available,
        List<int> missingIndices,
        int totalFragments,
        List<int>? originalSizes = null)
    {
        var result = new Dictionary<int, byte[]>();
        if (available.Count == 0) return result;

        var first = available.First();
        int K = totalFragments;
        int seedDataSize = first.Value.Length - K * 8;
        if (seedDataSize <= 0) return result;
        int blockSize = seedDataSize / K;

        var allFrags = DecodeFromSeed(first.Value, K, blockSize, originalSizes);
        if (allFrags == null) return result;

        foreach (int idx in missingIndices)
            if (idx >= 0 && idx < allFrags.Count)
                result[idx] = allFrags[idx];

        return result;
    }

    public List<byte[]> Strip(
        Dictionary<int, byte[]> encodedFragments,
        int originalFragmentCount,
        List<int>? originalSizes = null)
    {
        if (encodedFragments.Count == 0) return new List<byte[]>();

        var first = encodedFragments.First();
        int K = originalFragmentCount;
        int seedDataSize = first.Value.Length - K * 8;
        int blockSize = seedDataSize / K;

        var allFrags = DecodeFromSeed(first.Value, K, blockSize, originalSizes);
        return allFrags ?? new List<byte[]>();
    }

    public byte[] StripSingle(byte[] encodedFragment, int index, List<int>? originalSizes = null)
    {
        if (originalSizes != null && index < originalSizes.Count && encodedFragment.Length <= originalSizes[index])
            return encodedFragment;

        byte[] key = new byte[32];
        int keyLen = Math.Min(32, encodedFragment.Length);
        Buffer.BlockCopy(encodedFragment, 0, key, 0, keyLen);

        if (t_cache == null || t_cacheKey == null || !t_cacheKey.AsSpan().SequenceEqual(key.AsSpan()))
        {
            int K = originalSizes?.Count ?? 0;
            if (K == 0)
                return encodedFragment;

            int seedDataSize = encodedFragment.Length - K * 8;
            int blockSize = seedDataSize / K;

            t_cache = DecodeFromSeed(encodedFragment, K, blockSize, originalSizes);
            t_cacheKey = key;
        }

        if (t_cache != null && index >= 0 && index < t_cache.Count)
            return t_cache[index];

        return Array.Empty<byte>();
    }
}

