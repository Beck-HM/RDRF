using System.Diagnostics;
using System.Security.Cryptography;
using RDRF.Core.Index;
using RDRF.Core.Integrity;

namespace RDRF.Core.FSS;

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

        // Merge all fragments into a single byte array padded to K*blockSize
        byte[] fileBytes = new byte[K * blockSize];
        int offset = 0;
        foreach (var f in fragments)
        {
            Buffer.BlockCopy(f, 0, fileBytes, offset, f.Length);
            offset += f.Length;
        }

        // Split into K data blocks
        byte[][] dataBlocks = new byte[K][];
        for (int i = 0; i < K; i++)
        {
            dataBlocks[i] = new byte[blockSize];
            int srcOff = i * blockSize;
            int copyLen = Math.Min(blockSize, fileBytes.Length - srcOff);
            Buffer.BlockCopy(fileBytes, srcOff, dataBlocks[i], 0, copyLen);
        }

        // RS(K, K): K data + K parity = 2K total blocks
        var rs = new ReedSolomon(K, K);
        byte[][] allBlocks = new byte[2 * K][];
        for (int i = 0; i < K; i++)
            allBlocks[i] = dataBlocks[i];
        for (int i = K; i < 2 * K; i++)
            allBlocks[i] = new byte[blockSize];
        rs.Encode(allBlocks);

        // Build K seeds, each containing blocks[0..2K-2] + fingerprint table
        int blocksPerSeed = 2 * K - 1;
        int seedDataSize = blocksPerSeed * blockSize;
        int fingerprintSize = blocksPerSeed * 8;
        byte[][] seeds = new byte[K][];

        for (int s = 0; s < K; s++)
        {
            byte[] seed = new byte[seedDataSize + fingerprintSize];

            // Copy blocks 0..2K-2
            for (int b = 0; b < blocksPerSeed; b++)
                Buffer.BlockCopy(allBlocks[b], 0, seed, b * blockSize, blockSize);

            // Build and append fingerprint table (first 8 bytes of SHA-256 per block)
            for (int b = 0; b < blocksPerSeed; b++)
            {
                Span<byte> hash = stackalloc byte[32];
                SHA256.HashData(allBlocks[b], hash);
                Buffer.BlockCopy(hash.ToArray(), 0, seed, seedDataSize + b * 8, 8);
            }

            seeds[s] = seed;
        }

        return seeds.ToList();
    }

    private List<byte[]>? DecodeFromSeed(byte[] seed, int K, int blockSize, List<int>? originalSizes = null)
    {
        int blocksPerSeed = 2 * K - 1;
        int seedDataSize = blocksPerSeed * blockSize;

        byte[][] allBlocks = new byte[2 * K][];
        var validIndices = new List<int>(blocksPerSeed);

        for (int b = 0; b < blocksPerSeed; b++)
        {
            int blockOff = b * blockSize;
            byte[] block = new byte[blockSize];
            Buffer.BlockCopy(seed, blockOff, block, 0, blockSize);
            allBlocks[b] = block;

            // Verify fingerprint (first 8 bytes of SHA-256)
            byte[] expected = new byte[8];
            Buffer.BlockCopy(seed, seedDataSize + b * 8, expected, 0, 8);
            byte[] actual = SHA256.HashData(block);

            bool valid = true;
            for (int i = 0; i < 8; i++)
            {
                if (expected[i] != actual[i]) { valid = false; break; }
            }

            if (valid)
                validIndices.Add(b);
        }

        // Zero-fill missing blocks (including last parity block 2K-1 never in seed)
        for (int b = blocksPerSeed; b < 2 * K; b++)
            allBlocks[b] = new byte[blockSize];

        if (validIndices.Count < K)
        {
            Debug.WriteLine($"[Fss5PSend] Insufficient valid blocks: {validIndices.Count} < {K}");
            return null;
        }

        // RS decode using all valid blocks
        var rs = new ReedSolomon(K, K);
        var erasures = new List<int>();
        for (int i = 0; i < 2 * K; i++)
            if (!validIndices.Contains(i))
                erasures.Add(i);

        if (!rs.Decode(allBlocks, erasures))
        {
            Debug.WriteLine("[Fss5PSend] RS decode failed");
            return null;
        }

        // Reconstruct original fragments from data blocks[0..K-1]
        var result = new List<byte[]>(K);
        for (int i = 0; i < K; i++)
        {
            byte[] raw = allBlocks[i];
            int actualSize = originalSizes != null && i < originalSizes.Count
                ? originalSizes[i]
                : blockSize;

            if (actualSize < blockSize)
            {
                byte[] trimmed = new byte[actualSize];
                Buffer.BlockCopy(raw, 0, trimmed, 0, actualSize);
                result.Add(trimmed);
            }
            else
            {
                result.Add(raw);
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
        t_cache = null;
        t_cacheKey = null;

        var result = new Dictionary<int, byte[]>();
        if (available.Count == 0) return result;

        var first = available.First();
        int K = totalFragments;
        int blocksPerSeed = 2 * K - 1;
        int seedDataSize = first.Value.Length - blocksPerSeed * 8;
        int blockSize = seedDataSize / blocksPerSeed;

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
        t_cache = null;
        t_cacheKey = null;

        if (encodedFragments.Count == 0) return new List<byte[]>();

        var first = encodedFragments.First();
        int K = originalFragmentCount;
        int blocksPerSeed = 2 * K - 1;
        int seedDataSize = first.Value.Length - blocksPerSeed * 8;
        int blockSize = seedDataSize / blocksPerSeed;

        var allFrags = DecodeFromSeed(first.Value, K, blockSize, originalSizes);
        return allFrags ?? new List<byte[]>();
    }

    public byte[] StripSingle(byte[] encodedFragment, int index, List<int>? originalSizes = null)
    {
        // If the fragment is already at original size, return it directly
        if (originalSizes != null && index < originalSizes.Count && encodedFragment.Length <= originalSizes[index])
            return encodedFragment;

        // Identify the seed by its first 32 bytes to detect session changes
        byte[] key = new byte[32];
        int keyLen = Math.Min(32, encodedFragment.Length);
        Buffer.BlockCopy(encodedFragment, 0, key, 0, keyLen);

        if (t_cache == null || t_cacheKey == null || !t_cacheKey.AsSpan().SequenceEqual(key.AsSpan()))
        {
            int K = originalSizes?.Count ?? 0;
            if (K == 0)
                return encodedFragment;

            int blocksPerSeed = 2 * K - 1;
            int seedDataSize = encodedFragment.Length - blocksPerSeed * 8;
            int blockSize = seedDataSize / blocksPerSeed;

            t_cache = DecodeFromSeed(encodedFragment, K, blockSize, originalSizes);
            t_cacheKey = key;
        }

        if (t_cache != null && index >= 0 && index < t_cache.Count)
            return t_cache[index];

        return Array.Empty<byte>();
    }
}
