using System.Diagnostics;
using System.Security.Cryptography;
using RDRF.Core.Index;

namespace RDRF.Core.FSS;

/// <summary>
/// FSS1: neighbor duplication. Each fragment stores self + next fragment (concatenated).
/// </summary>

public class Fss1Neighbor : IFssStrategy
{
    public string Level => Constants.FssLevel1;

    /// <summary>
    /// Encode self||next for each fragment. Uses sequential windowed residency:
    /// after fragment i is encoded, raw[i] is released when no longer needed as a neighbor
    /// (raw[0] kept until the ring wrap of the last fragment). Peak ≈ 2× file (encoded)
    /// instead of raw + encoded ≈ 3× during a full parallel materialize.
    /// Mutates <paramref name="fragments"/> slots to null as raw is released.
    /// </summary>
    public List<byte[]> Encode(List<byte[]> fragments)
    {
        int n = fragments.Count;
        if (n == 0) return new List<byte[]>();

        if (n == 1)
        {
            byte[] only = fragments[0];
            byte[] combined = new byte[checked(only.Length * 2)];
            Buffer.BlockCopy(only, 0, combined, 0, only.Length);
            Buffer.BlockCopy(only, 0, combined, only.Length, only.Length);
            CryptographicOperations.ZeroMemory(only);
            fragments[0] = null!;
            return new List<byte[]> { combined };
        }

        var encoded = new byte[n][];
        // Keep frag0 alive until last ring wrap (next of n-1).
        byte[] first = fragments[0];

        for (int i = 0; i < n - 1; i++)
        {
            byte[] self = fragments[i] ?? throw new InvalidOperationException($"FSS1.Encode: raw[{i}] already released");
            byte[] next = fragments[i + 1] ?? throw new InvalidOperationException($"FSS1.Encode: raw[{i + 1}] already released");
            byte[] combined = new byte[checked(self.Length + next.Length)];
            Buffer.BlockCopy(self, 0, combined, 0, self.Length);
            Buffer.BlockCopy(next, 0, combined, self.Length, next.Length);
            encoded[i] = combined;

            // raw[i] was self for i and next for i-1 (already done). Keep raw[0] for wrap.
            if (i >= 1)
            {
                CryptographicOperations.ZeroMemory(self);
                fragments[i] = null!;
            }
        }

        // Last: self = n-1, next = first (ring)
        {
            byte[] self = fragments[n - 1] ?? throw new InvalidOperationException($"FSS1.Encode: raw[{n - 1}] already released");
            byte[] combined = new byte[checked(self.Length + first.Length)];
            Buffer.BlockCopy(self, 0, combined, 0, self.Length);
            Buffer.BlockCopy(first, 0, combined, self.Length, first.Length);
            encoded[n - 1] = combined;
            CryptographicOperations.ZeroMemory(self);
            fragments[n - 1] = null!;
            CryptographicOperations.ZeroMemory(first);
            fragments[0] = null!;
        }

        return new List<byte[]>(encoded);
    }

    public Dictionary<int, byte[]> Decode(
        Dictionary<int, byte[]> available,
        List<int> missingIndices,
        int totalFragments,
        List<int>? originalSizes = null)
    {
        var result = new Dictionary<int, byte[]>();
        var work = new Dictionary<int, byte[]>(available);

        bool madeProgress;
        do
        {
            madeProgress = false;
            var toRecover = new List<int>(missingIndices);

            foreach (int missingIdx in toRecover)
            {
                if (result.ContainsKey(missingIdx)) continue;

                int leftIdx = (missingIdx - 1 + totalFragments) % totalFragments;
                if (work.ContainsKey(leftIdx))
                {
                    byte[] neighborData = work[leftIdx];
                    int half = neighborData.Length / 2;
                    if (neighborData.Length > half)
                    {
                        byte[] recovered = new byte[neighborData.Length - half];
                        Buffer.BlockCopy(neighborData, half, recovered, 0, recovered.Length);
                        result[missingIdx] = recovered;
                        work[missingIdx] = recovered;
                        madeProgress = true;
                        continue;
                    }
                }

                int rightIdx = (missingIdx + 1) % totalFragments;
                if (work.ContainsKey(rightIdx))
                {
                    byte[] neighborData = work[rightIdx];
                    int half = neighborData.Length / 2;
                    if (neighborData.Length >= half)
                    {
                        byte[] recovered = new byte[half];
                        Buffer.BlockCopy(neighborData, 0, recovered, 0, half);
                        result[missingIdx] = recovered;
                        work[missingIdx] = recovered;
                        madeProgress = true;
                    }
                }
            }
        } while (madeProgress);

        return result;
    }

    public List<byte[]> Strip(
        Dictionary<int, byte[]> encodedFragments,
        int originalFragmentCount,
        List<int>? originalSizes = null)
    {
        var result = new List<byte[]>();
        for (int i = 0; i < originalFragmentCount; i++)
        {
            if (!encodedFragments.TryGetValue(i, out var data)) continue;

            if (originalSizes != null && i < originalSizes.Count)
            {
                int originalSize = originalSizes[i];
                if (data.Length >= originalSize)
                {
                    byte[] stripped = new byte[originalSize];
                    Buffer.BlockCopy(data, 0, stripped, 0, originalSize);
                    result.Add(stripped);
                }
            }
            else
            {
                int half = data.Length / 2;
                byte[] stripped = new byte[half];
                Buffer.BlockCopy(data, 0, stripped, 0, half);
                result.Add(stripped);
            }
        }
        return result;
    }

    public byte[] StripSingle(byte[] encodedFragment, int index, List<int>? originalSizes = null)
    {
        if (originalSizes != null && index < originalSizes.Count && originalSizes[index] > 0)
        {
            int size = originalSizes[index];
            if (size > encodedFragment.Length)
                throw new RdrfException(ErrorCode.FssEncodingFailed, $"FSS1.StripSingle[{index}]: originalSize={size} > fragLen={encodedFragment.Length}");
            byte[] stripped = new byte[size];
            Buffer.BlockCopy(encodedFragment, 0, stripped, 0, size);
            return stripped;
        }
        int half = encodedFragment.Length / 2;
        byte[] result = new byte[half];
        Buffer.BlockCopy(encodedFragment, 0, result, 0, half);
        return result;
    }
}

