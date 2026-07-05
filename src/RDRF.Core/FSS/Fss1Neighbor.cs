using System.Diagnostics;
using RDRF.Core.Index;

namespace RDRF.Core.FSS;

/// <summary>
/// FSS1: neighbor duplication. Each fragment stores self + next fragment (concatenated).
/// </summary>

public class Fss1Neighbor : IFssStrategy
{
    public string Level => Constants.FssLevel1;

    public List<byte[]> Encode(List<byte[]> fragments)
    {
        int n = fragments.Count;
        var encoded = new List<byte[]>(n);
        for (int i = 0; i < n; i++)
        {
            int nextIdx = (i + 1) % n;
            byte[] combined = new byte[fragments[i].Length + fragments[nextIdx].Length];
            Buffer.BlockCopy(fragments[i], 0, combined, 0, fragments[i].Length);
            Buffer.BlockCopy(fragments[nextIdx], 0, combined, fragments[i].Length, fragments[nextIdx].Length);
            encoded.Add(combined);
        }
        return encoded;
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
                throw new InvalidOperationException($"FSS1.StripSingle[{index}]: originalSize={size} > fragLen={encodedFragment.Length}");
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

