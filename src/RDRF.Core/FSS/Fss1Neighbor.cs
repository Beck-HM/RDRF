using RDRF.Core.Index;

namespace RDRF.Core.FSS;

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
        int totalFragents,
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

                // Try left neighbor
                int leftIdx = (missingIdx - 1 + totalFragents) % totalFragents;
                if (work.ContainsKey(leftIdx))
                {
                    byte[] neighborData = work[leftIdx];
                    if (originalSizes != null && leftIdx < originalSizes.Count)
                    {
                        int leftSize = originalSizes[leftIdx];
                        if (neighborData.Length > leftSize)
                        {
                            byte[] recovered = new byte[neighborData.Length - leftSize];
                            Buffer.BlockCopy(neighborData, leftSize, recovered, 0, recovered.Length);
                            result[missingIdx] = recovered;
                            work[missingIdx] = recovered;
                            madeProgress = true;
                            continue;
                        }
                    }
                    else
                    {
                        int half = neighborData.Length / 2;
                        byte[] recovered = new byte[half];
                        Buffer.BlockCopy(neighborData, half, recovered, 0, half);
                        result[missingIdx] = recovered;
                        work[missingIdx] = recovered;
                        madeProgress = true;
                        continue;
                    }
                }

                // Try right neighbor
                int rightIdx = (missingIdx + 1) % totalFragents;
                if (work.ContainsKey(rightIdx))
                {
                    byte[] neighborData = work[rightIdx];
                    if (originalSizes != null && missingIdx < originalSizes.Count)
                    {
                        int missingSize = originalSizes[missingIdx];
                        if (neighborData.Length >= missingSize)
                        {
                            byte[] recovered = new byte[missingSize];
                            Buffer.BlockCopy(neighborData, 0, recovered, 0, missingSize);
                            result[missingIdx] = recovered;
                            work[missingIdx] = recovered;
                            madeProgress = true;
                        }
                    }
                    else
                    {
                        int half = neighborData.Length / 2;
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
        Dictionary<int, byte[]> encodedFragents,
        int originalFragentCount,
        List<int>? originalSizes = null)
    {
        var result = new List<byte[]>();
        for (int i = 0; i < originalFragentCount; i++)
        {
            if (!encodedFragents.TryGetValue(i, out var data)) continue;

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
}
