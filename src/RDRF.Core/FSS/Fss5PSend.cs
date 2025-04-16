using RDRF.Core.Index;
using RDRF.Core.Integrity;

namespace RDRF.Core.FSS;

public class Fss5PSend : IFssStrategy
{
    public string Level => Constants.FssLevel5P;

    public List<byte[]> Encode(List<byte[]> fragments)
    {
        int n = fragments.Count;
        var result = new List<byte[]>(n);
        for (int i = 0; i < n; i++)
        {
            int nextIdx = (i + 1) % n;
            byte[] cur = fragments[i];
            byte[] next = fragments[nextIdx];
            byte[] combined = new byte[cur.Length + next.Length];
            Buffer.BlockCopy(cur, 0, combined, 0, cur.Length);
            Buffer.BlockCopy(next, 0, combined, cur.Length, next.Length);
            result.Add(combined);
        }
        return result;
    }

    public Dictionary<int, byte[]> Decode(
        Dictionary<int, byte[]> available,
        List<int> missingIndices,
        int totalFragents,
        List<int>? originalSizes = null)
    {
        var result = new Dictionary<int, byte[]>();
        foreach (int missingIdx in missingIndices)
        {
            int prevIdx = (missingIdx - 1 + totalFragents) % totalFragents;
            if (!available.TryGetValue(prevIdx, out var prevData)) continue;

            int ownSize;
            if (originalSizes != null && prevIdx < originalSizes.Count)
                ownSize = originalSizes[prevIdx];
            else
                ownSize = prevData.Length / 2;

            byte[] recovered = new byte[prevData.Length - ownSize];
            Buffer.BlockCopy(prevData, ownSize, recovered, 0, recovered.Length);
            result[missingIdx] = recovered;
        }
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

            if (originalSizes != null && i < originalSizes.Count && data.Length <= originalSizes[i])
            {
                result.Add(data);
                continue;
            }

            if (originalSizes != null && i < originalSizes.Count)
            {
                byte[] stripped = new byte[originalSizes[i]];
                Buffer.BlockCopy(data, 0, stripped, 0, originalSizes[i]);
                result.Add(stripped);
            }
            else
            {
                byte[] stripped = new byte[data.Length / 2];
                Buffer.BlockCopy(data, 0, stripped, 0, stripped.Length);
                result.Add(stripped);
            }
        }
        return result;
    }
}
