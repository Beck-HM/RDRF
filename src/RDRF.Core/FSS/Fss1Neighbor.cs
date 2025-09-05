using System.Diagnostics;
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
            int prev = (i - 1 + n) % n;
            int next = (i + 1) % n;
            int size = fragments[i].Length;
            int half = size / 2;

            byte[] output = new byte[size];
            // Upper 50%: from prev's upper half
            var prevFrag = fragments[prev];
            int copyPrev = Math.Min(half, prevFrag.Length);
            Buffer.BlockCopy(prevFrag, 0, output, 0, copyPrev);
            // Lower 50%: from next's lower half
            var nextFrag = fragments[next];
            int nextHalf = nextFrag.Length / 2;
            int copyNext = Math.Min(half, nextFrag.Length - nextHalf);
            Buffer.BlockCopy(nextFrag, nextHalf, output, half, copyNext);

            encoded.Add(output);
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

                int rightIdx = (missingIdx + 1) % totalFragments;
                int leftIdx = (missingIdx - 1 + totalFragments) % totalFragments;

                if (work.ContainsKey(rightIdx) && work.ContainsKey(leftIdx))
                {
                    var rightData = work[rightIdx];
                    var leftData = work[leftIdx];
                    int size = originalSizes?.Count > missingIdx ? originalSizes[missingIdx] : rightData.Length;
                    int half = size / 2;

                    byte[] recovered = new byte[size];
                    // Upper half from right fragment's upper half
                    int copyUpper = Math.Min(half, rightData.Length);
                    Buffer.BlockCopy(rightData, 0, recovered, 0, copyUpper);
                    // Lower half from left fragment's lower half
                    int leftHalf = leftData.Length / 2;
                    int copyLower = Math.Min(half, leftData.Length - leftHalf);
                    Buffer.BlockCopy(leftData, leftHalf, recovered, half, copyLower);

                    result[missingIdx] = recovered;
                    work[missingIdx] = recovered;
                    madeProgress = true;
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
        int n = originalFragmentCount;
        for (int i = 0; i < n; i++)
        {
            if (!encodedFragments.TryGetValue(i, out var data)) continue;

            // Each encoded fragment contains:
            //   upper = prev's upper half, lower = next's lower half
            // We need to extract THIS fragment's original data
            int rightIdx = (i + 1) % n;
            int leftIdx = (i - 1 + n) % n;

            if (!encodedFragments.TryGetValue(rightIdx, out var rightFrag) ||
                !encodedFragments.TryGetValue(leftIdx, out var leftFrag))
                continue;

            int size = originalSizes?.Count > i ? originalSizes[i] : rightFrag.Length;
            int half = size / 2;

            byte[] stripped = new byte[size];
            // Upper half from right fragment's upper half
            int copyUpper = Math.Min(half, rightFrag.Length);
            Buffer.BlockCopy(rightFrag, 0, stripped, 0, copyUpper);
            // Lower half from left fragment's lower half
            int leftHalf = leftFrag.Length / 2;
            int copyLower = Math.Min(half, leftFrag.Length - leftHalf);
            Buffer.BlockCopy(leftFrag, leftHalf, stripped, half, copyLower);

            result.Add(stripped);
        }
        return result;
    }

    public byte[] StripSingle(byte[] encodedFragment, int index, List<int>? originalSizes = null)
    {
        // StripSingle is only used in streaming path where the fragment
        // IS the data. FSS1 encoding rearranges data across fragments,
        // so StripSingle cannot recover a single fragment independently.
        // Fall back: return the fragment as-is (caller must use Strip for FSS1).
        int size = originalSizes?.Count > index ? originalSizes[index] : encodedFragment.Length;
        if (size > encodedFragment.Length) size = encodedFragment.Length;
        byte[] result = new byte[size];
        Buffer.BlockCopy(encodedFragment, 0, result, 0, size);
        return result;
    }
}
