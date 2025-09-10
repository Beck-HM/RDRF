using System.Security.Cryptography;
using RDRF.Core.Index;
using RDRF.Core.Integrity;

namespace RDRF.Core.FSS;

public class Fss5CrossRecovery : IFssStrategy
{
    public string Level => Constants.FssLevel5;

    public List<byte[]> Encode(List<byte[]> fragments)
    {
        int n = fragments.Count;
        var (step1, step2) = ChooseSteps(n);
        var encoded = new List<byte[]>();

        for (int i = 0; i < n; i++)
        {
            int n1Idx = (i + step1) % n;
            int n2Idx = (i + step2) % n;

            byte[] own = fragments[i];
            byte[] n1 = fragments[n1Idx];
            byte[] n2 = fragments[n2Idx];

            byte[] combined = new byte[4 + own.Length + 4 + n1.Length + 4 + n2.Length];
            int offset = 0;

            Buffer.BlockCopy(BitConverter.GetBytes(own.Length), 0, combined, offset, 4); offset += 4;
            Buffer.BlockCopy(own, 0, combined, offset, own.Length); offset += own.Length;

            Buffer.BlockCopy(BitConverter.GetBytes(n1.Length), 0, combined, offset, 4); offset += 4;
            Buffer.BlockCopy(n1, 0, combined, offset, n1.Length); offset += n1.Length;

            Buffer.BlockCopy(BitConverter.GetBytes(n2.Length), 0, combined, offset, 4); offset += 4;
            Buffer.BlockCopy(n2, 0, combined, offset, n2.Length); offset += n2.Length;

            encoded.Add(combined);
        }
        return encoded;
    }

    public static (int step1, int step2) ChooseSteps(int fragmentCount)
    {
        if (fragmentCount <= 4) return (1, 2);
        if (fragmentCount <= 8) return (1, 3);
        if (fragmentCount <= 16) return (2, 5);
        return (3, 7);
    }

    public Dictionary<int, byte[]> Decode(
        Dictionary<int, byte[]> available,
        List<int> missingIndices,
        int totalFragments,
        List<int>? originalSizes = null)
    {
        var result = new Dictionary<int, byte[]>();
        var known = new Dictionary<int, byte[]>(available);
        var (step1, step2) = ChooseSteps(totalFragments);

        bool madeProgress;
        int iterations = 0;
        do
        {
            madeProgress = false;
            var stillMissing = new List<int>(missingIndices);

            foreach (int missingIdx in stillMissing)
            {
                if (result.ContainsKey(missingIdx)) continue;

                byte[]? recovered = null;

                // Try step1 backward neighbor
                int src1Idx = (missingIdx - step1 + totalFragments) % totalFragments;
                if (known.ContainsKey(src1Idx) && IsValidFss5Fragment(known[src1Idx], out _))
                {
                    recovered = ExtractStep1Data(known[src1Idx]);
                }

                // Try step2 backward neighbor
                if (recovered == null)
                {
                    int src2Idx = (missingIdx - step2 + totalFragments) % totalFragments;
                    if (known.ContainsKey(src2Idx) && IsValidFss5Fragment(known[src2Idx], out _))
                    {
                        recovered = ExtractStep2Data(known[src2Idx]);
                    }
                }

                if (recovered != null)
                {
                    result[missingIdx] = recovered;
                    known[missingIdx] = recovered;
                    TryReconstructEncoded(missingIdx, known, step1, step2, totalFragments);
                    madeProgress = true;
                }
            }

            iterations++;
            if (iterations > totalFragments * 3) break;

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

            // If original sizes available and data matches, it's already raw (e.g. recovered)
            if (originalSizes != null && i < originalSizes.Count && data.Length <= originalSizes[i])
            {
                result.Add(data);
                continue;
            }

            result.Add(ExtractOwnData(data));
        }
        return result;
    }

    public byte[] StripSingle(byte[] encodedFragment, int index, List<int>? originalSizes = null)
    {
        if (originalSizes != null && index < originalSizes.Count && encodedFragment.Length <= originalSizes[index])
            return encodedFragment;
        return ExtractOwnData(encodedFragment);
    }

    private static bool IsValidFss5Fragment(byte[] data, out int ownSize)
    {
        ownSize = 0;
        if (data.Length < 12) return false;
        ownSize = BitConverter.ToInt32(data, 0);
        if (ownSize <= 0 || ownSize > 1024 * 1024) return false;
        int off = 4 + ownSize;
        if (off + 4 > data.Length) return false;
        int n1Size = BitConverter.ToInt32(data, off);
        if (n1Size <= 0 || n1Size > 1024 * 1024) return false;
        off += 4 + n1Size;
        if (off + 4 > data.Length) return false;
        int n2Size = BitConverter.ToInt32(data, off);
        if (n2Size <= 0 || n2Size > 1024 * 1024) return false;
        off += 4 + n2Size;
        return data.Length == off;
    }

    private static byte[] ExtractOwnData(byte[] encoded)
    {
        int ownSize = BitConverter.ToInt32(encoded, 0);
        byte[] own = new byte[ownSize];
        Buffer.BlockCopy(encoded, 4, own, 0, ownSize);
        return own;
    }

    private static byte[] ExtractStep1Data(byte[] encoded)
    {
        int ownSize = BitConverter.ToInt32(encoded, 0);
        int n1Size = BitConverter.ToInt32(encoded, 4 + ownSize);
        byte[] n1 = new byte[n1Size];
        Buffer.BlockCopy(encoded, 4 + ownSize + 4, n1, 0, n1Size);
        return n1;
    }

    private static byte[] ExtractStep2Data(byte[] encoded)
    {
        int ownSize = BitConverter.ToInt32(encoded, 0);
        int n1Size = BitConverter.ToInt32(encoded, 4 + ownSize);
        int offset = 4 + ownSize + 4 + n1Size;
        int n2Size = BitConverter.ToInt32(encoded, offset);
        byte[] n2 = new byte[n2Size];
        Buffer.BlockCopy(encoded, offset + 4, n2, 0, n2Size);
        return n2;
    }

    private static void TryReconstructEncoded(
        int recoveredIdx, Dictionary<int, byte[]> known,
        int step1, int step2, int n)
    {
        TryReconstructSingle(recoveredIdx, known, step1, step2, n);
        TryReconstructSingle((recoveredIdx - step1 + n) % n, known, step1, step2, n);
        TryReconstructSingle((recoveredIdx - step2 + n) % n, known, step1, step2, n);
    }

    private static void TryReconstructSingle(
        int encodedIdx, Dictionary<int, byte[]> known,
        int step1, int step2, int n)
    {
        if (known.TryGetValue(encodedIdx, out var existing) && IsValidFss5Fragment(existing, out _))
            return;

        int n1Idx = (encodedIdx + step1) % n;
        int n2Idx = (encodedIdx + step2) % n;

        if (!known.ContainsKey(encodedIdx) || !known.ContainsKey(n1Idx) || !known.ContainsKey(n2Idx))
            return;

        byte[] own = known[encodedIdx];
        byte[] n1 = known[n1Idx];
        byte[] n2 = known[n2Idx];

        byte[] combined = new byte[4 + own.Length + 4 + n1.Length + 4 + n2.Length];
        int offset = 0;
        Buffer.BlockCopy(BitConverter.GetBytes(own.Length), 0, combined, offset, 4); offset += 4;
        Buffer.BlockCopy(own, 0, combined, offset, own.Length); offset += own.Length;
        Buffer.BlockCopy(BitConverter.GetBytes(n1.Length), 0, combined, offset, 4); offset += 4;
        Buffer.BlockCopy(n1, 0, combined, offset, n1.Length); offset += n1.Length;
        Buffer.BlockCopy(BitConverter.GetBytes(n2.Length), 0, combined, offset, 4); offset += 4;
        Buffer.BlockCopy(n2, 0, combined, offset, n2.Length); offset += n2.Length;

        known[encodedIdx] = combined;
    }
}
