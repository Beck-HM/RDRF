using RDRF.Core.Index;

namespace RDRF.Core.FSS;

public class Fss2Verify : IFssStrategy
{
    private readonly Fss1Neighbor _fss1 = new();

    public string Level => Constants.FssLevel2;

    public List<byte[]> Encode(List<byte[]> fragments)
    {
        var fss1Encoded = _fss1.Encode(fragments);
        var result = new List<byte[]>();
        foreach (var frag in fss1Encoded)
        {
            byte[] hash = System.Security.Cryptography.SHA256.HashData(frag);
            byte[] combined = new byte[frag.Length + hash.Length];
            Buffer.BlockCopy(frag, 0, combined, 0, frag.Length);
            Buffer.BlockCopy(hash, 0, combined, frag.Length, hash.Length);
            result.Add(combined);
        }
        return result;
    }

    public Dictionary<int, byte[]> Decode(
        Dictionary<int, byte[]> available,
        List<int> missingIndices,
        int totalFragments,
        List<int>? originalSizes = null)
    {
        var fss1Available = new Dictionary<int, byte[]>();
        foreach (var kvp in available)
        {
            if (kvp.Value.Length < 32) continue;
            byte[] stripped = new byte[kvp.Value.Length - 32];
            Buffer.BlockCopy(kvp.Value, 0, stripped, 0, stripped.Length);
            fss1Available[kvp.Key] = stripped;
        }

        var recovered = _fss1.Decode(fss1Available, missingIndices, totalFragments, originalSizes);

        var result = new Dictionary<int, byte[]>();
        foreach (var kvp in recovered)
        {
            byte[] hash = System.Security.Cryptography.SHA256.HashData(kvp.Value);
            byte[] fss2Frag = new byte[kvp.Value.Length + hash.Length];
            Buffer.BlockCopy(kvp.Value, 0, fss2Frag, 0, kvp.Value.Length);
            Buffer.BlockCopy(hash, 0, fss2Frag, kvp.Value.Length, hash.Length);
            result[kvp.Key] = fss2Frag;
        }

        return result;
    }

    public List<byte[]> Strip(
        Dictionary<int, byte[]> encodedFragments,
        int originalFragmentCount,
        List<int>? originalSizes = null)
    {
        var stripped = new Dictionary<int, byte[]>();
        foreach (var kvp in encodedFragments)
        {
            byte[] data = kvp.Value;
            if (data.Length < 32) continue;
            int hashLen = 32;
            byte[] fragData = new byte[data.Length - hashLen];
            Buffer.BlockCopy(data, 0, fragData, 0, fragData.Length);
            stripped[kvp.Key] = fragData;
        }

        var verifind = new Dictionary<int, byte[]>();
        foreach (var kvp in stripped)
        {
            byte[] expectedHash = System.Security.Cryptography.SHA256.HashData(kvp.Value);
            int hashLen = 32;
            byte[] storedHash = new byte[hashLen];
            Buffer.BlockCopy(encodedFragments[kvp.Key], kvp.Value.Length, storedHash, 0, hashLen);

            if (Integrity.IntegrityChecker.BytesEqual(expectedHash, storedHash))
            {
                verifind[kvp.Key] = kvp.Value;
            }
            else
            {
                int count = encodedFragments.Count;
                int idx = kvp.Key;
                int leftIdx = (idx - 1 + count) % count;
                int rightIdx = (idx + 1) % count;

                if (stripped.ContainsKey(leftIdx))
                {
                    byte[] leftData = stripped[leftIdx];
                    if (originalSizes != null && leftIdx < originalSizes.Count)
                    {
                        int leftSize = originalSizes[leftIdx];
                        if (leftData.Length > leftSize)
                        {
                            byte[] recovered = new byte[leftData.Length - leftSize];
                            Buffer.BlockCopy(leftData, leftSize, recovered, 0, recovered.Length);
                            verifind[idx] = recovered;
                            continue;
                        }
                    }
                }

                if (stripped.ContainsKey(rightIdx))
                {
                    byte[] rightData = stripped[rightIdx];
                    if (originalSizes != null && idx < originalSizes.Count)
                    {
                        int size = originalSizes[idx];
                        if (rightData.Length >= size)
                        {
                            byte[] recovered = new byte[size];
                            Buffer.BlockCopy(rightData, 0, recovered, 0, size);
                            verifind[idx] = recovered;
                            continue;
                        }
                    }
                }
            }
        }

        return _fss1.Strip(verifind, originalFragmentCount, originalSizes);
    }

    public byte[] StripSingle(byte[] encodedFragment, int index, List<int>? originalSizes = null)
    {
        if (encodedFragment.Length < 32)
            return _fss1.StripSingle(encodedFragment, index, originalSizes);
        byte[] data = new byte[encodedFragment.Length - 32];
        Buffer.BlockCopy(encodedFragment, 0, data, 0, data.Length);
        return _fss1.StripSingle(data, index, originalSizes);
    }
}
