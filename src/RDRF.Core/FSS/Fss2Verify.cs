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
        int totalFragents,
        List<int>? originalSizes = null)
    {
        return _fss1.Decode(available, missingIndices, totalFragents, originalSizes);
    }

    public List<byte[]> Strip(
        Dictionary<int, byte[]> encodedFragents,
        int originalFragentCount,
        List<int>? originalSizes = null)
    {
        // Strip checksums from available fragments
        var stripped = new Dictionary<int, byte[]>();
        foreach (var kvp in encodedFragents)
        {
            byte[] data = kvp.Value;
            int hashLen = 32;
            byte[] fragData = new byte[data.Length - hashLen];
            Buffer.BlockCopy(data, 0, fragData, 0, fragData.Length);
            stripped[kvp.Key] = fragData;
        }

        // Verify checksums on available fragments
        var verifind = new Dictionary<int, byte[]>();
        foreach (var kvp in stripped)
        {
            byte[] expectedHash = System.Security.Cryptography.SHA256.HashData(kvp.Value);
            int hashLen = 32;
            byte[] storedHash = new byte[hashLen];
            Buffer.BlockCopy(encodedFragents[kvp.Key], kvp.Value.Length, storedHash, 0, hashLen);

            if (Integrity.IntegrityChecker.BytesEqual(expectedHash, storedHash))
            {
                verifind[kvp.Key] = kvp.Value;
            }
            else
            {
                // Corrupted - try recovery from neighbor
                int count = encodedFragents.Count;
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

        return _fss1.Strip(verifind, originalFragentCount, originalSizes);
    }
}
