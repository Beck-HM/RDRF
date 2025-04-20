using RDRF.Core.Index;

namespace RDRF.Core.FSS;

public class Fss2RRepair : IFssStrategy
{
    private readonly Fss1Neighbor _fss1 = new();
    private readonly Fss2Verify _fss2 = new();

    public string Level => Constants.FssLevel2R;

    public List<byte[]> Encode(List<byte[]> fragments) => _fss2.Encode(fragments);

    public Dictionary<int, byte[]> Decode(
        Dictionary<int, byte[]> available,
        List<int> missingIndices,
        int totalFragents,
        List<int>? originalSizes = null)
        => _fss2.Decode(available, missingIndices, totalFragents, originalSizes);

    public List<byte[]> Strip(
        Dictionary<int, byte[]> encodedFragents,
        int originalFragentCount,
        List<int>? originalSizes = null)
    {
        // Remove checksums, diagnose and repair corrupted fragments
        var stripped = new Dictionary<int, byte[]>();
        foreach (var kvp in encodedFragents)
        {
            byte[] data = kvp.Value;
            int hashLen = 32;
            byte[] fragData = new byte[data.Length - hashLen];
            Buffer.BlockCopy(data, 0, fragData, 0, fragData.Length);
            stripped[kvp.Key] = fragData;
        }

        // Verify and repair
        int count = encodedFragents.Count;
        for (int attempt = 0; attempt < 2; attempt++)
        {
            foreach (var kvp in new List<KeyValuePair<int, byte[]>>(stripped))
            {
                byte[] expectedHash = System.Security.Cryptography.SHA256.HashData(kvp.Value);
                int hashLen = 32;
                byte[] storedHash = new byte[hashLen];
                Buffer.BlockCopy(encodedFragents[kvp.Key], kvp.Value.Length, storedHash, 0, hashLen);
                int idx = kvp.Key;
                int leftIdx = (idx - 1 + count) % count;
                int rightIdx = (idx + 1) % count;

                if (Integrity.IntegrityChecker.BytesEqual(expectedHash, storedHash))
                    continue;

                // Corrupted - diagnose source
                if (stripped.ContainsKey(leftIdx))
                {
                    // Check left neighbor's checksum
                    byte[] leftData = stripped[leftIdx];
                    byte[] leftExpectedHash = System.Security.Cryptography.SHA256.HashData(leftData);
                    byte[] leftStoredHash = new byte[hashLen];
                    Buffer.BlockCopy(encodedFragents[leftIdx], leftData.Length, leftStoredHash, 0, hashLen);

                    if (Integrity.IntegrityChecker.BytesEqual(leftExpectedHash, leftStoredHash))
                    {
                        // Left neighbor is clean, source is primary (this fragment)
                        if (originalSizes != null && leftIdx < originalSizes.Count)
                        {
                            int leftSize = originalSizes[leftIdx];
                            if (leftData.Length > leftSize)
                            {
                                byte[] recovered = new byte[leftData.Length - leftSize];
                                Buffer.BlockCopy(leftData, leftSize, recovered, 0, recovered.Length);
                                stripped[idx] = recovered;
                                continue;
                            }
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
                            stripped[idx] = recovered;
                        }
                    }
                }
            }
        }

        return _fss1.Strip(stripped, originalFragentCount, originalSizes);
    }

    public byte[] StripSingle(byte[] encodedFragment, int index, List<int>? originalSizes = null)
    {
        byte[] data = new byte[encodedFragment.Length - 32];
        Buffer.BlockCopy(encodedFragment, 0, data, 0, data.Length);
        return _fss1.StripSingle(data, index, originalSizes);
    }
}
