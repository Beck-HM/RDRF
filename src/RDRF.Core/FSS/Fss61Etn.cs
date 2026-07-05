using RDRF.Core.Index;

namespace RDRF.Core.FSS;

/// <summary>
/// FSS6.1: ETN + LT fountain code repair trailer (strip-only, encode via FssRepairService).
/// </summary>

public class Fss61Etn : IFssStrategy
{
    public string Level => Constants.FssLevel61;

    public List<byte[]> Encode(List<byte[]> fragments)
        => fragments;

    public List<byte[]> Strip(Dictionary<int, byte[]> encodedFragments,
        int originalFragmentCount, List<int>? originalSizes = null)
    {
        var result = new List<byte[]>();
        for (int i = 0; i < originalFragmentCount; i++)
            if (encodedFragments.TryGetValue(i, out var data))
                result.Add(StripSingle(data, i));
        return result;
    }

    public byte[] StripSingle(byte[] encodedFragment, int index, List<int>? originalSizes = null)
    {
        var (data, _, _, _, _) = Fss61RepairTrailer.Parse(encodedFragment);
        return data;
    }

    public Dictionary<int, byte[]> Decode(
        Dictionary<int, byte[]> available,
        List<int> missingIndices,
        int totalFragments,
        List<int>? originalSizes = null)
        => new();
}

