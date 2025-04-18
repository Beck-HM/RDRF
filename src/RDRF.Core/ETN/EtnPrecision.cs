using RDRF.Core.Index;
using RDRF.Core.Storage;

namespace RDRF.Core.ETN;

public static class EtnPrecision
{
    public static PrecisionResult Analyze(
        byte[] indexBytes,
        byte[] rcBytes,
        List<byte[]> fragmentsWithTrailers)
    {
        var result = new PrecisionResult();

        RcFile rcFile;
        try { rcFile = RcFile.FromCbor(rcBytes); }
        catch (Exception ex)
        {
            result.IsValid = false;
            result.RcCorrupted = true;
            result.ErrorMessage = $"RC parse failed: {ex.Message}";
            return result;
        }

        byte[] strippedIndexBytes = StripFss6Fields(indexBytes);
        var actualIndexBm = EtnBlockMap.Build(strippedIndexBytes);
        var actualRcBm = EtnBlockMap.Build(rcBytes);

        var rcStoredIndexBm = rcFile.IndexBlockMap.Select(EtnBlockMap.HexToHash).ToList();
        var rcStoredFragmentBms = rcFile.FragentBlockMaps
            .Select(list => list.Select(EtnBlockMap.HexToHash).ToList()).ToList();

        var actualFragmentBms = new List<List<byte[]>>();
        var trailerIndexBms = new List<List<byte[]>>();
        var trailerRcBms = new List<List<byte[]>>();

        for (int i = 0; i < fragmentsWithTrailers.Count; i++)
        {
            var (data, tIndexBm, tRcBm) = EtnTrailer.Parse(fragmentsWithTrailers[i]);
            actualFragmentBms.Add(EtnBlockMap.Build(data));
            trailerIndexBms.Add(tIndexBm);
            trailerRcBms.Add(tRcBm);
        }

        RdrfIndex? index = null;
        try { index = IndexManager.DeserializeIndex(indexBytes); }
        catch { }

        var indexStoredRcBm = index?.Fss6RcBlockMap?.Select(EtnBlockMap.HexToHash).ToList() ?? new List<byte[]>();
        var indexStoredFragmentBms = index?.Fss6FragentBlockMaps
            ?.Select(list => list.Select(EtnBlockMap.HexToHash).ToList()).ToList()
            ?? new List<List<byte[]>>();

        CheckIndex(result, actualIndexBm, rcStoredIndexBm, trailerIndexBms);
        CheckRc(result, actualRcBm, indexStoredRcBm, trailerRcBms);
        CheckFragments(result, actualFragmentBms, rcStoredFragmentBms, indexStoredFragmentBms);

        result.IsValid = !result.IndexCorrupted && !result.RcCorrupted && result.CorruptedFragments.Count == 0;
        return result;
    }

    private static void CheckIndex(
        PrecisionResult result,
        List<byte[]> actualIndexBm,
        List<byte[]> rcStoredIndexBm,
        List<List<byte[]>> trailerIndexBms)
    {
        bool rcMatch = EtnBlockMap.Compare(actualIndexBm, rcStoredIndexBm);
        var trailerConsensus = TrailerConsensus(trailerIndexBms);
        bool trailerMatch = trailerConsensus != null && EtnBlockMap.Compare(actualIndexBm, trailerConsensus);

        if (rcMatch && trailerMatch) return;

        if (!rcMatch && trailerMatch)
        {
            result.RcCorrupted = true;
            result.RcCorruptedBlocks = EtnBlockMap.Diff(rcStoredIndexBm, actualIndexBm);
            return;
        }

        if (rcMatch && !trailerMatch)
        {
            result.CorruptedFragmentTrailers = FindDisagreeing(trailerIndexBms, actualIndexBm);
            return;
        }

        if (!rcMatch && !trailerMatch && trailerConsensus != null
            && EtnBlockMap.Compare(rcStoredIndexBm, trailerConsensus))
        {
            result.IndexCorrupted = true;
            result.IndexCorruptedBlocks = EtnBlockMap.Diff(actualIndexBm, rcStoredIndexBm);
            return;
        }

        result.IndexCorrupted = true;
        result.IndexCorruptedBlocks = EtnBlockMap.Diff(actualIndexBm, trailerConsensus ?? rcStoredIndexBm);
    }

    private static void CheckRc(
        PrecisionResult result,
        List<byte[]> actualRcBm,
        List<byte[]> indexStoredRcBm,
        List<List<byte[]>> trailerRcBms)
    {
        bool indexMatch = indexStoredRcBm.Count > 0 && EtnBlockMap.Compare(actualRcBm, indexStoredRcBm);
        var trailerConsensus = TrailerConsensus(trailerRcBms);
        bool trailerMatch = trailerConsensus != null && EtnBlockMap.Compare(actualRcBm, trailerConsensus);

        if (indexMatch && trailerMatch) return;

        if (indexMatch && !trailerMatch)
        {
            result.CorruptedFragmentTrailers = Union(result.CorruptedFragmentTrailers, FindDisagreeing(trailerRcBms, actualRcBm));
            return;
        }

        if (!indexMatch && trailerMatch) return;

        if (!indexMatch && !trailerMatch && trailerConsensus != null
            && EtnBlockMap.Compare(indexStoredRcBm, trailerConsensus))
        {
            result.RcCorrupted = true;
            result.RcCorruptedBlocks = EtnBlockMap.Diff(actualRcBm, indexStoredRcBm);
            return;
        }

        result.RcCorrupted = true;
        result.RcCorruptedBlocks = EtnBlockMap.Diff(actualRcBm, trailerConsensus ?? indexStoredRcBm);
    }

    private static void CheckFragments(
        PrecisionResult result,
        List<List<byte[]>> actualFragmentBms,
        List<List<byte[]>> rcStoredFragmentBms,
        List<List<byte[]>> indexStoredFragmentBms)
    {
        for (int i = 0; i < actualFragmentBms.Count; i++)
        {
            bool rcPresent = i < rcStoredFragmentBms.Count;
            bool indexPresent = i < indexStoredFragmentBms.Count;
            bool rcMatch = rcPresent && EtnBlockMap.Compare(actualFragmentBms[i], rcStoredFragmentBms[i]);
            bool indexMatch = indexPresent && EtnBlockMap.Compare(actualFragmentBms[i], indexStoredFragmentBms[i]);

            if (rcMatch && indexMatch) continue;
            if (!rcPresent && !indexPresent) continue;

            if (!rcPresent) { result.CorruptedFragments.Add(i); continue; }
            if (!indexPresent) { result.CorruptedFragments.Add(i); continue; }

            if (!rcMatch && indexMatch) { result.CorruptedFragments.Add(i); }
            else if (rcMatch && !indexMatch) { result.CorruptedFragments.Add(i); }
            else
            {
                bool peersAgree = EtnBlockMap.Compare(rcStoredFragmentBms[i], indexStoredFragmentBms[i]);
                if (peersAgree)
                {
                    result.CorruptedFragments.Add(i);
                    var blocks = EtnBlockMap.Diff(actualFragmentBms[i], rcStoredFragmentBms[i]);
                    if (blocks.Count > 0) result.CorruptedFragmentBlocks[i] = blocks;
                }
                else { result.CorruptedFragments.Add(i); }
            }
        }
    }

    private static List<byte[]>? TrailerConsensus(List<List<byte[]>> bms)
    {
        if (bms.Count == 0) return null;
        if (bms.Count == 1) return bms[0];
        var reference = bms[0];
        for (int i = 1; i < bms.Count; i++)
            if (!EtnBlockMap.Compare(reference, bms[i])) return null;
        return reference;
    }

    private static List<int> FindDisagreeing(List<List<byte[]>> bms, List<byte[]> reference)
    {
        var list = new List<int>();
        for (int i = 0; i < bms.Count; i++)
            if (!EtnBlockMap.Compare(bms[i], reference)) list.Add(i);
        return list;
    }

    private static List<int> Union(List<int> a, List<int> b)
    {
        var set = new HashSet<int>(a);
        foreach (var x in b) set.Add(x);
        return set.ToList();
    }

    internal static byte[] StripFss6Fields(byte[] indexBytes)
    {
        var index = IndexManager.DeserializeIndex(indexBytes);
        if (index == null) return indexBytes;
        index.Fss6FragentBlockMaps = null;
        index.Fss6RcBlockMap = null;
        return IndexManager.SerializeIndex(index);
    }
}

public class PrecisionResult
{
    public bool IsValid { get; set; } = true;
    public bool IndexCorrupted { get; set; }
    public List<int> IndexCorruptedBlocks { get; set; } = new();
    public bool RcCorrupted { get; set; }
    public List<int> RcCorruptedBlocks { get; set; } = new();
    public List<int> CorruptedFragments { get; set; } = new();
    public Dictionary<int, List<int>> CorruptedFragmentBlocks { get; set; } = new();
    public List<int> CorruptedFragmentTrailers { get; set; } = new();
    public string? ErrorMessage { get; set; }
}
