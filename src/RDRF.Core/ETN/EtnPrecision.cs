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
        var trailerFragmentBms = new List<List<byte[]>>();
        var trailerIndexBms = new List<List<byte[]>>();
        var trailerRcBms = new List<List<byte[]>>();

        for (int i = 0; i < fragmentsWithTrailers.Count; i++)
        {
            var (data, tFragBm, tIndexBm, tRcBm) = EtnTrailer.Parse(fragmentsWithTrailers[i]);
            actualFragmentBms.Add(EtnBlockMap.Build(data));
            trailerFragmentBms.Add(tFragBm);
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
        CheckFragments(result, actualFragmentBms, trailerFragmentBms, rcStoredFragmentBms, indexStoredFragmentBms);

        result.IsValid = !result.IndexCorrupted && !result.RcCorrupted && result.CorruptedFragments.Count == 0;
        return result;
    }

    private static void CheckIndex(
        PrecisionResult result,
        List<byte[]> actualIndexBm,
        List<byte[]> rcStoredIndexBm,
        List<List<byte[]>> trailerIndexBms)
    {
        bool rcMatch = rcStoredIndexBm.Count > 0 &&
            EtnBlockMap.DiffTrimmed(actualIndexBm, rcStoredIndexBm).Count == 0;
        var trailerConsensus = TrailerConsensus(trailerIndexBms);
        bool trailerMatch = trailerConsensus != null &&
            EtnBlockMap.DiffTrimmed(actualIndexBm, trailerConsensus).Count == 0;

        if (rcMatch && trailerMatch) return;

        if (!rcMatch && trailerMatch)
        {
            result.RcCorrupted = true;
            result.RcCorruptedBlocks = EtnBlockMap.DiffTrimmed(rcStoredIndexBm, actualIndexBm);
            return;
        }

        if (rcMatch && !trailerMatch)
        {
            result.CorruptedFragmentTrailers = FindDisagreeing(trailerIndexBms, actualIndexBm);
            return;
        }

        if (!rcMatch && !trailerMatch && trailerConsensus != null &&
            EtnBlockMap.DiffTrimmed(rcStoredIndexBm, trailerConsensus).Count == 0)
        {
            result.IndexCorrupted = true;
            result.IndexCorruptedBlocks = EtnBlockMap.DiffTrimmed(actualIndexBm, rcStoredIndexBm);
            return;
        }

        result.IndexCorrupted = true;
        result.IndexCorruptedBlocks = EtnBlockMap.DiffTrimmed(actualIndexBm, trailerConsensus ?? rcStoredIndexBm);
    }

    private static void CheckRc(
        PrecisionResult result,
        List<byte[]> actualRcBm,
        List<byte[]> indexStoredRcBm,
        List<List<byte[]>> trailerRcBms)
    {
        bool indexMatch = indexStoredRcBm.Count > 0 &&
            EtnBlockMap.DiffTrimmed(actualRcBm, indexStoredRcBm).Count == 0;
        var trailerConsensus = TrailerConsensus(trailerRcBms);
        bool trailerMatch = trailerConsensus != null &&
            EtnBlockMap.DiffTrimmed(actualRcBm, trailerConsensus).Count == 0;

        if (indexMatch && trailerMatch) return;

        if (indexMatch && !trailerMatch)
        {
            result.CorruptedFragmentTrailers = Union(result.CorruptedFragmentTrailers, FindDisagreeing(trailerRcBms, actualRcBm));
            return;
        }

        if (!indexMatch && trailerMatch) return;

        if (!indexMatch && !trailerMatch && trailerConsensus != null &&
            EtnBlockMap.DiffTrimmed(indexStoredRcBm, trailerConsensus).Count == 0)
        {
            result.RcCorrupted = true;
            result.RcCorruptedBlocks = EtnBlockMap.DiffTrimmed(actualRcBm, indexStoredRcBm);
            return;
        }

        result.RcCorrupted = true;
        result.RcCorruptedBlocks = EtnBlockMap.DiffTrimmed(actualRcBm, trailerConsensus ?? indexStoredRcBm);
    }

    private static void CheckFragments(
        PrecisionResult result,
        List<List<byte[]>> actualFragmentBms,
        List<List<byte[]>> trailerFragmentBms,
        List<List<byte[]>> rcStoredFragmentBms,
        List<List<byte[]>> indexStoredFragmentBms)
    {
        for (int i = 0; i < actualFragmentBms.Count; i++)
        {
            var actual32 = actualFragmentBms[i];
            bool hasTrailer = i < trailerFragmentBms.Count;
            bool hasRc = i < rcStoredFragmentBms.Count;
            bool hasIndex = i < indexStoredFragmentBms.Count;

            if (!hasRc && !hasIndex) continue;

            // Tier 1: trailer (2B) fast scan
            var suspicious = hasTrailer
                ? EtnBlockMap.DiffTrimmed(actual32, trailerFragmentBms[i])
                : new List<int>();

            // Tier 2: confirm suspicious blocks against RC (8B) + Index (8B)
            var corrupted = new List<int>();
            foreach (int b in suspicious)
            {
                bool rcOk = hasRc && b < rcStoredFragmentBms[i].Count &&
                    EtnBlockMap.IsSecondPassMatch(actual32[b], rcStoredFragmentBms[i][b]);
                bool idxOk = hasIndex && b < indexStoredFragmentBms[i].Count &&
                    EtnBlockMap.IsSecondPassMatch(actual32[b], indexStoredFragmentBms[i][b]);

                if (!rcOk && !idxOk)
                    corrupted.Add(b);
                else
                {
                    if (!result.SuspiciousFragmentBlocks.ContainsKey(i))
                        result.SuspiciousFragmentBlocks[i] = new List<int>();
                    result.SuspiciousFragmentBlocks[i].Add(b);
                }
            }

            // If no trailer available, compare full against RC/Index directly
            if (!hasTrailer)
            {
                bool rcMatch = hasRc && EtnBlockMap.DiffTrimmed(actual32, rcStoredFragmentBms[i]).Count == 0;
                bool idxMatch = hasIndex && EtnBlockMap.DiffTrimmed(actual32, indexStoredFragmentBms[i]).Count == 0;

                if (!rcMatch && !idxMatch)
                {
                    result.CorruptedFragments.Add(i);
                    result.CorruptedFragmentBlocks[i] = EtnBlockMap.DiffTrimmed(actual32,
                        rcStoredFragmentBms[i].Count > 0 ? rcStoredFragmentBms[i] : indexStoredFragmentBms[i]);
                }
                continue;
            }

            if (corrupted.Count > 0)
            {
                result.CorruptedFragments.Add(i);
                result.CorruptedFragmentBlocks[i] = corrupted;
            }
        }
    }

    private static List<byte[]>? TrailerConsensus(List<List<byte[]>> bms)
    {
        if (bms.Count == 0) return null;
        if (bms.Count == 1) return bms[0];
        var reference = bms[0];
        for (int i = 1; i < bms.Count; i++)
            if (EtnBlockMap.DiffTrimmed(reference, bms[i]).Count != 0) return null;
        return reference;
    }

    private static List<int> FindDisagreeing(List<List<byte[]>> bms, List<byte[]> reference)
    {
        var list = new List<int>();
        for (int i = 0; i < bms.Count; i++)
            if (EtnBlockMap.DiffTrimmed(bms[i], reference).Count != 0) list.Add(i);
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
    public Dictionary<int, List<int>> SuspiciousFragmentBlocks { get; set; } = new();
    public List<int> CorruptedFragmentTrailers { get; set; } = new();
    public string? ErrorMessage { get; set; }
}
