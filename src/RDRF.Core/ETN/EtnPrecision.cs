using RDRF.Core.FSS;
using RDRF.Core.Index;
using RDRF.Core.Dssa;

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

        // Parse index first to determine block size from file size
        RdrfIndex? index = null;
        try { index = IndexManager.DeserializeIndex(indexBytes); }
        catch (Exception ex)
        {
            result.ErrorMessage = $"Index deserialization failed: {ex.Message}";
            return result;
        }
        int blockSize = index != null ? EtnBlockMap.GetBlockSize(index.FileSize, index.FssStrategy) : 256;

        byte[] strippedIndexBytes = StripFss6Fields(indexBytes);
        byte[] actualIndexFlat = EtnBlockMap.Build(strippedIndexBytes, blockSize);
        int actualIndexCount = EtnBlockMap.BlockCount(actualIndexFlat);
        byte[] actualRcFlat = EtnBlockMap.Build(rcBytes, blockSize);
        int actualRcCount = EtnBlockMap.BlockCount(actualRcFlat);

        var rcStoredIndexBm = rcFile.IndexBlockMap.Select(EtnBlockMap.HexToHash).ToList();
        var rcStoredFragmentBms = rcFile.FragmentBlockMaps
            .Select(list => list.Select(EtnBlockMap.HexToHash).ToList()).ToList();

        int n = fragmentsWithTrailers.Count;
        var actualFragmentFlats = new byte[n][];
        var fragmentBlockCounts = new int[n];
        var trailerFragmentFlats = new byte[n][];
        var trailerFragmentCounts = new int[n];
        var trailerIndexFlats = new byte[n][];
        var trailerIndexCounts = new int[n];
        var trailerRcFlats = new byte[n][];
        var trailerRcCounts = new int[n];

        Parallel.For(0, n, i =>
        {
            var (data, tFragFlat, tFragCnt, tIdxFlat, tIdxCnt, tRcFlat, tRcCnt)
                = ParseAnyTrailer(fragmentsWithTrailers[i]);
            actualFragmentFlats[i] = EtnBlockMap.Build(data, blockSize);
            fragmentBlockCounts[i] = EtnBlockMap.BlockCount(actualFragmentFlats[i]);
            trailerFragmentFlats[i] = tFragFlat;
            trailerFragmentCounts[i] = tFragCnt;
            trailerIndexFlats[i] = tIdxFlat;
            trailerIndexCounts[i] = tIdxCnt;
            trailerRcFlats[i] = tRcFlat;
            trailerRcCounts[i] = tRcCnt;
        });

        var indexStoredRcBm = index?.Fss6RcBlockMap?.Select(EtnBlockMap.HexToHash).ToList() ?? new List<byte[]>();
        var indexStoredFragmentBms = index?.Fss6FragmentBlockMaps
            ?.Select(list => list.Select(EtnBlockMap.HexToHash).ToList()).ToList()
            ?? new List<List<byte[]>>();

        CheckIndex(result, actualIndexFlat, actualIndexCount, rcStoredIndexBm, trailerIndexFlats, trailerIndexCounts);
        CheckRc(result, actualRcFlat, actualRcCount, indexStoredRcBm, trailerRcFlats, trailerRcCounts);
        CheckFragments(result, actualFragmentFlats, fragmentBlockCounts,
            trailerFragmentFlats, trailerFragmentCounts, rcStoredFragmentBms, indexStoredFragmentBms);

        result.IsValid = !result.IndexCorrupted && !result.RcCorrupted && result.CorruptedFragments.Count == 0;
        return result;
    }

    private static void CheckIndex(
        PrecisionResult result,
        byte[] actualIndexFlat, int actualIndexCount,
        List<byte[]> rcStoredIndexBm,
        byte[][] trailerIndexFlats, int[] trailerIndexCounts)
    {
        bool rcMatch = rcStoredIndexBm.Count > 0 &&
            EtnBlockMap.DiffTrimmed(actualIndexFlat, actualIndexCount, rcStoredIndexBm).Count == 0;
        var trailerConsensus = TrailerConsensusFlat(trailerIndexFlats, trailerIndexCounts);
        bool trailerMatch = trailerConsensus != null &&
            EtnBlockMap.DiffTrimmed(actualIndexFlat, actualIndexCount, trailerConsensus).Count == 0;

        if (rcMatch && trailerMatch) return;

        if (!rcMatch && trailerMatch)
        {
            result.RcCorrupted = true;
            result.RcCorruptedBlocks = EtnBlockMap.DiffTrimmed(rcStoredIndexBm, actualIndexFlat, actualIndexCount);
            return;
        }

        if (rcMatch && !trailerMatch)
        {
            result.CorruptedFragmentTrailers = FindDisagreeingFlat(trailerIndexFlats, trailerIndexCounts, actualIndexFlat, actualIndexCount);
            return;
        }

        if (!rcMatch && !trailerMatch && trailerConsensus != null &&
            EtnBlockMap.DiffTrimmed(rcStoredIndexBm, trailerConsensus).Count == 0)
        {
            result.IndexCorrupted = true;
            result.IndexCorruptedBlocks = EtnBlockMap.DiffTrimmed(rcStoredIndexBm, actualIndexFlat, actualIndexCount);
            return;
        }

        result.IndexCorrupted = true;
        result.IndexCorruptedBlocks = EtnBlockMap.DiffTrimmed(trailerConsensus ?? rcStoredIndexBm, actualIndexFlat, actualIndexCount);
    }

    private static void CheckRc(
        PrecisionResult result,
        byte[] actualRcFlat, int actualRcCount,
        List<byte[]> indexStoredRcBm,
        byte[][] trailerRcFlats, int[] trailerRcCounts)
    {
        bool indexMatch = indexStoredRcBm.Count > 0 &&
            EtnBlockMap.DiffTrimmed(actualRcFlat, actualRcCount, indexStoredRcBm).Count == 0;
        var trailerConsensus = TrailerConsensusFlat(trailerRcFlats, trailerRcCounts);
        bool trailerMatch = trailerConsensus != null &&
            EtnBlockMap.DiffTrimmed(actualRcFlat, actualRcCount, trailerConsensus).Count == 0;

        if (indexMatch && trailerMatch) return;

        if (indexMatch && !trailerMatch)
        {
            result.CorruptedFragmentTrailers = Union(result.CorruptedFragmentTrailers,
                FindDisagreeingFlat(trailerRcFlats, trailerRcCounts, actualRcFlat, actualRcCount));
            return;
        }

        if (!indexMatch && trailerMatch) return;

        if (!indexMatch && !trailerMatch && trailerConsensus != null &&
            EtnBlockMap.DiffTrimmed(indexStoredRcBm, trailerConsensus).Count == 0)
        {
            result.RcCorrupted = true;
            result.RcCorruptedBlocks = EtnBlockMap.DiffTrimmed(indexStoredRcBm, actualRcFlat, actualRcCount);
            return;
        }

        result.RcCorrupted = true;
        result.RcCorruptedBlocks = EtnBlockMap.DiffTrimmed(trailerConsensus ?? indexStoredRcBm, actualRcFlat, actualRcCount);
    }

    private static void CheckFragments(
        PrecisionResult result,
        byte[][] actualFragmentFlats, int[] fragmentBlockCounts,
        byte[][] trailerFragmentFlats, int[] trailerFragmentCounts,
        List<List<byte[]>> rcStoredFragmentBms,
        List<List<byte[]>> indexStoredFragmentBms)
    {
        for (int i = 0; i < actualFragmentFlats.Length; i++)
        {
            var actualFlat = actualFragmentFlats[i];
            int blockCount = fragmentBlockCounts[i];
            bool hasTrailer = i < trailerFragmentFlats.Length;
            bool hasRc = i < rcStoredFragmentBms.Count;
            bool hasIndex = i < indexStoredFragmentBms.Count;

            if (!hasRc && !hasIndex) continue;

            // Tier 1: compare actual[..2] vs trailer fragment BM (2B)
            var suspicious = new List<int>();
            if (hasTrailer && trailerFragmentFlats[i].Length > 0)
            {
                byte[] tFlat = trailerFragmentFlats[i];
                int tCount = Math.Min(blockCount, trailerFragmentCounts[i]);
                for (int b = 0; b < tCount; b++)
                    if (actualFlat[b * 32] != tFlat[b * 2] || actualFlat[b * 32 + 1] != tFlat[b * 2 + 1])
                        suspicious.Add(b);
                for (int b = tCount; b < blockCount; b++)
                    suspicious.Add(b);
            }
            else
            {
                for (int b = 0; b < blockCount; b++)
                    suspicious.Add(b);
            }

            if (suspicious.Count == 0) continue;

            // Tier 2: confirm suspicious against RC (8B) + Index (8B)
            var corrupted = new List<int>();
            foreach (int b in suspicious)
            {
                bool rcOk = hasRc && b < rcStoredFragmentBms[i].Count &&
                    EtnBlockMap.IsSecondPassMatch(actualFlat, b, rcStoredFragmentBms[i][b]);
                bool idxOk = hasIndex && b < indexStoredFragmentBms[i].Count &&
                    EtnBlockMap.IsSecondPassMatch(actualFlat, b, indexStoredFragmentBms[i][b]);

                if (!rcOk && !idxOk)
                    corrupted.Add(b);
                else
                {
                    if (!result.SuspiciousFragmentBlocks.ContainsKey(i))
                        result.SuspiciousFragmentBlocks[i] = new List<int>();
                    result.SuspiciousFragmentBlocks[i].Add(b);
                }
            }

            if (corrupted.Count > 0)
            {
                result.CorruptedFragments.Add(i);
                result.CorruptedFragmentBlocks[i] = corrupted;
            }
        }
    }

    private static List<byte[]>? TrailerConsensusFlat(byte[][] trailerFlats, int[] trailerCounts)
    {
        if (trailerFlats.Length == 0) return null;
        if (trailerFlats.Length == 1)
            return ToListOfBytes(trailerFlats[0], trailerCounts[0]);
        var reference = ToListOfBytes(trailerFlats[0], trailerCounts[0]);
        for (int i = 1; i < trailerFlats.Length; i++)
            if (EtnBlockMap.DiffTrimmed(trailerFlats[i], trailerCounts[i], EtnBlockMap.TrailerHashLen, reference).Count != 0) return null;
        return reference;
    }

    private static List<int> FindDisagreeingFlat(byte[][] bmFlats, int[] bmCounts, byte[] referenceFlat, int referenceCount)
    {
        var list = new List<int>();
        for (int i = 0; i < bmFlats.Length; i++)
            if (EtnBlockMap.DiffTrimmed(bmFlats[i], bmCounts[i], referenceFlat, referenceCount, EtnBlockMap.TrailerHashLen).Count != 0)
                list.Add(i);
        return list;
    }

    private static List<byte[]> ToListOfBytes(byte[] flat, int count)
    {
        var list = new List<byte[]>(count);
        for (int i = 0; i < count; i++)
        {
            byte[] h = new byte[2];
            Buffer.BlockCopy(flat, i * 2, h, 0, 2);
            list.Add(h);
        }
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
        index.Fss6FragmentBlockMaps = null;
        index.Fss6RcBlockMap = null;
        return IndexManager.SerializeIndex(index);
    }

    private static (byte[] data, byte[] fragFlat, int fragCount, byte[] indexFlat, int indexCount, byte[] rcFlat, int rcCount) ParseAnyTrailer(byte[] fragmentData)
    {
        // Try FSS6.1 repair trailer first
        var (raw61, _, _, _, _) = Fss61RepairTrailer.Parse(fragmentData);
        if (raw61.Length < fragmentData.Length)
            return (raw61, [], 0, [], 0, [], 0);
        // Fall back to ETN trailer
        return EtnTrailer.Parse(fragmentData);
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
    /// <summary>Error message when validation fails.</summary>
    public string? ErrorMessage { get; set; }
}
