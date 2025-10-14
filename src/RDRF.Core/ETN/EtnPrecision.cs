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
        byte[] strippedRcBytes = StripFss6RcFields(rcBytes);
        byte[] actualRcFlat = EtnBlockMap.Build(strippedRcBytes, blockSize);
        int actualRcCount = EtnBlockMap.BlockCount(actualRcFlat);

        var rcStoredIndexBm = rcFile.IndexBlockMap.Select(EtnBlockMap.HashFromString).ToList();
        var rcStoredIndex2B = rcFile.Index2B?.Select(EtnBlockMap.HashFromString).ToList();
        var rcStoredFragmentBms = rcFile.FragmentBlockMaps
            .Select(list => list.Select(EtnBlockMap.HashFromString).ToList()).ToList();
        var rcStoredFragment2B = rcFile.Fragment2B
            ?.Select(list => list.Select(EtnBlockMap.HashFromString).ToList()).ToList();

        int n = fragmentsWithTrailers.Count;
        var actualFragmentFlats = new byte[n][];
        var fragmentBlockCounts = new int[n];
        var trailerIndex2B = new byte[n][];
        var trailerIndex2BCounts = new int[n];
        var trailerIndex8B = new byte[n][];
        var trailerRc2B = new byte[n][];
        var trailerRc2BCounts = new int[n];
        var trailerRc8B = new byte[n][];

        Parallel.For(0, n, i =>
        {
            var t = ParseAnyTrailer(fragmentsWithTrailers[i]);
            actualFragmentFlats[i] = EtnBlockMap.Build(t.RawData, blockSize);
            fragmentBlockCounts[i] = EtnBlockMap.BlockCount(actualFragmentFlats[i]);
            trailerIndex2B[i] = t.Index2B;
            trailerIndex2BCounts[i] = t.Index2BCount;
            trailerIndex8B[i] = t.Index8B;
            trailerRc2B[i] = t.Rc2B;
            trailerRc2BCounts[i] = t.Rc2BCount;
            trailerRc8B[i] = t.Rc8B;
        });

        List<byte[]>? indexStoredRcBm;
        if (index?.Fss6RcBlockMapFlat != null)
            indexStoredRcBm = SplitFlat(index.Fss6RcBlockMapFlat, EtnBlockMap.SecondHashLen);
        else
            indexStoredRcBm = index?.Fss6RcBlockMap?.Select(EtnBlockMap.HashFromString).ToList();

        List<byte[]>? indexStoredRc2B;
        if (index?.Fss6RcBlockMapFlat != null)
            indexStoredRc2B = SplitFlat(index.Fss6RcBlockMapFlat, EtnBlockMap.TrailerHashLen);
        else
            indexStoredRc2B = index?.Fss6Rc2B?.Select(EtnBlockMap.HashFromString).ToList();

        var indexStoredFragmentBms = new List<List<byte[]>>();
        var indexStoredFragment2B = new List<List<byte[]>>();
        if (index?.Fss6FragmentBlockMapsFlat != null)
        {
            foreach (var flat in index.Fss6FragmentBlockMapsFlat)
            {
                indexStoredFragmentBms.Add(SplitFlat(flat, EtnBlockMap.SecondHashLen));
                indexStoredFragment2B.Add(SplitFlat(flat, EtnBlockMap.TrailerHashLen));
            }
        }
        else if (index?.Fss6FragmentBlockMaps != null)
        {
            foreach (var list in index.Fss6FragmentBlockMaps)
                indexStoredFragmentBms.Add(list.Select(EtnBlockMap.HashFromString).ToList());
            if (index?.Fss6Fragment2B != null)
                foreach (var list in index.Fss6Fragment2B)
                    indexStoredFragment2B.Add(list.Select(EtnBlockMap.HashFromString).ToList());
        }

        CheckIndex(result, actualIndexFlat, actualIndexCount,
            rcStoredIndexBm, rcStoredIndex2B,
            trailerIndex2B, trailerIndex2BCounts, trailerIndex8B);
        CheckRc(result, actualRcFlat, actualRcCount,
            indexStoredRcBm, indexStoredRc2B,
            trailerRc2B, trailerRc2BCounts, trailerRc8B);
        CheckFragments(result, actualFragmentFlats, fragmentBlockCounts,
            rcStoredFragmentBms, rcStoredFragment2B,
            indexStoredFragmentBms, indexStoredFragment2B);

        result.IsValid = !result.IndexCorrupted && !result.RcCorrupted && result.CorruptedFragments.Count == 0;
        return result;
    }

    private static void CheckIndex(
        PrecisionResult result,
        byte[] actualIndexFlat, int actualIndexCount,
        List<byte[]> rc8B,
        List<byte[]>? rc2B,
        byte[][] trailerIdx2B, int[] trailerIdx2BCounts,
        byte[][] trailerIdx8B)
    {
        var idx2BConsensus = TrailerConsensusFlat(trailerIdx2B, trailerIdx2BCounts);
        if (idx2BConsensus == null && trailerIdx2B.Length > 0)
            idx2BConsensus = ToListOfBytes2B(trailerIdx2B[0], trailerIdx2BCounts[0]);

        bool has8BTrailer = trailerIdx8B.Length > 0 && trailerIdx8B[0].Length > 0;

        for (int b = 0; b < actualIndexCount; b++)
        {
            // Tier 1: 2B → pass or suspicious
            if (b < idx2BConsensus.Count && idx2BConsensus[b].Length >= 2 &&
                actualIndexFlat[b * 32] == idx2BConsensus[b][0] &&
                actualIndexFlat[b * 32 + 1] == idx2BConsensus[b][1])
                continue;

            // Tier 2: 8B → collision or corrupted
            bool b8BOk = (has8BTrailer && b < trailerIdx2BCounts[0] &&
                Is8BMatch(actualIndexFlat, b,
                    trailerIdx8B[0].AsSpan(b * 8, 8).ToArray()));
            b8BOk = b8BOk || (b < rc8B.Count &&
                Is8BMatch(actualIndexFlat, b, rc8B[b]));

            if (!b8BOk)
            {
                result.IndexCorrupted = true;
                result.IndexCorruptedBlocks.Add(b);
            }
        }
    }

    private static void CheckRc(
        PrecisionResult result,
        byte[] actualRcFlat, int actualRcCount,
        List<byte[]> index8B,
        List<byte[]>? index2B,
        byte[][] trailerRc2B, int[] trailerRc2BCounts,
        byte[][] trailerRc8B)
    {
        var rc2BConsensus = TrailerConsensusFlat(trailerRc2B, trailerRc2BCounts);
        if (rc2BConsensus == null && trailerRc2B.Length > 0)
            rc2BConsensus = ToListOfBytes2B(trailerRc2B[0], trailerRc2BCounts[0]);

        bool has8BTrailer = trailerRc8B.Length > 0 && trailerRc8B[0].Length > 0;

        for (int b = 0; b < actualRcCount; b++)
        {
            if (b < rc2BConsensus.Count && rc2BConsensus[b].Length >= 2 &&
                actualRcFlat[b * 32] == rc2BConsensus[b][0] &&
                actualRcFlat[b * 32 + 1] == rc2BConsensus[b][1])
                continue;

            bool b8BOk = (has8BTrailer && b < trailerRc2BCounts[0] &&
                Is8BMatch(actualRcFlat, b,
                    trailerRc8B[0].AsSpan(b * 8, 8).ToArray()));
            b8BOk = b8BOk || (b < index8B.Count &&
                Is8BMatch(actualRcFlat, b, index8B[b]));

            if (!b8BOk)
            {
                result.RcCorrupted = true;
                result.RcCorruptedBlocks.Add(b);
            }
        }
    }

    private static bool Is8BMatch(byte[] actualFlat, int blockIndex, byte[] stored8B)
        => EtnBlockMap.IsSecondPassMatch(actualFlat, blockIndex, stored8B);

    private static void CheckFragments(
        PrecisionResult result,
        byte[][] actualFragmentFlats, int[] fragmentBlockCounts,
        List<List<byte[]>> rc8B,
        List<List<byte[]>>? rc2B,
        List<List<byte[]>> index8B,
        List<List<byte[]>>? index2B)
    {
        for (int i = 0; i < actualFragmentFlats.Length; i++)
        {
            var actualFlat = actualFragmentFlats[i];
            int blockCount = fragmentBlockCounts[i];
            bool hasRc8B = i < rc8B.Count;
            bool hasIdx8B = i < index8B.Count;
            if (!hasRc8B && !hasIdx8B) continue;

            // Tier 1: frag2B from Index CBOR (A) or RC CBOR (C)
            List<byte[]>? frag2B = (index2B != null && i < index2B.Count) ? index2B[i]
                : (rc2B != null && i < rc2B.Count) ? rc2B[i] : null;
            var suspicious = new List<int>();
            if (frag2B != null && frag2B.Count > 0)
            {
                int tCount = Math.Min(blockCount, frag2B.Count);
                for (int b = 0; b < tCount; b++)
                {
                    if (actualFlat[b * 32] != frag2B[b][0] || actualFlat[b * 32 + 1] != frag2B[b][1])
                        suspicious.Add(b);
                }
                for (int b = tCount; b < blockCount; b++)
                    suspicious.Add(b);
            }
            else
            {
                for (int b = 0; b < blockCount; b++)
                    suspicious.Add(b);
            }

            if (suspicious.Count == 0) continue;

            // Tier 2: frag8B from RC (C) + Index (A)
            var corrupted = new List<int>();
            foreach (int b in suspicious)
            {
                bool rcOk = hasRc8B && b < rc8B[i].Count &&
                    EtnBlockMap.IsSecondPassMatch(actualFlat, b, rc8B[i][b]);
                bool idxOk = hasIdx8B && b < index8B[i].Count &&
                    EtnBlockMap.IsSecondPassMatch(actualFlat, b, index8B[i][b]);

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
            return ToListOfBytes2B(trailerFlats[0], trailerCounts[0]);
        var reference = ToListOfBytes2B(trailerFlats[0], trailerCounts[0]);
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

    private static List<byte[]> ToListOfBytes2B(byte[] flat, int count)
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

    internal static byte[] StripFss6RcFields(byte[] rcBytes)
    {
        var rc = RcFile.FromCbor(rcBytes);
        rc.RepairA = null;
        rc.RepairB = null;
        rc.Repair62A = null;
        rc.Repair62B = null;
        return rc.ToCborBytes();
    }

    internal static byte[] StripFss6Fields(byte[] indexBytes)
    {
        var index = IndexManager.DeserializeIndex(indexBytes);
        if (index == null) return indexBytes;
        index.Fss6FragmentBlockMaps = null;
        index.Fss6FragmentBlockMapsFlat = null;
        index.Fss6Fragment2B = null;
        index.Fss6RcBlockMap = null;
        index.Fss6RcBlockMapFlat = null;
        index.Fss6Rc2B = null;
        index.Fss61RepairB = null;
        index.Fss61RepairC = null;
        index.Fss62RepairB = null;
        index.Fss62RepairC = null;
        return IndexManager.SerializeIndex(index);
    }

    private static List<byte[]> SplitFlat(byte[] flat, int hashLen)
    {
        int count = flat.Length / hashLen;
        var list = new List<byte[]>(count);
        for (int i = 0; i < count; i++)
        {
            byte[] h = new byte[hashLen];
            Buffer.BlockCopy(flat, i * hashLen, h, 0, hashLen);
            list.Add(h);
        }
        return list;
    }

    private static EtnTrailerData ParseAnyTrailer(byte[] fragmentData)
    {
        var (raw62, _, _, _, _) = Fss62RepairTrailer.Parse(fragmentData);
        if (raw62.Length < fragmentData.Length)
        {
            var (raw61b, _, _, _, _) = Fss61RepairTrailer.Parse(raw62);
            if (raw61b.Length < raw62.Length)
                return EtnTrailer.Parse(raw61b);
            return EtnTrailer.Parse(raw62);
        }
        var (raw61, _, _, _, _) = Fss61RepairTrailer.Parse(fragmentData);
        if (raw61.Length < fragmentData.Length)
            return EtnTrailer.Parse(raw61);
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
    public string? ErrorMessage { get; set; }
}
