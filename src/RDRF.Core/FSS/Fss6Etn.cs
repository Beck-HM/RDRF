using RDRF.Core.ETN;
using RDRF.Core.Index;
using RDRF.Core.Storage;

namespace RDRF.Core.FSS;

public class Fss6Etn : IFssStrategy
{
    public string Level => Constants.FssLevel6;

    public List<byte[]> Encode(List<byte[]> fragments) => fragments;

    public List<byte[]> Strip(Dictionary<int, byte[]> encodedFragments, int originalFragmentCount, List<int>? originalSizes = null)
    {
        var result = new List<byte[]>();
        foreach (var kvp in encodedFragments.OrderBy(k => k.Key))
            result.Add(kvp.Value);
        return result;
    }

    public Dictionary<int, byte[]> Decode(
        Dictionary<int, byte[]> available,
        List<int> missingIndices,
        int totalFragments,
        List<int>? originalSizes = null)
        => new();

    public byte[] Strip(byte[] fragmentData)
    {
        // Try FSS6.1 trailer first, fall back to ETN trailer
        var (raw61, _, _, _, _) = Fss61RepairTrailer.Parse(fragmentData);
        if (raw61.Length < fragmentData.Length) return raw61;
        var (data, _, _, _, _, _, _) = EtnTrailer.Parse(fragmentData);
        return data;
    }

    public byte[] StripSingle(byte[] encodedFragment, int index, List<int>? originalSizes = null)
        => encodedFragment;

    public static byte[] BuildBlockMap(byte[] data) => EtnBlockMap.Build(data);
    public static bool CompareBlockMaps(List<byte[]> a, List<byte[]> b) => EtnBlockMap.DiffTrimmed(a, b).Count == 0;
    public static byte[] BuildTrailer(byte[] fragFlat, int fragCount, byte[] indexFlat, int indexCount, byte[] rcFlat, int rcCount, int rawSize = 0)
        => EtnTrailer.Build(fragFlat, fragCount, indexFlat, indexCount, rcFlat, rcCount, rawSize);

    public static (byte[] data, byte[] indexFlat, int indexCount, byte[] rcFlat, int rcCount) ParseTrailer(byte[] fragmentData)
    {
        var (data, _, _, indexFlat, indexCount, rcFlat, rcCount) = EtnTrailer.Parse(fragmentData);
        return (data, indexFlat, indexCount, rcFlat, rcCount);
    }

    public static byte[] StripEtnFieldsFromIndexJson(byte[] indexBytes)
        => EtnPrecision.StripFss6Fields(indexBytes);

    public static (List<byte[]> Fragments, byte[] IndexJson, byte[] RcJson) InjectCrossValidation(
        List<byte[]> fragments, byte[] indexBytes, string fileFingerprint, long fileSize, string strategy)
    {
        int bs = EtnBlockMap.GetBlockSize(fileSize, strategy);
        byte[] indexBlockFlat = EtnBlockMap.Build(indexBytes, bs);
        int idxBlockCount = EtnBlockMap.BlockCount(indexBlockFlat);

        var fragmentBlockFlats = new byte[fragments.Count][];
        Parallel.For(0, fragments.Count, i =>
        {
            fragmentBlockFlats[i] = EtnBlockMap.Build(fragments[i], bs);
        });

        var rcFile = new RcFile
        {
            Version = 1,
            FileFingerprint = fileFingerprint,
            IndexBlockMap = HexListFromSecondFlat(indexBlockFlat, idxBlockCount),
            FragmentBlockMaps = fragmentBlockFlats.Select(f => HexListFromSecondFlat(f, EtnBlockMap.BlockCount(f))).ToList(),
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };
        byte[] rcBytes = rcFile.ToCborBytes();
        byte[] rcBlockFlat = EtnBlockMap.Build(rcBytes, bs);
        int rcBlockCount = EtnBlockMap.BlockCount(rcBlockFlat);

        for (int i = 0; i < fragments.Count; i++)
        {
            int rawLen = fragments[i].Length;
            int fragCount = EtnBlockMap.BlockCount(fragmentBlockFlats[i]);
            byte[] trailer = EtnTrailer.Build(
                fragmentBlockFlats[i], fragCount,
                indexBlockFlat, idxBlockCount,
                rcBlockFlat, rcBlockCount,
                rawLen);
            byte[] withTrailer = new byte[rawLen + trailer.Length];
            Buffer.BlockCopy(fragments[i], 0, withTrailer, 0, rawLen);
            Buffer.BlockCopy(trailer, 0, withTrailer, rawLen, trailer.Length);
            fragments[i] = withTrailer;
        }

        byte[] updatedIndexBytes = AddFss6FieldsToIndex(indexBytes, fragmentBlockFlats, rcBlockFlat);
        return (fragments, updatedIndexBytes, rcBytes);
    }

    private static byte[] AddFss6FieldsToIndex(
        byte[] indexBytes, byte[][] fragmentBlockFlats, byte[] rcBlockFlat)
    {
        var index = IndexManager.DeserializeIndex(indexBytes);
        if (index == null)
            throw new InvalidDataException("Failed to parse index for ETN injection");

        int rcBlockCount = EtnBlockMap.BlockCount(rcBlockFlat);
        index.Fss6RcBlockMap = HexListFromSecondFlat(rcBlockFlat, rcBlockCount);

        index.Fss6FragmentBlockMaps = new List<List<string>>();
        for (int i = 0; i < fragmentBlockFlats.Length; i++)
        {
            int fc = EtnBlockMap.BlockCount(fragmentBlockFlats[i]);
            index.Fss6FragmentBlockMaps.Add(HexListFromSecondFlat(fragmentBlockFlats[i], fc));
        }

        return IndexManager.SerializeIndex(index);
    }

    public static CrossValidationResult CrossValidate(
        byte[] indexBytes, List<byte[]> fragmentsWithTrailers, byte[] rcBytes)
    {
        var precision = EtnPrecision.Analyze(indexBytes, rcBytes, fragmentsWithTrailers);
        return CrossValidationResult.FromPrecision(precision);
    }

    private static List<string> HexListFromSecondFlat(byte[] flat, int blockCount)
    {
        var list = new List<string>(blockCount);
        for (int i = 0; i < blockCount; i++)
            list.Add(EtnBlockMap.HashToHex(EtnBlockMap.TruncateSecond(flat, i)));
        return list;
    }
}

public class CrossValidationResult
{
    public bool IsValid { get; set; } = true;
    public List<int> CorruptedFragments { get; set; } = new();
    public bool IndexCorrupted { get; set; }
    public bool RcCorrupted { get; set; }
    /// <summary>Error message when cross-validation fails.</summary>
    public string? ErrorMessage { get; set; }
    public List<int> IndexCorruptedBlocks { get; set; } = new();
    public List<int> RcCorruptedBlocks { get; set; } = new();
    public Dictionary<int, List<int>> CorruptedFragmentBlocks { get; set; } = new();
    public List<int> CorruptedFragmentTrailers { get; set; } = new();
    public Dictionary<int, List<int>> SuspiciousFragmentBlocks { get; set; } = new();

    public static CrossValidationResult FromPrecision(PrecisionResult p)
    {
        return new CrossValidationResult
        {
            IsValid = p.IsValid,
            CorruptedFragments = p.CorruptedFragments,
            IndexCorrupted = p.IndexCorrupted,
            RcCorrupted = p.RcCorrupted,
            ErrorMessage = p.ErrorMessage,
            IndexCorruptedBlocks = p.IndexCorruptedBlocks,
            RcCorruptedBlocks = p.RcCorruptedBlocks,
            CorruptedFragmentBlocks = p.CorruptedFragmentBlocks,
            CorruptedFragmentTrailers = p.CorruptedFragmentTrailers,
            SuspiciousFragmentBlocks = p.SuspiciousFragmentBlocks,
        };
    }
}
