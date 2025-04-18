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
        var (data, _, _) = EtnTrailer.Parse(fragmentData);
        return data;
    }

    public static List<byte[]> BuildBlockMap(byte[] data) => EtnBlockMap.Build(data);
    public static bool CompareBlockMaps(List<byte[]> a, List<byte[]> b) => EtnBlockMap.Compare(a, b);
    public static byte[] BuildTrailer(List<byte[]> indexBlockMap, List<byte[]> rcBlockMap, int rawSize = 0)
        => EtnTrailer.Build(indexBlockMap, rcBlockMap, rawSize);

    public static (byte[] data, List<byte[]> indexBlockMap, List<byte[]> rcBlockMap) ParseTrailer(byte[] fragmentData)
        => EtnTrailer.Parse(fragmentData);

    public static byte[] StripEtnFieldsFromIndexJson(byte[] indexBytes)
        => EtnPrecision.StripFss6Fields(indexBytes);

    public static (List<byte[]> Fragments, byte[] IndexJson, byte[] RcJson) InjectCrossValidation(
        List<byte[]> fragments, byte[] indexBytes, string fileFingerprint)
    {
        var indexBlockMap = EtnBlockMap.Build(indexBytes);
        var fragmentBlockMaps = fragments.Select(EtnBlockMap.Build).ToList();

        var rcFile = new RcFile
        {
            Version = 1,
            FileFingerprint = fileFingerprint,
            IndexBlockMap = indexBlockMap.Select(EtnBlockMap.HashToHex).ToList(),
FragentBlockMaps = fragmentBlockMaps.Select(
                list => list.Select(EtnBlockMap.HashToHex).ToList()).ToList(),
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };
        byte[] rcBytes = rcFile.ToCborBytes();
        var rcBlockMap = EtnBlockMap.Build(rcBytes);

        for (int i = 0; i < fragments.Count; i++)
        {
            int rawLen = fragments[i].Length;
            byte[] trailer = EtnTrailer.Build(indexBlockMap, rcBlockMap, rawLen);
            byte[] withTrailer = new byte[rawLen + trailer.Length];
            Buffer.BlockCopy(fragments[i], 0, withTrailer, 0, rawLen);
            Buffer.BlockCopy(trailer, 0, withTrailer, rawLen, trailer.Length);
            fragments[i] = withTrailer;
        }

        byte[] updatedIndexBytes = AddFss6FieldsToIndex(indexBytes, fragmentBlockMaps, rcBlockMap);
        return (fragments, updatedIndexBytes, rcBytes);
    }

    private static byte[] AddFss6FieldsToIndex(
        byte[] indexBytes, List<List<byte[]>> fragmentBlockMaps, List<byte[]> rcBlockMap)
    {
        var index = IndexManager.DeserializeIndex(indexBytes);
        if (index == null)
            throw new InvalidDataException("Failed to parse index JSON for ETN injection");

        index.Fss6FragentBlockMaps = fragmentBlockMaps.Select(
            list => list.Select(EtnBlockMap.HashToHex).ToList()).ToList();
        index.Fss6RcBlockMap = rcBlockMap.Select(EtnBlockMap.HashToHex).ToList();

        return IndexManager.SerializeIndex(index);
    }

    public static CrossValidationResult CrossValidate(
        byte[] indexBytes, List<byte[]> fragmentsWithTrailers, byte[] rcBytes)
    {
        var precision = EtnPrecision.Analyze(indexBytes, rcBytes, fragmentsWithTrailers);
        return CrossValidationResult.FromPrecision(precision);
    }
}

public class CrossValidationResult
{
    public bool IsValid { get; set; } = true;
    public List<int> CorruptedFragments { get; set; } = new();
    public bool IndexCorrupted { get; set; }
    public bool RcCorrupted { get; set; }
    public string? ErrorMessage { get; set; }
    public List<int> IndexCorruptedBlocks { get; set; } = new();
    public List<int> RcCorruptedBlocks { get; set; } = new();
    public Dictionary<int, List<int>> CorruptedFragmentBlocks { get; set; } = new();
    public List<int> CorruptedFragmentTrailers { get; set; } = new();

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
        };
    }
}
