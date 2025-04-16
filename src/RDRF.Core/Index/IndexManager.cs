using System.Text.Json;
using System.Text.Json.Serialization;
using RDRF.Core.Encryption;

namespace RDRF.Core.Index;

public static class IndexManager
{
    public static RdrfIndex BuildIndex(
        string fileFingerprint,
        string originalFilename,
        long originalSize,
        List<string> fragmentHashes,
        List<string> fragmentNonces,
        string originalHash,
        string fssStrategy,
        List<int>? originalFragentSizes = null,
        int? originalFragentCount = null,
        Dictionary<string, object>? fssParams = null)
    {
        int fragmentCount = fragmentHashes.Count;
        var index = new RdrfIndex
        {
            FileFingerprint = fileFingerprint,
            OriginalName = originalFilename,
            FileSize = originalSize,
            FragentCount = fragmentCount,
            FragentHashes = fragmentHashes,
            OriginalHash = originalHash,
            FssStrategy = fssStrategy,
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            FssParams = fssParams,
            OriginalFragentSizes = originalFragentSizes ?? new List<int>(),
            Salt = string.Empty,
        };

        var fragments = new List<FragentInfo>(fragmentCount);
        for (int i = 0; i < fragmentCount; i++)
        {
            fragments.Add(new FragentInfo
            {
                Index = i,
                Hash = fragmentHashes[i],
                Nonce = fragmentNonces[i],
            });
        }
        index.Fragents = fragments;

        if (originalFragentCount.HasValue)
            index.OriginalFragentCount = originalFragentCount.Value;

        return index;
    }

    public static byte[] SerializeIndex(RdrfIndex index)
    {
        return JsonSerializer.SerializeToUtf8Bytes(index, new JsonSerializerOptions
        {
            WriteIndented = false,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        });
    }

    public static RdrfIndex DeserializeIndex(byte[] jsonBytes)
    {
        var index = JsonSerializer.Deserialize<RdrfIndex>(jsonBytes);
        if (index == null)
            throw new InvalidDataException("Failed to parse embedded index");
        return index;
    }

    public static byte[] EncryptIndexWithKey(RdrfIndex index, byte[] aesKey)
    {
        byte[] json = SerializeIndex(index);
        string jsonString = System.Text.Encoding.UTF8.GetString(json);
        return EncryptionLayer.EncryptIndexFileWithKey(jsonString, aesKey);
    }

    public static byte[] EncryptIndex(RdrfIndex index, byte[] rcCode)
        => EncryptIndexWithKey(index, EncryptionLayer.DeriveKey(rcCode));

    public static RdrfIndex DecryptIndexWithKey(byte[] encryptedIndex, byte[] aesKey)
    {
        string json = EncryptionLayer.DecryptIndexFileWithKey(encryptedIndex, aesKey);
        RdrfIndex? index = JsonSerializer.Deserialize<RdrfIndex>(json);
        if (index == null)
            throw new InvalidDataException("Failed to parse index file");
        return index;
    }

    public static RdrfIndex DecryptIndex(byte[] encryptedIndex, byte[] rcCode)
        => DecryptIndexWithKey(encryptedIndex, EncryptionLayer.DeriveKey(rcCode));

    public static FragentInfo? GetFragentInfo(RdrfIndex index, int fragmentIndex)
        => index.Fragents?.FirstOrDefault(f => f.Index == fragmentIndex);
}

public class RdrfIndex
{
    [JsonPropertyName("file_fingerprint")]
    public string FileFingerprint { get; set; } = string.Empty;

    [JsonPropertyName("custom_name")]
    public string? CustomName { get; set; }

    [JsonPropertyName("original_name")]
    public string OriginalName { get; set; } = string.Empty;

    [JsonPropertyName("file_size")]
    public long FileSize { get; set; }

    [JsonPropertyName("fragment_count")]
    public int FragentCount { get; set; }

    [JsonPropertyName("original_fragment_count")]
    public int OriginalFragentCount { get; set; }

    [JsonPropertyName("original_fragment_sizes")]
    public List<int> OriginalFragentSizes { get; set; } = new();

    [JsonPropertyName("fragment_hashes")]
    public List<string> FragentHashes { get; set; } = new();

    [JsonPropertyName("original_hash")]
    public string OriginalHash { get; set; } = string.Empty;

    [JsonPropertyName("fss_strategy")]
    public string FssStrategy { get; set; } = "FSS1";

    [JsonPropertyName("fss_params")]
    public Dictionary<string, object>? FssParams { get; set; }

    [JsonPropertyName("fss6_fragment_block_maps")]
    public List<List<string>>? Fss6FragentBlockMaps { get; set; }

    [JsonPropertyName("fss6_rc_block_map")]
    public List<string>? Fss6RcBlockMap { get; set; }

    [JsonPropertyName("salt")]
    public string? Salt { get; set; }

    [JsonPropertyName("created_at")]
    public long CreatedAt { get; set; }

    [JsonPropertyName("updated_at")]
    public long? UpdatedAt { get; set; }

    [JsonPropertyName("fragments")]
    public List<FragentInfo>? Fragents { get; set; }
}

public class FragentInfo
{
    [JsonPropertyName("index")]
    public int Index { get; set; }

    [JsonPropertyName("size")]
    public int Size { get; set; }

    [JsonPropertyName("hash")]
    public string Hash { get; set; } = string.Empty;

    [Obsolete("Nonce is stored in the index for backward compatibility but never read during restore.")]
    [JsonPropertyName("nonce")]
    public string Nonce { get; set; } = string.Empty;

    [JsonPropertyName("filename")]
    public string? Filename { get; set; }
}
