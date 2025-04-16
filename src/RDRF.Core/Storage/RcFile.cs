using System.Text.Json;
using System.Text.Json.Serialization;

namespace RDRF.Core.Storage;

public class RcFile
{
    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    [JsonPropertyName("file_fingerprint")]
    public string FileFingerprint { get; set; } = string.Empty;

    [JsonPropertyName("index_block_map")]
    public List<string> IndexBlockMap { get; set; } = new();

    [JsonPropertyName("fragment_block_maps")]
    public List<List<string>> FragentBlockMaps { get; set; } = new();

    [JsonPropertyName("created_at")]
    public long CreatedAt { get; set; }

    public string ToJson()
    {
        return JsonSerializer.Serialize(this, new JsonSerializerOptions
        {
            WriteIndented = false,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        });
    }

    public static RcFile FromJson(string json)
    {
        var rc = JsonSerializer.Deserialize<RcFile>(json);
        if (rc == null)
            throw new InvalidDataException("Failed to parse RC file");
        return rc;
    }

    public static RcFile FromJson(byte[] jsonBytes)
        => FromJson(System.Text.Encoding.UTF8.GetString(jsonBytes));

    public byte[] ToJsonUtf8Bytes()
        => System.Text.Encoding.UTF8.GetBytes(ToJson());
}
