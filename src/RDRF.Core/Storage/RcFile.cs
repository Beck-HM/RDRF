using System.Formats.Cbor;

namespace RDRF.Core.Storage;

public class RcFile
{
    public int Version { get; set; } = 1;
    public string FileFingerprint { get; set; } = string.Empty;
    public List<string> IndexBlockMap { get; set; } = new();
    public List<List<string>> FragentBlockMaps { get; set; } = new();
    public long CreatedAt { get; set; }

    // FSS6.1 repair data (null for non-FSS6.1 backups)
    public int? RepairSeed { get; set; }
    public int? RepairCount { get; set; }
    public int? RepairBlockSize { get; set; }
    public byte[]? RepairData { get; set; }

    public byte[] ToCborBytes()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(null);

        writer.WriteTextString("version"); writer.WriteInt32(Version);
        writer.WriteTextString("file_fingerprint"); writer.WriteTextString(FileFingerprint);
        writer.WriteTextString("index_block_map"); WriteStringList(writer, IndexBlockMap);
        writer.WriteTextString("fragment_block_maps"); WriteNestedStringList(writer, FragentBlockMaps);
        writer.WriteTextString("created_at"); writer.WriteInt64(CreatedAt);

        if (RepairSeed.HasValue) { writer.WriteTextString("repair_seed"); writer.WriteInt32(RepairSeed.Value); }
        if (RepairCount.HasValue) { writer.WriteTextString("repair_count"); writer.WriteInt32(RepairCount.Value); }
        if (RepairBlockSize.HasValue) { writer.WriteTextString("repair_block_size"); writer.WriteInt32(RepairBlockSize.Value); }
        if (RepairData != null) { writer.WriteTextString("repair_data"); writer.WriteByteString(RepairData); }

        writer.WriteEndMap();
        return writer.Encode();
    }

    public static RcFile FromCbor(byte[] bytes)
    {
        var reader = new CborReader(bytes);
        var rc = new RcFile();

        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            switch (reader.ReadTextString())
            {
                case "version":              rc.Version = reader.ReadInt32(); break;
                case "file_fingerprint":     rc.FileFingerprint = reader.ReadTextString(); break;
                case "index_block_map":      rc.IndexBlockMap = ReadStringList(reader); break;
                case "fragment_block_maps":  rc.FragentBlockMaps = ReadNestedStringList(reader); break;
                case "created_at":           rc.CreatedAt = reader.ReadInt64(); break;
                case "repair_seed":          rc.RepairSeed = reader.ReadInt32(); break;
                case "repair_count":         rc.RepairCount = reader.ReadInt32(); break;
                case "repair_block_size":    rc.RepairBlockSize = reader.ReadInt32(); break;
                case "repair_data":          rc.RepairData = reader.ReadByteString(); break;
                default:                     reader.SkipValue(); break;
            }
        }
        reader.ReadEndMap();
        return rc;
    }

    private static void WriteStringList(CborWriter writer, List<string> list)
    {
        writer.WriteStartArray(null);
        foreach (var item in list)
            writer.WriteTextString(item);
        writer.WriteEndArray();
    }

    private static void WriteNestedStringList(CborWriter writer, List<List<string>> list)
    {
        writer.WriteStartArray(null);
        foreach (var inner in list)
            WriteStringList(writer, inner);
        writer.WriteEndArray();
    }

    private static List<string> ReadStringList(CborReader reader)
    {
        var list = new List<string>();
        reader.ReadStartArray();
        while (reader.PeekState() != CborReaderState.EndArray)
            list.Add(reader.ReadTextString());
        reader.ReadEndArray();
        return list;
    }

    private static List<List<string>> ReadNestedStringList(CborReader reader)
    {
        var list = new List<List<string>>();
        reader.ReadStartArray();
        while (reader.PeekState() != CborReaderState.EndArray)
            list.Add(ReadStringList(reader));
        reader.ReadEndArray();
        return list;
    }
}
