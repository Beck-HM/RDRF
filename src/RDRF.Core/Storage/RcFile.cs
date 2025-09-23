using System.Formats.Cbor;
using RDRF.Core.FSS;

namespace RDRF.Core.Dssa;

public class RcFile
{
    public int Version { get; set; } = 1;
    public string FileFingerprint { get; set; } = string.Empty;
    public List<string> IndexBlockMap { get; set; } = new();
    public List<List<string>> FragmentBlockMaps { get; set; } = new();
    public long CreatedAt { get; set; }

    public Fss61RepairData? RepairA { get; set; }
    public Fss61RepairData? RepairB { get; set; }
    public Fss62RepairData? Repair62A { get; set; }
    public Fss62RepairData? Repair62B { get; set; }

    public byte[] ToCborBytes()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(null);

        writer.WriteTextString("version"); writer.WriteInt32(Version);
        writer.WriteTextString("file_fingerprint"); writer.WriteTextString(FileFingerprint);
        writer.WriteTextString("index_block_map"); WriteStringList(writer, IndexBlockMap);
        writer.WriteTextString("fragment_block_maps"); WriteNestedStringList(writer, FragmentBlockMaps);
        writer.WriteTextString("created_at"); writer.WriteInt64(CreatedAt);

        WriteRepair(writer, "repair_a", RepairA);
        WriteRepair(writer, "repair_b", RepairB);
        WriteFss62Repair(writer, "repair_62a", Repair62A);
        WriteFss62Repair(writer, "repair_62b", Repair62B);

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
                case "fragment_block_maps":  rc.FragmentBlockMaps = ReadNestedStringList(reader); break;
                case "created_at":           rc.CreatedAt = reader.ReadInt64(); break;
                case "repair_a":             rc.RepairA = ReadRepair(reader); break;
                case "repair_b":             rc.RepairB = ReadRepair(reader); break;
                case "repair_62a":           rc.Repair62A = ReadFss62Repair(reader); break;
                case "repair_62b":           rc.Repair62B = ReadFss62Repair(reader); break;
                default:                     reader.SkipValue(); break;
            }
        }
        reader.ReadEndMap();
        return rc;
    }

    private static void WriteRepair(CborWriter w, string key, Fss61RepairData? r)
    {
        if (r == null) return;
        w.WriteTextString(key);
        w.WriteStartMap(null);
        w.WriteTextString("seed"); w.WriteInt32(r.Seed);
        w.WriteTextString("block_count"); w.WriteInt32(r.BlockCount);
        w.WriteTextString("block_size"); w.WriteInt32(r.BlockSize);
        w.WriteTextString("data"); w.WriteByteString(r.Data);
        w.WriteEndMap();
    }

    private static Fss61RepairData ReadRepair(CborReader r)
    {
        var rd = new Fss61RepairData();
        r.ReadStartMap();
        while (r.PeekState() != CborReaderState.EndMap)
        {
            switch (r.ReadTextString())
            {
                case "seed":        rd.Seed = r.ReadInt32(); break;
                case "block_count": rd.BlockCount = r.ReadInt32(); break;
                case "block_size":  rd.BlockSize = r.ReadInt32(); break;
                case "data":        rd.Data = r.ReadByteString(); break;
                default:            r.SkipValue(); break;
            }
        }
        r.ReadEndMap();
        return rd;
    }

    private static void WriteFss62Repair(CborWriter w, string key, Fss62RepairData? r)
    {
        if (r == null) return;
        w.WriteTextString(key);
        w.WriteStartMap(null);
        w.WriteTextString("seed"); w.WriteInt32(r.Seed);
        w.WriteTextString("block_count"); w.WriteInt32(r.BlockCount);
        w.WriteTextString("block_size"); w.WriteInt32(r.BlockSize);
        w.WriteTextString("data"); w.WriteByteString(r.Data);
        w.WriteTextString("entropy"); w.WriteByteString(r.EntropySamples);
        w.WriteEndMap();
    }

    private static Fss62RepairData ReadFss62Repair(CborReader r)
    {
        var rd = new Fss62RepairData();
        r.ReadStartMap();
        while (r.PeekState() != CborReaderState.EndMap)
        {
            switch (r.ReadTextString())
            {
                case "seed":        rd.Seed = r.ReadInt32(); break;
                case "block_count": rd.BlockCount = r.ReadInt32(); break;
                case "block_size":  rd.BlockSize = r.ReadInt32(); break;
                case "data":        rd.Data = r.ReadByteString(); break;
                case "entropy":     rd.EntropySamples = r.ReadByteString(); break;
                default:            r.SkipValue(); break;
            }
        }
        r.ReadEndMap();
        return rd;
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
