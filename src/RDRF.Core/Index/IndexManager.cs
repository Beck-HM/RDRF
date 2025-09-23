using System.Formats.Cbor;
using System.Text.Json;
using RDRF.Core.Encryption;
using RDRF.Core.FSS;
using RDRF.Core.Versioning;

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
        List<int>? originalFragmentSizes = null,
        int? originalFragmentCount = null,
        Dictionary<string, object>? fssParams = null)
    {
        int fragmentCount = fragmentHashes.Count;
        var index = new RdrfIndex
        {
            FileFingerprint = fileFingerprint,
            OriginalName = originalFilename,
            FileSize = originalSize,
            FragmentCount = fragmentCount,
            FragmentHashes = fragmentHashes,
            OriginalHash = originalHash,
            FssStrategy = fssStrategy,
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            FssParams = fssParams,
            OriginalFragmentSizes = originalFragmentSizes ?? new List<int>(),
            Salt = string.Empty,
        };

        var fragments = new List<FragmentInfo>(fragmentCount);
        for (int i = 0; i < fragmentCount; i++)
        {
            fragments.Add(new FragmentInfo
            {
                Index = i,
                Hash = fragmentHashes[i],
                Nonce = fragmentNonces[i],
            });
        }
        index.Fragments = fragments;

        if (originalFragmentCount.HasValue)
            index.OriginalFragmentCount = originalFragmentCount.Value;

        return index;
    }

    public static byte[] SerializeIndex(RdrfIndex index)
    {
        var writer = new CborWriter();
        writer.WriteStartMap(null);

        WriteField(writer, "file_fingerprint", index.FileFingerprint);
        WriteField(writer, "custom_name", index.CustomName);
        WriteField(writer, "original_name", index.OriginalName);
        WriteField(writer, "file_size", index.FileSize);
        WriteField(writer, "fragment_count", index.FragmentCount);
        WriteField(writer, "original_fragment_count", index.OriginalFragmentCount, 0);
        WriteField(writer, "original_fragment_sizes", index.OriginalFragmentSizes);
        WriteField(writer, "fragment_hashes", index.FragmentHashes);
        WriteField(writer, "original_hash", index.OriginalHash);
        WriteField(writer, "fss_strategy", index.FssStrategy);
        WriteField(writer, "compression", index.Compression);
        WriteFssParams(writer, index.FssParams);
        WriteField(writer, "fss6_fragment_block_maps", index.Fss6FragmentBlockMaps);
        WriteField(writer, "fss6_rc_block_map", index.Fss6RcBlockMap);
        WriteField(writer, "raw_fragment_hashes", index.RawFragmentHashes);
        WriteField(writer, "salt", index.Salt);
        WriteField(writer, "created_at", index.CreatedAt);
        WriteField(writer, "updated_at", index.UpdatedAt);
        WriteField(writer, "version_number", index.VersionNumber);
        WriteVersions(writer, index.Versions);
        WriteFragments(writer, index.Fragments);
        WriteRepairData(writer, "fss61_repair_b", index.Fss61RepairB);
        WriteRepairData(writer, "fss61_repair_c", index.Fss61RepairC);
        WriteFss62RepairData(writer, "fss62_repair_b", index.Fss62RepairB);
        WriteFss62RepairData(writer, "fss62_repair_c", index.Fss62RepairC);

        writer.WriteEndMap();
        return writer.Encode();
    }

    public static RdrfIndex DeserializeIndex(byte[] cborBytes)
    {
        var reader = new CborReader(cborBytes);
        var index = new RdrfIndex();

        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            switch (reader.ReadTextString())
            {
                case "file_fingerprint":            index.FileFingerprint = reader.ReadTextString(); break;
                case "custom_name":                 index.CustomName = reader.ReadTextString(); break;
                case "original_name":               index.OriginalName = reader.ReadTextString(); break;
                case "file_size":                   index.FileSize = reader.ReadInt64(); break;
                case "fragment_count":              index.FragmentCount = reader.ReadInt32(); break;
                case "original_fragment_count":     index.OriginalFragmentCount = reader.ReadInt32(); break;
                case "original_fragment_sizes":     index.OriginalFragmentSizes = ReadInt32List(reader); break;
                case "fragment_hashes":             index.FragmentHashes = ReadStringList(reader); break;
                case "original_hash":               index.OriginalHash = reader.ReadTextString(); break;
                case "fss_strategy":                index.FssStrategy = reader.ReadTextString(); break;
                case "compression":                  index.Compression = reader.ReadTextString(); break;
                case "fss_params":                  index.FssParams = ReadFssParams(reader); break;
                case "fss6_fragment_block_maps":    index.Fss6FragmentBlockMaps = ReadNestedStringList(reader); break;
                case "fss6_rc_block_map":           index.Fss6RcBlockMap = ReadStringList(reader); break;
                case "raw_fragment_hashes":          index.RawFragmentHashes = ReadByteArrayList(reader); break;
                case "salt":                        index.Salt = reader.ReadTextString(); break;
                case "created_at":                  index.CreatedAt = reader.ReadInt64(); break;
                case "updated_at":                  index.UpdatedAt = reader.ReadInt64(); break;
                case "version_number":               index.VersionNumber = reader.ReadInt32(); break;
                case "versions":                     index.Versions = ReadVersions(reader); break;
                case "fragments":                   index.Fragments = ReadFragments(reader); break;
                case "fss61_repair_b":              index.Fss61RepairB = ReadRepairData(reader); break;
                case "fss61_repair_c":              index.Fss61RepairC = ReadRepairData(reader); break;
                case "fss62_repair_b":              index.Fss62RepairB = ReadFss62RepairData(reader); break;
                case "fss62_repair_c":              index.Fss62RepairC = ReadFss62RepairData(reader); break;
                default:                            reader.SkipValue(); break;
            }
        }
        reader.ReadEndMap();
        return index;
    }

    public static byte[] EncryptIndexWithKey(RdrfIndex index, byte[] aesKey)
    {
        byte[] cbor = SerializeIndex(index);
        return EncryptionLayer.EncryptIndexWithKey(cbor, aesKey);
    }

    public static byte[] EncryptIndex(RdrfIndex index, byte[] rcCode)
        => EncryptIndexWithKey(index, EncryptionLayer.DeriveKey(rcCode));

    public static RdrfIndex DecryptIndexWithKey(byte[] encryptedIndex, byte[] aesKey)
    {
        byte[] cbor = EncryptionLayer.DecryptIndexWithKey(encryptedIndex, aesKey);
        return DeserializeIndex(cbor);
    }

    public static RdrfIndex DecryptIndex(byte[] encryptedIndex, byte[] rcCode)
        => DecryptIndexWithKey(encryptedIndex, EncryptionLayer.DeriveKey(rcCode));

    public static FragmentInfo? GetFragmentInfo(RdrfIndex index, int fragmentIndex)
        => index.Fragments?.FirstOrDefault(f => f.Index == fragmentIndex);

    // ── CBOR serialization helpers ──

    private static void WriteField(CborWriter w, string key, string? value)
    {
        if (value == null) return;
        w.WriteTextString(key);
        w.WriteTextString(value);
    }

    private static void WriteField(CborWriter w, string key, int value)
    {
        w.WriteTextString(key);
        w.WriteInt32(value);
    }

    private static void WriteField(CborWriter w, string key, int value, int defaultValue)
    {
        if (value == defaultValue) return;
        w.WriteTextString(key);
        w.WriteInt32(value);
    }

    private static void WriteField(CborWriter w, string key, long value)
    {
        w.WriteTextString(key);
        w.WriteInt64(value);
    }

    private static void WriteField(CborWriter w, string key, long? value)
    {
        if (value == null) return;
        w.WriteTextString(key);
        w.WriteInt64(value.Value);
    }

    private static void WriteField(CborWriter w, string key, List<string>? values)
    {
        if (values == null) return;
        w.WriteTextString(key);
        WriteStringList(w, values);
    }

    private static void WriteField(CborWriter w, string key, List<int> values)
    {
        w.WriteTextString(key);
        WriteInt32List(w, values);
    }

    private static void WriteField(CborWriter w, string key, List<List<string>>? values)
    {
        if (values == null) return;
        w.WriteTextString(key);
        WriteNestedStringList(w, values);
    }

    private static void WriteField(CborWriter w, string key, List<List<byte[]>>? values)
    {
        if (values == null) return;
        w.WriteTextString(key);
        WriteNestedByteArrayList(w, values);
    }

    private static void WriteField(CborWriter w, string key, List<byte[]>? values)
    {
        if (values == null) return;
        w.WriteTextString(key);
        WriteByteArrayList(w, values);
    }

    private static void WriteFssParams(CborWriter w, Dictionary<string, object>? fssParams)
    {
        if (fssParams == null || fssParams.Count == 0) return;
        w.WriteTextString("fss_params");
        w.WriteStartMap(null);
        foreach (var kvp in fssParams)
        {
            w.WriteTextString(kvp.Key);
            w.WriteTextString(kvp.Value switch
            {
                JsonElement je => je.GetRawText(),
                _ => kvp.Value?.ToString() ?? ""
            });
        }
        w.WriteEndMap();
    }

    private static void WriteFragments(CborWriter w, List<FragmentInfo>? Fragments)
    {
        if (Fragments == null) return;
        w.WriteTextString("fragments");
        w.WriteStartArray(null);
        foreach (var f in Fragments)
        {
            w.WriteStartMap(null);
            w.WriteTextString("index");    w.WriteInt32(f.Index);
            w.WriteTextString("size");     w.WriteInt32(f.Size);
            w.WriteTextString("hash");     w.WriteTextString(f.Hash);
            w.WriteTextString("nonce");    w.WriteTextString(f.Nonce);
            if (f.Filename != null) { w.WriteTextString("filename"); w.WriteTextString(f.Filename); }
            if (f.SourceVersion != null) { w.WriteTextString("source_version"); w.WriteTextString(f.SourceVersion); }
            w.WriteEndMap();
        }
        w.WriteEndArray();
    }

    private static void WriteStringList(CborWriter w, List<string> list)
    {
        w.WriteStartArray(null);
        foreach (var item in list)
            w.WriteTextString(item);
        w.WriteEndArray();
    }

    private static void WriteInt32List(CborWriter w, List<int> list)
    {
        w.WriteStartArray(null);
        foreach (var item in list)
            w.WriteInt32(item);
        w.WriteEndArray();
    }

    private static void WriteNestedStringList(CborWriter w, List<List<string>> list)
    {
        w.WriteStartArray(null);
        foreach (var inner in list)
            WriteStringList(w, inner);
        w.WriteEndArray();
    }

    private static void WriteByteArrayList(CborWriter w, List<byte[]> list)
    {
        w.WriteStartArray(null);
        foreach (var item in list)
            w.WriteByteString(item);
        w.WriteEndArray();
    }

    private static void WriteNestedByteArrayList(CborWriter w, List<List<byte[]>> list)
    {
        w.WriteStartArray(null);
        foreach (var inner in list)
            WriteByteArrayList(w, inner);
        w.WriteEndArray();
    }

    private static List<string> ReadStringList(CborReader r)
    {
        var list = new List<string>();
        r.ReadStartArray();
        while (r.PeekState() != CborReaderState.EndArray)
            list.Add(r.ReadTextString());
        r.ReadEndArray();
        return list;
    }

    private static List<byte[]> ReadByteArrayList(CborReader r)
    {
        var list = new List<byte[]>();
        r.ReadStartArray();
        while (r.PeekState() != CborReaderState.EndArray)
            list.Add(r.ReadByteString());
        r.ReadEndArray();
        return list;
    }

    private static List<List<byte[]>> ReadNestedByteArrayList(CborReader r)
    {
        var list = new List<List<byte[]>>();
        r.ReadStartArray();
        while (r.PeekState() != CborReaderState.EndArray)
            list.Add(ReadByteArrayList(r));
        r.ReadEndArray();
        return list;
    }

    private static List<int> ReadInt32List(CborReader r)
    {
        var list = new List<int>();
        r.ReadStartArray();
        while (r.PeekState() != CborReaderState.EndArray)
            list.Add(r.ReadInt32());
        r.ReadEndArray();
        return list;
    }

    private static List<List<string>> ReadNestedStringList(CborReader r)
    {
        var list = new List<List<string>>();
        r.ReadStartArray();
        while (r.PeekState() != CborReaderState.EndArray)
            list.Add(ReadStringList(r));
        r.ReadEndArray();
        return list;
    }

    private static Dictionary<string, object>? ReadFssParams(CborReader r)
    {
        r.ReadStartMap();
        var dict = new Dictionary<string, object>();
        while (r.PeekState() != CborReaderState.EndMap)
        {
            var key = r.ReadTextString();
            var value = r.ReadTextString();
            try { dict[key] = JsonDocument.Parse(value).RootElement.Clone(); }
            catch { dict[key] = value; }
        }
        r.ReadEndMap();
        return dict;
    }

    private static List<FragmentInfo> ReadFragments(CborReader r)
    {
        var list = new List<FragmentInfo>();
        r.ReadStartArray();

        int index = 0;
        while (r.PeekState() != CborReaderState.EndArray)
        {
            var f = new FragmentInfo();
            r.ReadStartMap();
            while (r.PeekState() != CborReaderState.EndMap)
            {
                switch (r.ReadTextString())
                {
                    case "index":    f.Index = r.ReadInt32(); break;
                    case "size":     f.Size = r.ReadInt32(); break;
                    case "hash":     f.Hash = r.ReadTextString(); break;
                    case "nonce":    f.Nonce = r.ReadTextString(); break;
                    case "filename": f.Filename = r.ReadTextString(); break;
                    case "source_version": f.SourceVersion = r.ReadTextString(); break;
                    default:         r.SkipValue(); break;
                }
            }
            r.ReadEndMap();
            f.Index = index++; // override with sequential position
            list.Add(f);
        }
        r.ReadEndArray();
        return list;
    }

    private static void WriteVersions(CborWriter w, List<VersionRecord>? versions)
    {
        if (versions == null || versions.Count == 0) return;
        w.WriteTextString("versions");
        w.WriteStartArray(null);
        foreach (var v in versions)
        {
            w.WriteStartMap(null);
            w.WriteTextString("version");
            w.WriteInt32(v.Version);
            w.WriteTextString("user_message");
            w.WriteTextString(v.UserMessage);
            w.WriteTextString("system_diff");
            w.WriteTextString(v.SystemDiff);
            w.WriteTextString("created_at");
            w.WriteInt64(v.CreatedAt);
            w.WriteTextString("file_fingerprint");
            w.WriteTextString(v.FileFingerprint);
            if (v.Salt is { Length: > 0 })
            {
                w.WriteTextString("salt");
                w.WriteByteString(v.Salt);
            }
            if (v.Files is { Count: > 0 })
            {
                w.WriteTextString("files");
                w.WriteStartArray(null);
                foreach (var f in v.Files)
                {
                    w.WriteStartMap(null);
                    w.WriteTextString("path"); w.WriteTextString(f.Path);
                    w.WriteTextString("change_type"); w.WriteTextString(f.ChangeType);
                    w.WriteTextString("diff"); w.WriteTextString(f.Diff);
                    w.WriteEndMap();
                }
                w.WriteEndArray();
            }
            w.WriteEndMap();
        }
        w.WriteEndArray();
    }

    private static List<VersionRecord> ReadVersions(CborReader r)
    {
        var list = new List<VersionRecord>();
        r.ReadStartArray();
        while (r.PeekState() != CborReaderState.EndArray)
        {
            var v = new VersionRecord();
            r.ReadStartMap();
            while (r.PeekState() != CborReaderState.EndMap)
            {
                switch (r.ReadTextString())
                {
                    case "version":          v.Version = r.ReadInt32(); break;
                    case "user_message":     v.UserMessage = r.ReadTextString(); break;
                    case "system_diff":      v.SystemDiff = r.ReadTextString(); break;
                    case "created_at":       v.CreatedAt = r.ReadInt64(); break;
                    case "file_fingerprint": v.FileFingerprint = r.ReadTextString(); break;
                    case "salt":             v.Salt = r.ReadByteString(); break;
                    case "files":
                        v.Files = new List<FileEntry>();
                        r.ReadStartArray();
                        while (r.PeekState() != CborReaderState.EndArray)
                        {
                            var fe = new FileEntry();
                            r.ReadStartMap();
                            while (r.PeekState() != CborReaderState.EndMap)
                            {
                                switch (r.ReadTextString())
                                {
                                    case "path":        fe.Path = r.ReadTextString(); break;
                                    case "change_type": fe.ChangeType = r.ReadTextString(); break;
                                    case "diff":        fe.Diff = r.ReadTextString(); break;
                                    default:            r.SkipValue(); break;
                                }
                            }
                            r.ReadEndMap();
                            v.Files.Add(fe);
                        }
                        r.ReadEndArray();
                        break;
                    default:                 r.SkipValue(); break;
                }
            }
            r.ReadEndMap();
            list.Add(v);
        }
        r.ReadEndArray();
        return list;
    }

    private static void WriteField(CborWriter w, string key, int? value)
    {
        if (value == null) return;
        w.WriteTextString(key);
        w.WriteInt32(value.Value);
    }

    private static void WriteRepairData(CborWriter w, string key, FSS.Fss61RepairData? r)
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

    private static void WriteFss62RepairData(CborWriter w, string key, FSS.Fss62RepairData? r)
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

    private static FSS.Fss62RepairData? ReadFss62RepairData(CborReader r)
    {
        var rd = new FSS.Fss62RepairData();
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

    private static FSS.Fss61RepairData? ReadRepairData(CborReader r)
    {
        var rd = new FSS.Fss61RepairData();
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
}

public class RdrfIndex
{
    public string FileFingerprint { get; set; } = string.Empty;
    public string? CustomName { get; set; }
    public string OriginalName { get; set; } = string.Empty;
    public long FileSize { get; set; }
    public int FragmentCount { get; set; }
    public int OriginalFragmentCount { get; set; }
    public List<int> OriginalFragmentSizes { get; set; } = new();
    public List<string> FragmentHashes { get; set; } = new();
    public string OriginalHash { get; set; } = string.Empty;
    public string FssStrategy { get; set; } = "FSS1";
    public string? Compression { get; set; }
    public Dictionary<string, object>? FssParams { get; set; }
    public List<List<string>>? Fss6FragmentBlockMaps { get; set; }
    public List<string>? Fss6RcBlockMap { get; set; }
    public List<byte[]>? RawFragmentHashes { get; set; }
    public string? Salt { get; set; }
    public long CreatedAt { get; set; }
    public long? UpdatedAt { get; set; }
    public int? VersionNumber { get; set; }
    public List<Versioning.VersionRecord>? Versions { get; set; }
    public List<FragmentInfo>? Fragments { get; set; }
    public FSS.Fss61RepairData? Fss61RepairB { get; set; }
    public FSS.Fss61RepairData? Fss61RepairC { get; set; }
    public FSS.Fss62RepairData? Fss62RepairB { get; set; }
    public FSS.Fss62RepairData? Fss62RepairC { get; set; }
}

public class FragmentInfo
{
    public int Index { get; set; }
    public int Size { get; set; }
    public string Hash { get; set; } = string.Empty;

    [Obsolete("Nonce is stored in the index for backward compatibility but never read during restore.")]
    public string Nonce { get; set; } = string.Empty;
    public string? Filename { get; set; }
    public string? SourceVersion { get; set; }
}
