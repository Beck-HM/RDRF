using System.Formats.Cbor;

namespace RDRF.Core.Versioning;

public class VersionChainConfig
{
    public byte[] Salt { get; set; } = Array.Empty<byte>();
    public int KdfIterations { get; set; }
    public long CreatedAt { get; set; }

    public byte[] Serialize()
    {
        var w = new CborWriter();
        w.WriteStartMap(null);
        w.WriteTextString("salt");
        w.WriteByteString(Salt);
        w.WriteTextString("kdf_iterations");
        w.WriteInt32(KdfIterations);
        w.WriteTextString("created_at");
        w.WriteInt64(CreatedAt);
        w.WriteEndMap();
        return w.Encode();
    }

    public static VersionChainConfig Deserialize(byte[] data)
    {
        var r = new CborReader(data);
        var c = new VersionChainConfig();
        r.ReadStartMap();
        while (r.PeekState() != CborReaderState.EndMap)
        {
            string key = r.ReadTextString();
            switch (key)
            {
                case "salt": c.Salt = r.ReadByteString(); break;
                case "kdf_iterations": c.KdfIterations = r.ReadInt32(); break;
                case "created_at": c.CreatedAt = r.ReadInt64(); break;
                default: r.SkipValue(); break;
            }
        }
        r.ReadEndMap();
        return c;
    }
}
