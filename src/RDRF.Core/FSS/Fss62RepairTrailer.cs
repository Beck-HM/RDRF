using RDRF.Core.Abstractions;
namespace RDRF.Core.FSS;

/// <summary>
/// Binary trailer build/parse for FSS6.2 Duip repair data appended to fragments.
/// </summary>

public static class Fss62RepairTrailer
{
    public static byte[] Build(byte[] fragmentData, string aFingerprint, string cFingerprint,
        Fss62RepairData repairA, Fss62RepairData repairC)
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms, System.Text.Encoding.UTF8, true);

        w.Write(HexToBytes(aFingerprint));
        w.Write(HexToBytes(cFingerprint));

        WriteRepair(w, repairA);
        WriteRepair(w, repairC);

        w.Write(fragmentData.Length);
        int trailerSize = (int)ms.Length + 4;
        w.Write(trailerSize);

        byte[] trailer = ms.ToArray();
        var result = new byte[fragmentData.Length + trailer.Length];
        Buffer.BlockCopy(fragmentData, 0, result, 0, fragmentData.Length);
        Buffer.BlockCopy(trailer, 0, result, fragmentData.Length, trailer.Length);
        return result;
    }

    public static (byte[] data, string aFingerprint, string cFingerprint,
        Fss62RepairData? repairA, Fss62RepairData? repairC) Parse(byte[] fileData)
    {
        if (fileData.Length < 12)
            return (fileData, "", "", null, null);

        int trailerSize = BitConverter.ToInt32(fileData, fileData.Length - 4);
        if (trailerSize <= 0 || trailerSize > fileData.Length)
            return (fileData, "", "", null, null);

        int trailerStart = fileData.Length - trailerSize;
        if (trailerStart < 0)
            return (fileData, "", "", null, null);

        if (trailerSize < 104)
            return (fileData, "", "", null, null);

        using var fragStream = new MemoryStream(fileData, trailerStart, trailerSize);
        var r = new BinaryReader(fragStream);

        string aFp = BytesToHex(r.ReadBytes(32));
        string cFp = BytesToHex(r.ReadBytes(32));

        var repairA = ReadRepair(r);
        var repairC = ReadRepair(r);

        int rawSize = r.ReadInt32();
        if (rawSize <= 0 || rawSize > fileData.Length)
            return (fileData, aFp, cFp, repairA, repairC);

        byte[] rawData = new byte[rawSize];
        Buffer.BlockCopy(fileData, 0, rawData, 0, rawSize);
        return (rawData, aFp, cFp, repairA, repairC);
    }

    private static void WriteRepair(BinaryWriter w, Fss62RepairData r)
    {
        w.Write(r.Seed);
        w.Write(r.BlockCount);
        w.Write(r.BlockSize);
        w.Write(r.EntropySamples.Length);
        w.Write(r.EntropySamples);
        w.Write(r.Data.Length);
        w.Write(r.Data);
    }

    private static Fss62RepairData? ReadRepair(BinaryReader r)
    {
        if (r.BaseStream.Length - r.BaseStream.Position < 16)
            return null;
        int seed = r.ReadInt32();
        int blockCount = r.ReadInt32();
        int blockSize = r.ReadInt32();
        int entropyLen = r.ReadInt32();
        if (entropyLen < 0 || entropyLen > 10_000)
            return null;
        if (r.BaseStream.Length - r.BaseStream.Position < entropyLen)
            return null;
        byte[] entropy = r.ReadBytes(entropyLen);
        int dataLen = r.ReadInt32();
        if (dataLen < 0 || dataLen > 100_000_000)
            return null;
        if (r.BaseStream.Length - r.BaseStream.Position < dataLen)
            return null;
        byte[] data = r.ReadBytes(dataLen);
        if (data.Length != dataLen)
            return null;
        return new Fss62RepairData
        {
            Seed = seed,
            BlockCount = blockCount,
            BlockSize = blockSize,
            Data = data,
            EntropySamples = entropy,
        };
    }

    private static byte[] HexToBytes(string hex)
    {
        if (hex.Length % 2 != 0) hex = hex.PadRight(hex.Length + 1, '0');
        byte[] b = new byte[hex.Length / 2];
        for (int i = 0; i < b.Length; i++)
            b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return b;
    }

    private static string BytesToHex(byte[] bytes)
        => Hex.EncodeLower(bytes);
}



