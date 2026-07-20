namespace RDRF.Core.Compression.Ckc;

public class CkcAlgorithm : ICompressionAlgorithm
{
    private TansTable? _cachedLit, _cachedLen, _cachedDst;

    public string Name => Constants.CompressionCkc;

    public byte[] Compress(byte[] data, string? options = null)
    {
        bool useDelta = options != null && options.Contains("delta", StringComparison.OrdinalIgnoreCase);
        bool fast = options != null && options.Contains("fast", StringComparison.OrdinalIgnoreCase);
        var work = useDelta ? DeltaEncode(data) : data;
        // Do not forward "delta"/"bwt" — delta already applied; bwt is CompressSingle-only.
        byte[] ckc = CkcEncoder.CompressSingle(work, options: fast ? "fast" : null);
        return useDelta
            ? PrefixTransformByte(0x01, ckc)
            : ckc;
    }

    public byte[] Decompress(byte[] data)
    {
        byte tf = GetTransformFlag(data);
        byte[] inner;
        if (tf != 0)
        {
            inner = new byte[data.Length - 1];
            Array.Copy(data, 1, inner, 0, inner.Length);
        }
        else inner = data;

        int ver = inner.Length >= 4 ? inner[3] : 0;
        byte[] result;

        if (ver == 0x03 && _cachedLit != null)
            result = CkcEncoder.DecompressShared(inner, _cachedLit, _cachedLen!, _cachedDst!);
        else if (ver == 0x03)
            throw new RdrfException(ErrorCode.FileFormatInvalid, "CKC shared fragment without prior 0x02 fragment");
        else if (ver == 0x04)
        {
            result = CkcEncoder.DecompressSingleWithDict(inner);
            (_cachedLit, _cachedLen, _cachedDst) = CkcEncoder.BuildTablesFromCompressed(inner);
        }
        else
        {
            result = CkcEncoder.DecompressTans(inner);
            (_cachedLit, _cachedLen, _cachedDst) = CkcEncoder.BuildTablesFromCompressed(inner);
        }

        return tf == 0x01 ? DeltaDecode(result) : result;
    }

    public bool CanHandle(byte[] data)
    {
        // Support both raw CKC and prefixed transform byte + CKC
        if (data.Length >= 8 && data[0] == 0x43 && data[1] == 0x4B && data[2] == 0x43
            && (data[3] == 0x02 || data[3] == 0x03 || data[3] == 0x04))
            return true;
        if (data.Length >= 9 && data[1] == 0x43 && data[2] == 0x4B && data[3] == 0x43
            && (data[4] == 0x02 || data[4] == 0x03 || data[4] == 0x04))
            return true;
        return false;
    }

    private static byte GetTransformFlag(byte[] data)
    {
        if (data.Length < 5) return 0;
        // Check if first byte is a transform flag (0x00 or 0x01) followed by "CKC"
        if (data[0] <= 0x01 && data[1] == 0x43 && data[2] == 0x4B && data[3] == 0x43)
            return data[0];
        return 0;
    }

    private static byte[] PrefixTransformByte(byte tf, byte[] ckc)
    {
        var r = new byte[ckc.Length + 1];
        r[0] = tf;
        Array.Copy(ckc, 0, r, 1, ckc.Length);
        return r;
    }

    internal static byte[] DeltaEncode(byte[] data)
    {
        var d = new byte[data.Length];
        if (data.Length > 0) d[0] = data[0];
        for (int i = 1; i < data.Length; i++)
            d[i] = (byte)(data[i] ^ data[i - 1]);
        return d;
    }

    internal static byte[] DeltaDecode(byte[] encoded)
    {
        var d = new byte[encoded.Length];
        if (encoded.Length > 0) d[0] = encoded[0];
        byte acc = d[0];
        for (int i = 1; i < encoded.Length; i++)
        {
            d[i] = (byte)(encoded[i] ^ acc);
            acc = d[i];
        }
        return d;
    }
}
