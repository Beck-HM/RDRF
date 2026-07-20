namespace RDRF.Core.Compression.Ckc;

public static class CkcEngine
{
    private const int XFragHistory = 256;

    public static void CompressInPlace(List<byte[]> fragments, bool crossFragment = false, byte[]? dict = null)
    {
        if (fragments.Count == 0) return;

        byte[] c0 = dict != null
            ? CkcEncoder.CompressSingleWithDict(fragments[0], dict)
            : CkcEncoder.CompressSingle(fragments[0]);
        if (c0.Length >= fragments[0].Length) return;
        fragments[0] = c0;
        if (fragments.Count == 1) return;

        var (tLit, tLen, tDst) = CkcEncoder.BuildTablesFromCompressed(fragments[0]);

        if (!crossFragment)
        {
            var results = new byte[fragments.Count - 1][];
            var flags = new bool[fragments.Count - 1];
            Parallel.For(1, fragments.Count, i =>
            {
                byte[] c = CkcEncoder.CompressWithShared(fragments[i], tLit, tLen, tDst);
                if (c.Length < fragments[i].Length) { results[i - 1] = c; flags[i - 1] = true; }
            });
            for (int i = 1; i < fragments.Count; i++)
                if (flags[i - 1]) fragments[i] = results[i - 1];
            return;
        }

        byte[]? prevTail = null;
        for (int i = 1; i < fragments.Count; i++)
        {
            byte[] data = fragments[i];
            int histLen = prevTail != null ? Math.Min(XFragHistory, prevTail.Length) : 0;

            List<CkcToken> tokens;
            if (histLen > 0)
            {
                var combined = new byte[histLen + data.Length];
                Array.Copy(prevTail, prevTail.Length - histLen, combined, 0, histLen);
                Array.Copy(data, 0, combined, histLen, data.Length);
                tokens = CkcEncoder.Tokenize(combined, offset: histLen);
            }
            else
            {
                tokens = CkcEncoder.Tokenize(data);
            }

            byte[] c = CkcEncoder.TansEncodeShared(data, tokens, tLit, tLen, tDst);

            prevTail = data;

            if (c.Length < data.Length) fragments[i] = c;
        }
    }

    public static void DecompressInPlace(List<byte[]> fragments)
    {
        if (fragments.Count == 0) return;
        if (!IsCkc(fragments[0])) return;

        byte[] f0c = fragments[0];
        fragments[0] = f0c[3] == 0x04
            ? CkcEncoder.DecompressSingleWithDict(f0c)
            : CkcEncoder.DecompressTans(f0c);
        if (fragments.Count == 1) return;

        var (tLit, tLen, tDst) = CkcEncoder.BuildTablesFromCompressed(f0c);

        Parallel.For(1, fragments.Count, i =>
        {
            if (IsCkc(fragments[i]))
                fragments[i] = CkcEncoder.DecompressShared(fragments[i], tLit, tLen, tDst);
        });
    }

    private static bool IsCkc(byte[] data)
        => data.Length >= 4
           && data[0] == 0x43 && data[1] == 0x4B && data[2] == 0x43
           && (data[3] == 0x02 || data[3] == 0x03 || data[3] == 0x04);
}
