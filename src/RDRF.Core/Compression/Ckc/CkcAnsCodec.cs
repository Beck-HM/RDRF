namespace RDRF.Core.Compression.Ckc;

internal sealed class CkcAnsEncoder
{
    public TansTable Literal, Length, DistSlot;
    public int LitBits => Literal.BitsPerQ;
    public int LenBits => Length.BitsPerQ;
    public int DstBits => DistSlot.BitsPerQ;

    public void Train(byte[] data, List<CkcToken> tokens, int L)
    {
        var lit = new int[256]; for (int i = 0; i < 256; i++) lit[i] = 1;
        var len = new int[256]; for (int i = 0; i < 256; i++) len[i] = 1;
        var dst = new int[CkcDistSlot.SlotCount]; for (int i = 0; i < dst.Length; i++) dst[i] = 1;

        int n = Math.Min(data.Length, 65536);
        for (int i = 0; i < n; i++) lit[data[i]]++;
        foreach (var t in tokens)
        {
            if (t.IsMatch)
            {
                int li = t.Length - CkcConstants.MinMatchLen;
                if (li >= 0 && li < 256) len[li]++;
                var (slot, _) = CkcDistSlot.Map(t.Distance);
                if (slot >= 0 && slot < dst.Length) dst[slot]++;
            }
        }

        Literal = TansTable.Build(lit, L);
        Length = TansTable.Build(len, L);
        DistSlot = TansTable.Build(dst, L);
    }

    // Encode one literal: returns (nextState, q-1 value)
    public (int next, int q1) EncodeLit(int state, byte sym)
    {
        var (n, q) = Literal.Encode(state, sym);
        return (n, q - 1);
    }
    public (int next, int q1) EncodeLen(int state, int sym)
    {
        var (n, q) = Length.Encode(state, sym);
        return (n, q - 1);
    }
    public (int next, int q1) EncodeDst(int state, int sym)
    {
        var (n, q) = DistSlot.Encode(state, sym);
        return (n, q - 1);
    }
}

internal sealed class CkcAnsDecoder
{
    public TansTable Literal, Length, DistSlot;

    public void Init(TansTable lit, TansTable len, TansTable dst)
    {
        Literal = lit; Length = len; DistSlot = dst;
    }

    public byte DecodeLit(int state, int q, out int next)
    {
        Literal.TryDecode(state, q + 1, out next);
        return (byte)Literal.GetSymbol(state);
    }
    public int DecodeLen(int state, int q, out int next)
    {
        Length.TryDecode(state, q + 1, out next);
        return Length.GetSymbol(state) + CkcConstants.MinMatchLen;
    }
    public int DecodeDst(int state, int q, out int next)
    {
        DistSlot.TryDecode(state, q + 1, out next);
        return DistSlot.GetSymbol(state);
    }
}
