using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace RDRF.Core.Compression.Ckc;

internal static class CkcEncoder
{
    private const int L_LIT  = 8192;
    private const int L      = 4096;
    private const int L_DST  = 1024;
    private const int SB_LIT = 14;
    private const int SB_DST = 11;
    private const int SB_LEN = 13;
    private const int LitContexts = 8;
    private const int LitSymbols = LitContexts * 256;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int LitCtx(int state)
    {
        return state >= 7 ? 7 : state;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int LitCtx(int state, byte _a, byte _b = 0, int _c = 0) => LitCtx(state); // compat overload

    [ThreadStatic] private static byte[]? _tsBits;
    [ThreadStatic] private static (int state, int repIndex, bool isRep, bool isShortRep, int litExtra)[]? _tsStInfo;

    private static int ReadBits(ref int pos, ref ulong acc, ref int avail, int n, byte[] data)
    {
        while (avail < n)
        {
            if (pos >= data.Length) break;
            acc |= (ulong)data[pos++] << avail; avail += 8;
        }
        int v = (int)(acc & ((1uL << n) - 1));
        acc >>= n; avail -= n;
        return v;
    }

    internal static byte[] TansEncodeRaw(byte[] data, int ns = 256)
    {
        var litF = new int[ns];
        for (int i = 0; i < ns; i++) litF[i] = 1;
        for (int i = 0; i < data.Length; i++) litF[data[i]]++;

        var tLit = TansTable.Build(litF, L_LIT);
        // Pack bits into a growable byte buffer (MSB-first per old Reverse() bit list).
        // Old path: List<byte> of 0/1 then Reverse then pack LSB-first into bytes.
        // Equivalence: write bits into a stack, reverse by packing from end.
        int estBits = data.Length * 16 + 64;
        byte[] bitBytes = new byte[(estBits + 7) / 8 + 8];
        int bitCount = 0;
        void Wb(int b)
        {
            int bi = bitCount++;
            int need = (bi >> 3) + 1;
            if (need > bitBytes.Length)
            {
                var nb = new byte[bitBytes.Length * 2];
                Buffer.BlockCopy(bitBytes, 0, nb, 0, bitBytes.Length);
                bitBytes = nb;
            }
            if ((b & 1) != 0)
                bitBytes[bi >> 3] |= (byte)(1 << (bi & 7));
        }
        void Wv(int val, int w) { for (int j = w - 1; j >= 0; j--) Wb((val >> j) & 1); }
        int s = L_LIT;

        for (int i = data.Length - 1; i >= 0; i--)
        {
            int sym = data[i];
            var (nl, ql) = tLit.Encode(s, sym);
            Wv(ql - 1, tLit.SymBitsQ(sym)); s = nl;
        }

        Wv(data.Length, 20);
        Wv(s, SB_LIT);

        // Reverse bit order (same as bits.Reverse()) then pack 8 LSBs at a time.
        var ms = new MemoryStream();
        ms.WriteByte(0x43); ms.WriteByte(0x4B); ms.WriteByte(0x43); ms.WriteByte(0x06);
        Span<byte> hdr = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(hdr, data.Length); ms.Write(hdr);
        WriteFreqRaw(ms, litF);
        int acc = 0, nb = 0;
        for (int bi = bitCount - 1; bi >= 0; bi--)
        {
            int bit = (bitBytes[bi >> 3] >> (bi & 7)) & 1;
            acc |= bit << nb;
            if (++nb >= 8) { ms.WriteByte((byte)acc); acc = 0; nb = 0; }
        }
        if (nb > 0) ms.WriteByte((byte)acc);
        return ms.ToArray();
    }

    private static byte[] WrapWithBwtMagic(byte[] ckc02, int primary)
    {
        var ms = new MemoryStream();
        ms.WriteByte(0x43); ms.WriteByte(0x4B); ms.WriteByte(0x43); ms.WriteByte(0x05);
        Span<byte> hdr = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(hdr, primary); ms.Write(hdr);
        ms.Write(ckc02, 4, ckc02.Length - 4);
        return ms.ToArray();
    }

    public static byte[] CompressSingle(byte[] data, string? options = null)
    {
        bool delta = options != null && options.Contains("delta", StringComparison.OrdinalIgnoreCase);
        if (delta) { data = CkcAlgorithm.DeltaEncode(data); }
        
        bool bwt = options != null && options.Contains("bwt", StringComparison.OrdinalIgnoreCase);
        if (bwt) return CompressBwt(data);

        bool fast = options != null && options.Contains("fast", StringComparison.OrdinalIgnoreCase);
        var tokens = Tokenize(data, fast: fast);
        var compressed = TansEncode(data, tokens);
        return compressed;
    }

    private static byte[] CompressBwt(byte[] data)
    {
        var (bwt, primary) = CkcBwt.Forward(data);
        var mtf = CkcBwt.ForwardMTF(bwt);
        var compressed = TansEncodeRaw(mtf, 256);
        // Wrap with 0x05: magic + primary + raw-compressed
        var ms = new MemoryStream();
        ms.WriteByte(0x43); ms.WriteByte(0x4B); ms.WriteByte(0x43); ms.WriteByte(0x05);
        Span<byte> hdr = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(hdr, primary); ms.Write(hdr);
        BinaryPrimitives.WriteInt32LittleEndian(hdr, data.Length); ms.Write(hdr);
        ms.Write(compressed, 4, compressed.Length - 4); // skip the 0x06 magic, keep rest
        return ms.ToArray();
    }

    public static byte[] DecompressSingle(byte[] data, string? options = null)
    {
        bool delta = options != null && options.Contains("delta");
        bool bwt = data.Length >= 4 && data[3] == 0x05;
        int ver = bwt ? 0x05 : (data.Length >= 4 ? data[3] : 0);

        byte[] result;
        if (ver == 0x05) result = DecompressBwt(data);
        else if (ver == 0x04) result = DecompressSingleWithDict(data);
        else if (ver == 0x02) result = DecompressTans(data);
        else throw new InvalidDataException("Unknown CKC version or not CKC data");

        return delta ? CkcAlgorithm.DeltaDecode(result) : result;
    }

    private static byte[] DecompressBwt(byte[] data)
    {
        if (data.Length < 16) throw new InvalidDataException("CKC BWT stream too short");
        int primary = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(4));
        int origSize = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(8));
        // Build 0x06 compatible stream from bytes 12+
        var ckc06 = new byte[4 + data.Length - 12];
        ckc06[0] = 0x43; ckc06[1] = 0x4B; ckc06[2] = 0x43; ckc06[3] = 0x06;
        Array.Copy(data, 12, ckc06, 4, data.Length - 12);
        var mtf = DecompressRaw(ckc06);
        var bwt = CkcBwt.InverseMTF(mtf);
        return CkcBwt.Inverse(bwt, primary);
    }

    internal static byte[] DecompressRaw(byte[] data)
    {
        if (data.Length < 8 || data[3] != 0x06) throw new InvalidDataException("Not a raw CKC stream");
        int originalSize = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(4));
        int rawp = 8;
        var litF = ReadFreqRaw(data, ref rawp);
        var tLit = TansTable.Build(litF, L_LIT);
        int pos = rawp;
        ulong acc = 0; int bitsAvail = 0;
        int s = ReadBits(ref pos, ref acc, ref bitsAvail, SB_LIT, data);
        int tc = ReadBits(ref pos, ref acc, ref bitsAvail, 20, data);
        var result = new byte[originalSize];
        for (int op = 0; op < tc && op < originalSize; op++)
        {
            int sym = tLit.GetSymbol(s);
            int q = ReadBits(ref pos, ref acc, ref bitsAvail, tLit.SymBitsQ(sym), data) + 1;
            tLit.TryDecode(s, q, out s);
            result[op] = (byte)sym;
        }
        return result;
    }

    public static byte[] CompressSingleWithDict(byte[] data, byte[] dict, string? options = null)
    {
        int dLen = dict.Length;
        var combined = new byte[dLen + data.Length];
        Array.Copy(dict, 0, combined, 0, dLen);
        Array.Copy(data, 0, combined, dLen, data.Length);
        var tokens = Tokenize(combined, offset: dLen, dictLen: dLen);
        return TansEncodeWithDict(data, tokens, dict);
    }

    internal static byte[] TansEncodeWithDict(byte[] data, List<CkcToken> tokens, byte[] dict)
    {
        // Build tables from tokens (same as TansEncode)
        var litF = new int[LitSymbols]; for (int i = 0; i < litF.Length; i++) litF[i] = 1;
        var lenF = new int[512]; for (int i = 0; i < lenF.Length; i++) lenF[i] = 1;
        var dstF = new int[CkcDistSlot.SlotCount * 2]; for (int i = 0; i < dstF.Length; i++) dstF[i] = 1;

        var smCount = new CkcStateMachine();
        byte _p3 = 0; int _l3 = 0;
        foreach (var tk in tokens)
        {
            if (tk.IsMatch)
            {
                int li = tk.Length - CkcConstants.MinMatchLen;
                int ri = smCount.WhichRep(tk.Distance);
                if (ri >= 0) { if (ri == 0 && tk.Length == 1) smCount.OnShortRep(); else smCount.OnLongRep(ri); }
                else smCount.OnNormalMatch(tk.Distance);
                var (slot, _) = CkcDistSlot.Map(tk.Distance);
                int lenOff = tk.Length <= 8 ? 0 : 256;
                int dstOff = tk.Length <= 4 ? 0 : CkcDistSlot.SlotCount;
                if (li >= 0 && li < 256) lenF[lenOff + li]++;
                if (slot >= 0 && slot < CkcDistSlot.SlotCount) dstF[dstOff + slot]++;
                _p3 = 0; _l3 = tk.Length;
            }
            else { litF[LitCtx(smCount.State, tk.Literal, _p3, _l3) * 256 + tk.Literal]++; smCount.OnLiteral(); _p3 = tk.Literal; _l3 = 0; }
        }

        var tLit = TansTable.Build(litF, L_LIT);
        var tLen = TansTable.Build(lenF, L);
        var tDst = TansTable.Build(dstF, L_DST);

        // Re-tokenize with costs (WITH dictDict)
        var combined = new byte[dict.Length + data.Length];
        Array.Copy(dict, 0, combined, 0, dict.Length);
        Array.Copy(data, 0, combined, dict.Length, data.Length);
        tokens = TokenizeWithCost(combined, dict.Length, tLit, tLen, tDst, dict.Length);

        // Re-count, rebuild, re-tokenize for convergence
        for (int i = 0; i < litF.Length; i++) litF[i] = 1;
        for (int i = 0; i < lenF.Length; i++) lenF[i] = 1;
        for (int i = 0; i < dstF.Length; i++) dstF[i] = 1;
        smCount = new CkcStateMachine();
        _p3 = 0; _l3 = 0;
        foreach (var tk in tokens)
        {
            if (tk.IsMatch)
            {
                int li = tk.Length - CkcConstants.MinMatchLen;
                int ri = smCount.WhichRep(tk.Distance);
                if (ri >= 0) { if (ri == 0 && tk.Length == 1) smCount.OnShortRep(); else smCount.OnLongRep(ri); }
                else smCount.OnNormalMatch(tk.Distance);
                var (slot, _) = CkcDistSlot.Map(tk.Distance);
                int lenOff = tk.Length <= 8 ? 0 : 256;
                int dstOff = tk.Length <= 4 ? 0 : CkcDistSlot.SlotCount;
                if (li >= 0 && li < 256) lenF[lenOff + li]++;
                if (slot >= 0 && slot < CkcDistSlot.SlotCount) dstF[dstOff + slot]++;
                _p3 = 0; _l3 = tk.Length;
            }
            else { litF[LitCtx(smCount.State, tk.Literal, _p3, _l3) * 256 + tk.Literal]++; smCount.OnLiteral(); _p3 = tk.Literal; _l3 = 0; }
        }
        tLit = TansTable.Build(litF, L_LIT);
        tLen = TansTable.Build(lenF, L);
        tDst = TansTable.Build(dstF, L_DST);
        tokens = TokenizeWithCost(combined, dict.Length, tLit, tLen, tDst, dict.Length);

        // Multi-strategy: try 4 decision thresholds
        double bestBits = EstimateTokenBits(tokens, tLit, tLen, tDst);
        for (int s = 1; s < 4; s++)
        {
            var alt = TokenizeWithCost(combined, dict.Length, tLit, tLen, tDst, dict.Length, s);
            double ab = EstimateTokenBits(alt, tLit, tLen, tDst);
            if (ab < bestBits) { bestBits = ab; tokens = alt; }
        }

        // Encode tokens
        var bits = new List<byte>();
        void Wb(int b) => bits.Add((byte)(b & 1));
        void Wv(int val, int w) { for (int j = w - 1; j >= 0; j--) Wb((val >> j) & 1); }
        int sLit = L_LIT, sLen = L, sDst = L_DST;

        var stInfo = new (int state, int repIndex, bool isRep, bool isShortRep, int litExtra)[tokens.Count];
        var sm = new CkcStateMachine();
        byte _p4 = 0; int _l4 = 0;
        for (int i = 0; i < tokens.Count; i++)
        {
            var tk = tokens[i];
            int le = 0;
            if (tk.IsMatch)
            {
                int ri = sm.WhichRep(tk.Distance);
                if (ri >= 0) { bool isShort = ri == 0 && tk.Length == 1; stInfo[i] = (sm.State, ri, true, isShort, le); if (isShort) sm.OnShortRep(); else sm.OnLongRep(ri); }
                else { stInfo[i] = (sm.State, -1, false, false, le); sm.OnNormalMatch(tk.Distance); }
                _p4 = 0; _l4 = tk.Length;
            }
            else { stInfo[i] = (sm.State, -1, false, false, le); sm.OnLiteral(); _p4 = tk.Literal; _l4 = 0; }
        }
        for (int i = tokens.Count - 1; i >= 0; i--)
        {
            var tk = tokens[i];
            if (tk.IsMatch)
            {
                bool isRep = stInfo[i].isRep; bool isShortRep = stInfo[i].isShortRep; int repIdx = stInfo[i].repIndex;
                if (isShortRep) { Wb(0); Wb((repIdx >> 1) & 1); Wb(repIdx & 1); Wb(1); Wb(1); continue; }
                bool lenShort = tk.Length <= 8; var (slot, extra) = CkcDistSlot.Map(tk.Distance);
                int li = tk.Length - CkcConstants.MinMatchLen; int lenSym = lenShort ? li : (li + 256);
                if (isRep)
                {
                    var (nl, ql) = tLen.Encode(sLen, lenSym); Wv(ql - 1, tLen.SymBitsQ(lenSym)); sLen = nl;
                    if (repIdx == 0) { Wb(1); Wb((repIdx >> 1) & 1); Wb(repIdx & 1); Wb(1); Wb(1); }
                    else { Wb((repIdx >> 1) & 1); Wb(repIdx & 1); Wb(1); Wb(1); }
                }
                else
                {
                    if (extra > 0) { int ev = tk.Distance - GetDistBase(slot); for (int j = extra - 1; j >= 0; j--) Wb((ev >> j) & 1); }
                    int dstSym = (tk.Length <= 4) ? slot : (slot + CkcDistSlot.SlotCount);
                    var (nd, qd) = tDst.Encode(sDst, dstSym); Wv(qd - 1, tDst.SymBitsQ(dstSym)); sDst = nd;
                    var (nl, ql) = tLen.Encode(sLen, lenSym); Wv(ql - 1, tLen.SymBitsQ(lenSym)); sLen = nl;
                    Wb(0); Wb(1);
                }
            }
            else
            {
                int ctx = LitCtx(stInfo[i].state, tk.Literal); int litSym = ctx * 256 + tk.Literal;
                var (nl, ql) = tLit.Encode(sLit, litSym); Wv(ql - 1, tLit.SymBitsQ(litSym)); sLit = nl; Wb(0);
            }
        }

        Wv(tokens.Count, 20);
        Wv(sLit, SB_LIT); Wv(sLen, SB_LEN); Wv(sDst, SB_DST);
        bits.Reverse();

        var ms = new MemoryStream();
        // 0x04 header
        ms.WriteByte(0x43); ms.WriteByte(0x4B); ms.WriteByte(0x43); ms.WriteByte(0x04);
        Span<byte> hdr = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(hdr, (ushort)dict.Length); ms.Write(hdr);
        ms.Write(dict, 0, dict.Length);
        hdr = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(hdr, data.Length); ms.Write(hdr);
        WriteFreqRaw(ms, litF); WriteFreqRaw(ms, lenF); WriteFreqRaw(ms, dstF);

        int acc2 = 0, nb2 = 0;
        foreach (byte b in bits) { acc2 |= b << nb2; if (++nb2 >= 8) { ms.WriteByte((byte)acc2); acc2 = 0; nb2 = 0; } }
        if (nb2 > 0) ms.WriteByte((byte)acc2);
        return ms.ToArray();
    }

    public static byte[] DecompressSingleWithDict(byte[] data)
    {
        if (data.Length < 8 || data[0] != 0x43 || data[1] != 0x4B || data[2] != 0x43 || data[3] != 0x04)
            throw new InvalidDataException("Not a CKC v4 dictionary stream");
        int dictLen = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(4));
        int originalSize = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(6 + dictLen));
        var dict = new byte[dictLen];
        Array.Copy(data, 6, dict, 0, dictLen);

        int rawp = 10 + dictLen;
        var litF = ReadFreqRaw(data, ref rawp);
        var lenF = ReadFreqRaw(data, ref rawp);
        var dstF = ReadFreqRaw(data, ref rawp);
        var tLit = TansTable.Build(litF, L_LIT);
        var tLen = TansTable.Build(lenF, L);
        var tDst = TansTable.Build(dstF, L_DST);

        int pos = rawp;
        ulong acc = 0; int bitsAvail = 0;
        int sDst = ReadBits(ref pos, ref acc, ref bitsAvail, SB_DST, data);
        int sLen = ReadBits(ref pos, ref acc, ref bitsAvail, SB_LEN, data);
        int sLit = ReadBits(ref pos, ref acc, ref bitsAvail, SB_LIT, data);
        int tc = ReadBits(ref pos, ref acc, ref bitsAvail, 20, data);
        return DecodeResult(originalSize, data, tc, sLit, sLen, sDst, tLit, tLen, tDst, ref pos, ref acc, ref bitsAvail, dict);
    }

    private static void AdvanceMatch(CkcStateMachine sm, CkcToken tk)
    {
        int ri = sm.WhichRep(tk.Distance);
        if (ri >= 0)
        {
            if (ri == 0 && tk.Length == 1) sm.OnShortRep();
            else sm.OnLongRep(ri);
        }
        else sm.OnNormalMatch(tk.Distance);
    }

    private static int ComputeMatchBits(CkcToken tk, CkcStateMachine sm,
        TansTable tLen, TansTable tDst)
    {
        int ri = sm.WhichRep(tk.Distance);
        if (ri == 0 && tk.Length == 1)
            return 5;

        int lenOff = tk.Length <= 8 ? 0 : 256;
        int li = tk.Length - CkcConstants.MinMatchLen;
        int lenSym = lenOff + li;
        int cost = tLen.SymBitsQ(lenSym);

        if (ri >= 0)
        {
            cost += (ri == 0 ? 5 : 4);
            return cost;
        }

        var (slot, extra) = CkcDistSlot.Map(tk.Distance);
        int dstSym = (tk.Length <= 4) ? slot : (slot + CkcDistSlot.SlotCount);
        cost += tDst.SymBitsQ(dstSym) + extra;
        cost += 2;
        return cost;
    }

    internal static List<CkcToken> TokenizeWithCost(byte[] data, int offset,
        TansTable tLit, TansTable tLen, TansTable tDst, int dictLen = 0, int strategy = 0)
    {
        int cutValue = 512;
        var mf = CkcMatchFinder.Rent(data, data.Length, cutValue);
        try
        {
            var tokens = new List<CkcToken>();
            var sm = new CkcStateMachine();
            for (int dp = 0; dp < offset; dp++)
                mf.FindLongestMatch(dp, Math.Min(CkcConstants.MaxMatchLen, data.Length - dp));

            int pos = offset;
            while (pos < data.Length)
            {
                int lenLimit = Math.Min(CkcConstants.MaxMatchLen, data.Length - pos);
                var (len, dist) = mf.FindLongestMatch(pos, lenLimit);
                int localPos = pos - offset;

                int bestLen = len, bestDist = dist, bestSkip = 0;
                int bestCost = int.MaxValue;

                // Rep priority: check rep distances before hash chain search
                int[] repDists = { sm.Rep0, sm.Rep1, sm.Rep2, sm.Rep3 };
                for (int ri = 0; ri < 4; ri++)
                {
                    int rd = repDists[ri];
                    if (rd <= 0 || rd > localPos + dictLen) continue;
                    if (pos - rd < 0 || pos + 2 >= data.Length || pos - rd + 2 >= data.Length) continue;
                    if (data[pos] == data[pos - rd] && data[pos + 1] == data[pos - rd + 1]
                        && data[pos + 2] == data[pos - rd + 2])
                    {
                        int repLen = 3;
                        int rlim = Math.Min(Math.Min(CkcConstants.MaxMatchLen, data.Length - pos), data.Length - (pos - rd));
                        while (repLen < rlim && data[pos - rd + repLen] == data[pos + repLen])
                            repLen++;
                        if (repLen >= CkcConstants.MinMatchLen)
                        {
                            int repCost = ComputeMatchBits(new CkcToken(repLen, rd), sm, tLen, tDst);
                            if (repCost < bestCost) { bestCost = repCost; bestLen = repLen; bestDist = rd; bestSkip = 0; }
                        }
                    }
                }

                if (len >= CkcConstants.MinMatchLen && dist <= localPos + dictLen)
                {
                    bestCost = ComputeMatchBits(new CkcToken(len, dist), sm, tLen, tDst);
                    if (len >= 12)
                    {
                        for (int skip = 1; skip <= 3 && pos + skip < data.Length; skip++)
                        {
                            if (!mf.HeadHasEntry(pos + skip)) continue;
                            int nextLimit = Math.Min(CkcConstants.MaxMatchLen, data.Length - pos - skip);
                            var (nextLen, nextDist) = mf.FindLongestMatch(pos + skip, nextLimit);
                            if (nextLen >= CkcConstants.MinMatchLen && nextDist <= localPos + skip + dictLen)
                            {
                                int cost = ComputeMatchLitCost(skip, data, pos, sm, tLit) + ComputeMatchBits(new CkcToken(nextLen, nextDist), sm, tLen, tDst);
                                if (cost < bestCost)
                                {
                                    bestCost = cost; bestLen = nextLen; bestDist = nextDist; bestSkip = skip;
                                    if (nextLen >= nextLimit) break;
                                }
                            }
                        }
                    }
                }

                int fullLitCost = 0;
                int ll = Math.Min(CkcConstants.MinMatchLen, data.Length - pos);
                for (int j = 0; j < ll; j++)
                    fullLitCost += 1 + tLit.SymBitsQ(LitCtx(sm.State, data[pos + j]) * 256 + data[pos + j]);

                // Adaptive: override strategy based on recent match/literal ratio
                int adapStrategy = strategy;
                if (strategy == 0 && tokens.Count >= 8)
                {
                    int recM = 0, recBits = 0;
                    int lookback = Math.Min(32, tokens.Count);
                    for (int t = tokens.Count - 1; t >= tokens.Count - lookback && t >= 0; t--)
                    {
                        if (tokens[t].IsMatch) recM++;
                        recBits += tokens[t].IsMatch ? tokens[t].Length : 1;
                    }
                    if (recBits >= 16)
                    {
                        double mr = (double)recM / lookback;
                        if (mr > 0.65) adapStrategy = 1;
                        else if (mr < 0.25) adapStrategy = 3;
                    }
                }

                int threshold = adapStrategy switch
                {
                    1 => fullLitCost * 5 / 4,   // aggressive: prefer matches
                    2 => bestLen >= 12 ? fullLitCost * 3 / 2 : fullLitCost, // long-match bonus
                    3 => fullLitCost * 3 / 4,   // conservative: prefer literals
                    _ => fullLitCost
                };
                if (bestLen >= CkcConstants.MinMatchLen && bestCost < threshold)
                {
                    for (int s = 0; s < bestSkip; s++)
                    {
                        tokens.Add(new CkcToken(data[pos + s]));
                        sm.OnLiteral();
                    }
                    tokens.Add(new CkcToken(bestLen, bestDist));
                    AdvanceMatch(sm, new CkcToken(bestLen, bestDist));
                    pos += bestSkip + bestLen;
                }
                else
                {
                    tokens.Add(new CkcToken(data[pos]));
                    sm.OnLiteral();
                    pos++;
                }
            }
            return tokens;
        }
        finally { CkcMatchFinder.Return(mf); }
    }

    private static int ComputeMatchLitCost(int skip, byte[] data, int pos, CkcStateMachine sm, TansTable tLit)
    {
        var snap = sm.Snapshot();
        int cost = 0;
        for (int s = 0; s < skip; s++)
        {
            int ctx = LitCtx(sm.State, data[pos + s]);
            cost += 1 + tLit.SymBitsQ(ctx * 256 + data[pos + s]);
            sm.OnLiteral();
        }
        sm.Restore(snap.state, snap.r0, snap.r1, snap.r2, snap.r3);
        return cost;
    }

    private static double EstimateTokenBits(List<CkcToken> tokens, TansTable tLit, TansTable tLen, TansTable tDst)
    {
        var sm = new CkcStateMachine();
        double total = 0;
        byte _pe = 0; int _le = 0;
        foreach (var tk in tokens)
        {
            if (tk.IsMatch)
            {
                total += ComputeMatchBits(tk, sm, tLen, tDst);
                AdvanceMatch(sm, tk);
                _pe = 0; _le = tk.Length;
            }
            else
            {
                int ctx = LitCtx(sm.State, tk.Literal, _pe, _le);
                total += 1 + tLit.SymBitsQ(ctx * 256 + tk.Literal);
                sm.OnLiteral();
                _pe = tk.Literal; _le = 0;
            }
        }
        return total;
    }

    internal static byte[] TansEncode(byte[] data, List<CkcToken> tokens)
    {
        var litF = new int[LitSymbols];
        var lenF = new int[512];
        var dstF = new int[CkcDistSlot.SlotCount * 2];

        for (int i = 0; i < litF.Length; i++) litF[i] = 1;
        for (int i = 0; i < 512; i++) lenF[i] = 1;
        for (int i = 0; i < dstF.Length; i++) dstF[i] = 1;

        var smCount = new CkcStateMachine();
        byte _p1 = 0; int _l1 = 0;
        foreach (var tk in tokens)
        {
            if (tk.IsMatch)
            {
                int li = tk.Length - CkcConstants.MinMatchLen;
                int ri = smCount.WhichRep(tk.Distance);
                if (ri >= 0) { if (ri == 0 && tk.Length == 1) smCount.OnShortRep(); else smCount.OnLongRep(ri); }
                else smCount.OnNormalMatch(tk.Distance);
                var (slot, _) = CkcDistSlot.Map(tk.Distance);
                int lenOff = tk.Length <= 8 ? 0 : 256;
                int dstOff = tk.Length <= 4 ? 0 : CkcDistSlot.SlotCount;
                if (li >= 0 && li < 256) lenF[lenOff + li]++;
                if (slot >= 0 && slot < CkcDistSlot.SlotCount) dstF[dstOff + slot]++;
                _p1 = 0; _l1 = tk.Length;
            }
            else { int ctx = LitCtx(smCount.State, tk.Literal, _p1, _l1); litF[ctx * 256 + tk.Literal]++; smCount.OnLiteral(); _p1 = tk.Literal; _l1 = 0; }
        }

        var tLit = TansTable.Build(litF, L_LIT);
        var tLen = TansTable.Build(lenF, L);
        var tDst = TansTable.Build(dstF, L_DST);

        tokens = TokenizeWithCost(data, 0, tLit, tLen, tDst);

        // Re-count from optimized tokens, rebuild, re-tokenize for convergence
        for (int i = 0; i < litF.Length; i++) litF[i] = 1;
        for (int i = 0; i < lenF.Length; i++) lenF[i] = 1;
        for (int i = 0; i < dstF.Length; i++) dstF[i] = 1;
        smCount = new CkcStateMachine();
        _p1 = 0; _l1 = 0;
        foreach (var tk in tokens)
        {
            if (tk.IsMatch)
            {
                int li = tk.Length - CkcConstants.MinMatchLen;
                int ri = smCount.WhichRep(tk.Distance);
                if (ri >= 0) { if (ri == 0 && tk.Length == 1) smCount.OnShortRep(); else smCount.OnLongRep(ri); }
                else smCount.OnNormalMatch(tk.Distance);
                var (slot, _) = CkcDistSlot.Map(tk.Distance);
                int lenOff = tk.Length <= 8 ? 0 : 256;
                int dstOff = tk.Length <= 4 ? 0 : CkcDistSlot.SlotCount;
                if (li >= 0 && li < 256) lenF[lenOff + li]++;
                if (slot >= 0 && slot < CkcDistSlot.SlotCount) dstF[dstOff + slot]++;
                _p1 = 0; _l1 = tk.Length;
            }
            else { litF[LitCtx(smCount.State, tk.Literal, _p1, _l1) * 256 + tk.Literal]++; smCount.OnLiteral(); _p1 = tk.Literal; _l1 = 0; }
        }
        tLit = TansTable.Build(litF, L_LIT);
        tLen = TansTable.Build(lenF, L);
        tDst = TansTable.Build(dstF, L_DST);
        tokens = TokenizeWithCost(data, 0, tLit, tLen, tDst);

        // Multi-strategy: try 4 decision thresholds
        double bestBits = EstimateTokenBits(tokens, tLit, tLen, tDst);
        for (int s = 1; s < 4; s++)
        {
            var alt = TokenizeWithCost(data, 0, tLit, tLen, tDst, 0, s);
            double ab = EstimateTokenBits(alt, tLit, tLen, tDst);
            if (ab < bestBits) { bestBits = ab; tokens = alt; }
        }

        var bits = new List<byte>();
        void Wb(int b) => bits.Add((byte)(b & 1));
        void Wv(int val, int w) { for (int j = w - 1; j >= 0; j--) Wb((val >> j) & 1); }
        int sLit = L_LIT, sLen = L, sDst = L_DST;

        var stInfo = new (int state, int repIndex, bool isRep, bool isShortRep, int litExtra)[tokens.Count];
        var sm = new CkcStateMachine();
        byte _ps = 0; int _ls = 0;
        for (int i = 0; i < tokens.Count; i++)
        {
            var tk = tokens[i];
            int le = 0;
            if (tk.IsMatch)
            {
                int ri = sm.WhichRep(tk.Distance);
                if (ri >= 0) { bool isShort = ri == 0 && tk.Length == 1; stInfo[i] = (sm.State, ri, true, isShort, le); if (isShort) sm.OnShortRep(); else sm.OnLongRep(ri); }
                else { stInfo[i] = (sm.State, -1, false, false, le); sm.OnNormalMatch(tk.Distance); }
                _ps = 0; _ls = tk.Length;
            }
            else { stInfo[i] = (sm.State, -1, false, false, le); sm.OnLiteral(); _ps = tk.Literal; _ls = 0; }
        }

        // Reverse encoding
        for (int i = tokens.Count - 1; i >= 0; i--)
        {
            var tk = tokens[i];
            if (tk.IsMatch)
            {
                bool isRep = stInfo[i].isRep;
                bool isShortRep = stInfo[i].isShortRep;
                int repIdx = stInfo[i].repIndex;

                if (isShortRep)
                {
                    Wb(0); Wb((repIdx >> 1) & 1); Wb(repIdx & 1); Wb(1); Wb(1);
                    continue;
                }

                bool lenShort = tk.Length <= 8;
                var (slot, extra) = CkcDistSlot.Map(tk.Distance);
                int li = tk.Length - CkcConstants.MinMatchLen;
                int lenSym = lenShort ? li : (li + 256);

                if (isRep)
                {
                    var (nl, ql) = tLen.Encode(sLen, lenSym); Wv(ql - 1, tLen.SymBitsQ(lenSym)); sLen = nl;
                    if (repIdx == 0) { Wb(1); Wb((repIdx >> 1) & 1); Wb(repIdx & 1); Wb(1); Wb(1); }
                    else { Wb((repIdx >> 1) & 1); Wb(repIdx & 1); Wb(1); Wb(1); }
                }
                else
                {
                    if (extra > 0) { int ev = tk.Distance - GetDistBase(slot); for (int j = extra - 1; j >= 0; j--) Wb((ev >> j) & 1); }
                    int dstSym = (tk.Length <= 4) ? slot : (slot + CkcDistSlot.SlotCount);
                    var (nd, qd) = tDst.Encode(sDst, dstSym); Wv(qd - 1, tDst.SymBitsQ(dstSym)); sDst = nd;
                    var (nl, ql) = tLen.Encode(sLen, lenSym); Wv(ql - 1, tLen.SymBitsQ(lenSym)); sLen = nl;
                    Wb(0); Wb(1);
                }
            }
            else
            {
                int ctx = LitCtx(stInfo[i].state);
                int litSym = ctx * 256 + tk.Literal;
                var (nl, ql) = tLit.Encode(sLit, litSym); Wv(ql - 1, tLit.SymBitsQ(litSym)); sLit = nl;
                Wb(0);
            }
        }

        Wv(tokens.Count, 20);
        Wv(sLit, SB_LIT); Wv(sLen, SB_LEN); Wv(sDst, SB_DST);
        bits.Reverse();

        var ms = new MemoryStream();
        ms.WriteByte(0x43); ms.WriteByte(0x4B); ms.WriteByte(0x43); ms.WriteByte(0x02);
        Span<byte> hdr = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(hdr, data.Length); ms.Write(hdr);

        WriteFreqRaw(ms, litF); WriteFreqRaw(ms, lenF); WriteFreqRaw(ms, dstF);

        int acc = 0, nb = 0;
        foreach (byte b in bits) { acc |= b << nb; if (++nb >= 8) { ms.WriteByte((byte)acc); acc = 0; nb = 0; } }
        if (nb > 0) ms.WriteByte((byte)acc);
        return ms.ToArray();
    }

    private static void WriteFreqRaw(Stream s, int[] freqs)
    {
        Span<byte> buf = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(buf, (ushort)freqs.Length);
        s.Write(buf);
        foreach (int v in freqs)
        {
            int d = v - 1;
            while (d >= 0x80) { s.WriteByte((byte)(d | 0x80)); d >>= 7; }
            s.WriteByte((byte)d);
        }
    }

    private static int[] ReadFreqRaw(byte[] data, ref int pos)
    {
        if (pos + 2 > data.Length) return new int[] { 1 };
        int count = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(pos)); pos += 2;
        if (count == 0 || count > 4096) return new int[] { 1 };
        var freqs = new int[count];
        for (int i = 0; i < count; i++)
        {
            int d = 0, shift = 0;
            while (pos < data.Length)
            {
                byte b = data[pos++];
                d |= (b & 0x7F) << shift;
                if ((b & 0x80) == 0) break;
                shift += 7;
            }
            freqs[i] = d + 1;
        }
        return freqs;
    }

    public static byte[] DecompressTans(byte[] data)
    {
        if (data.Length < 8 || data[0] != 0x43 || data[1] != 0x4B || data[2] != 0x43 || data[3] != 0x02)
            throw new InvalidDataException("Not a CKC v2 compressed stream");

        int originalSize = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(4));

        int rawp = 8;
        var litF = ReadFreqRaw(data, ref rawp);
        var lenF = ReadFreqRaw(data, ref rawp);
        var dstF = ReadFreqRaw(data, ref rawp);
        var tLit = TansTable.Build(litF, L_LIT);
        var tLen = TansTable.Build(lenF, L);
        var tDst = TansTable.Build(dstF, L_DST);

        int pos = rawp;
        ulong acc = 0; int bitsAvail = 0;
        int sDst = ReadBits(ref pos, ref acc, ref bitsAvail, SB_DST, data);
        int sLen = ReadBits(ref pos, ref acc, ref bitsAvail, SB_LEN, data);
        int sLit = ReadBits(ref pos, ref acc, ref bitsAvail, SB_LIT, data);
        int tc = ReadBits(ref pos, ref acc, ref bitsAvail, 20, data);
        return DecodeResult(originalSize, data, tc, sLit, sLen, sDst, tLit, tLen, tDst, ref pos, ref acc, ref bitsAvail);
    }

    public static byte[] Decompress(byte[] data)
        => DecompressTans(data);

    public static int GetDistBase(int slot) { if (slot == 0) return 1; if (slot == 1) return 2; if (slot == 2) return 3; if (slot == 3) return 4; int b = 5, p = 1; for (int s = 4; s < slot; s++) { p <<= 1; b += p; } return b; }
    public static int GetExtraBits(int slot) { if (slot <= 3) return 0; if (slot <= 4) return 1; if (slot <= 5) return 2; if (slot <= 6) return 3; if (slot <= 7) return 4; if (slot <= 8) return 5; if (slot <= 9) return 6; if (slot <= 10) return 7; if (slot <= 11) return 8; if (slot <= 12) return 9; if (slot <= 13) return 10; if (slot <= 14) return 11; if (slot <= 15) return 12; return Math.Min(slot - 3, 25); }

    // --- Shared-table mode (0x03 format) ---

    internal static byte[] CompressWithShared(byte[] data, TansTable tLit, TansTable tLen, TansTable tDst)
    {
        var tokens = Tokenize(data);
        return TansEncodeShared(data, tokens, tLit, tLen, tDst);
    }

    internal static byte[] DecompressShared(byte[] data, TansTable tLit, TansTable tLen, TansTable tDst)
    {
        if (data.Length < 8 || data[0] != 0x43 || data[1] != 0x4B || data[2] != 0x43 || data[3] != 0x03)
            throw new InvalidDataException("Not a CKC v2 shared compressed stream");

        int originalSize = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(4));
        int rawp = 8;
        int pos = rawp;
        ulong acc = 0; int bitsAvail = 0;
        int sDst = ReadBits(ref pos, ref acc, ref bitsAvail, SB_DST, data);
        int sLen = ReadBits(ref pos, ref acc, ref bitsAvail, SB_LEN, data);
        int sLit = ReadBits(ref pos, ref acc, ref bitsAvail, SB_LIT, data);
        int tc = ReadBits(ref pos, ref acc, ref bitsAvail, 20, data);
        return DecodeResult(originalSize, data, tc, sLit, sLen, sDst, tLit, tLen, tDst, ref pos, ref acc, ref bitsAvail);
    }

    internal static (TansTable lit, TansTable len, TansTable dst) BuildTablesFromCompressed(byte[] compressed)
    {
        int rawp = 8;
        if (compressed.Length >= 4 && compressed[3] == 0x04)
        {
            int dictLen = BinaryPrimitives.ReadUInt16LittleEndian(compressed.AsSpan(4));
            rawp = 10 + dictLen;
        }
        var litF = ReadFreqRaw(compressed, ref rawp);
        var lenF = ReadFreqRaw(compressed, ref rawp);
        var dstF = ReadFreqRaw(compressed, ref rawp);
        return (TansTable.Build(litF, L_LIT), TansTable.Build(lenF, L), TansTable.Build(dstF, L_DST));
    }

    private static int MatchBits(int m, int d)
    {
        var (slot, extra) = CkcDistSlot.Map(d);
        int lenBits = (m - CkcConstants.MinMatchLen) <= 8 ? 8 : 10;
        int distCost = extra + (slot < 8 ? 2 : 4 + (slot - 8) / 3);
        return lenBits + distCost + 4;
    }

    internal static List<CkcToken> Tokenize(byte[] data, int offset = 0, int dictLen = 0, bool fast = false)
    {
        const int LIT_BITS = 9;
        int cutValue = fast ? 64 : 512;
        int levels = fast ? 3 : 6;
        var mf = CkcMatchFinder.Rent(data, data.Length, cutValue, levels);
        try
        {
            var tokens = new List<CkcToken>();
            for (int dp = 0; dp < offset; dp++)
                mf.FindLongestMatch(dp, Math.Min(CkcConstants.MaxMatchLen, data.Length - dp));

            int pos = offset;
            int literalRun = 0;
            int maxLiteralRun = Math.Max(4096, (data.Length - offset) / 8);
            bool bailOut = false;
            while (pos < data.Length)
            {
                int lenLimit = Math.Min(CkcConstants.MaxMatchLen, data.Length - pos);
                int len = 0, dist = 0;
                if (!bailOut)
                {
                    (len, dist) = mf.FindLongestMatch(pos, lenLimit);
                }
                int localPos = pos - offset;
                if (!bailOut && len >= CkcConstants.MinMatchLen && MatchBits(len, dist) < len * LIT_BITS && dist <= localPos + dictLen)
                {
                    literalRun = 0;
                    int bestLen = len, bestDist = dist, bestSkip = 0;
                    int bestCost = MatchBits(len, dist);
                    if (len >= 12)
                    {
                        for (int skip = 1; skip <= 3 && pos + skip < data.Length; skip++)
                        {
                            int nextLimit = Math.Min(CkcConstants.MaxMatchLen, data.Length - pos - skip);
                            if (!mf.HeadHasEntry(pos + skip)) continue;
                            var (nextLen, nextDist) = mf.FindLongestMatch(pos + skip, nextLimit);
                            if (nextLen >= CkcConstants.MinMatchLen && nextDist <= localPos + skip + dictLen)
                            {
                                int cost = skip * LIT_BITS + MatchBits(nextLen, nextDist);
                                if (cost < bestCost)
                                {
                                    bestCost = cost; bestLen = nextLen; bestDist = nextDist; bestSkip = skip;
                                    if (nextLen >= nextLimit) break;
                                }
                            }
                        }
                    }
                    for (int s = 0; s < bestSkip; s++)
                        tokens.Add(new CkcToken(data[pos + s]));
                    tokens.Add(new CkcToken(bestLen, bestDist));
                    pos += bestSkip + bestLen;
                }
                else
                {
                    tokens.Add(new CkcToken(data[pos])); pos++;
                    if (++literalRun >= maxLiteralRun)
                        bailOut = true;
                }
            }
            return tokens;
        }
        finally { CkcMatchFinder.Return(mf); }
    }

    internal static byte[] TansEncodeShared(byte[] data, List<CkcToken> tokens,
        TansTable tLit, TansTable tLen, TansTable tDst)
    {
        int capBits = Math.Max(tokens.Count * 80 + 1024, _tsBits?.Length ?? 0);
        if (_tsBits == null || _tsBits.Length < capBits) _tsBits = new byte[capBits];
        var bits = _tsBits;
        int nb = 0;
        void Wb(int b) { bits[nb++] = (byte)(b & 1); }
        void Wv(int val, int w) { for (int j = w - 1; j >= 0; j--) Wb((val >> j) & 1); }
        int sLit = L_LIT, sLen = L, sDst = L_DST;

        if (_tsStInfo == null || _tsStInfo.Length < tokens.Count) _tsStInfo = new (int state, int repIndex, bool isRep, bool isShortRep, int litExtra)[tokens.Count];
        var stInfo = _tsStInfo;
        var sm = new CkcStateMachine();
        byte _p2 = 0; int _l2 = 0;
        for (int i = 0; i < tokens.Count; i++)
        {
            var tk = tokens[i];
            int le = 0;
            if (tk.IsMatch)
            {
                int ri = sm.WhichRep(tk.Distance);
                if (ri >= 0) { bool isShort = ri == 0 && tk.Length == 1; stInfo[i] = (sm.State, ri, true, isShort, le); if (isShort) sm.OnShortRep(); else sm.OnLongRep(ri); }
                else { stInfo[i] = (sm.State, -1, false, false, le); sm.OnNormalMatch(tk.Distance); }
                _p2 = 0; _l2 = tk.Length;
            }
            else { stInfo[i] = (sm.State, -1, false, false, le); sm.OnLiteral(); _p2 = tk.Literal; _l2 = 0; }
        }

        for (int i = tokens.Count - 1; i >= 0; i--)
        {
            var tk = tokens[i];
            if (tk.IsMatch)
            {
                bool isRep = stInfo[i].isRep;
                bool isShortRep = stInfo[i].isShortRep;
                int repIdx = stInfo[i].repIndex;

                if (isShortRep)
                {
                    Wb(0); Wb((repIdx >> 1) & 1); Wb(repIdx & 1); Wb(1); Wb(1);
                    continue;
                }

                bool lenShort = tk.Length <= 8;
                var (slot, extra) = CkcDistSlot.Map(tk.Distance);
                int li = tk.Length - CkcConstants.MinMatchLen;
                int lenSym = lenShort ? li : (li + 256);

                if (isRep)
                {
                    var (nl, ql) = tLen.Encode(sLen, lenSym); Wv(ql - 1, tLen.SymBitsQ(lenSym)); sLen = nl;
                    if (repIdx == 0) { Wb(1); Wb((repIdx >> 1) & 1); Wb(repIdx & 1); Wb(1); Wb(1); }
                    else { Wb((repIdx >> 1) & 1); Wb(repIdx & 1); Wb(1); Wb(1); }
                }
                else
                {
                    if (extra > 0) { int ev = tk.Distance - GetDistBase(slot); for (int j = extra - 1; j >= 0; j--) Wb((ev >> j) & 1); }
                    int dstSym = (tk.Length <= 4) ? slot : (slot + CkcDistSlot.SlotCount);
                    var (nd, qd) = tDst.Encode(sDst, dstSym); Wv(qd - 1, tDst.SymBitsQ(dstSym)); sDst = nd;
                    var (nl, ql) = tLen.Encode(sLen, lenSym); Wv(ql - 1, tLen.SymBitsQ(lenSym)); sLen = nl;
                    Wb(0); Wb(1);
                }
            }
            else
            {
                int ctx = LitCtx(stInfo[i].state);
                int litSym = ctx * 256 + tk.Literal;
                var (nl, ql) = tLit.Encode(sLit, litSym); Wv(ql - 1, tLit.SymBitsQ(litSym)); sLit = nl;
                Wb(0);
            }
        }

        Wv(tokens.Count, 20);
        Wv(sLit, SB_LIT); Wv(sLen, SB_LEN); Wv(sDst, SB_DST);

        Array.Reverse(bits, 0, nb);

        var ms = new MemoryStream();
        ms.WriteByte(0x43); ms.WriteByte(0x4B); ms.WriteByte(0x43); ms.WriteByte(0x03);
        Span<byte> hdr = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(hdr, data.Length); ms.Write(hdr);

        int acc2 = 0, nb2 = 0;
        for (int i = 0; i < nb; i++) { acc2 |= bits[i] << nb2; if (++nb2 >= 8) { ms.WriteByte((byte)acc2); acc2 = 0; nb2 = 0; } }
        if (nb2 > 0) ms.WriteByte((byte)acc2);
        return ms.ToArray();
    }

    private static byte[] DecodeResult(int originalSize, byte[] data, int tc,
        int sLit, int sLen, int sDst, TansTable tLit, TansTable tLen, TansTable tDst,
        ref int startPos, ref ulong startAcc, ref int startBitsAvail,
        byte[]? history = null)
    {
        int pos = startPos;
        ulong acc = startAcc;
        int bitsAvail = startBitsAvail;

        var result = new byte[originalSize];
        int op = 0;
        var sm = new CkcStateMachine();
        while (tc-- > 0 && op < originalSize)
        {
            int flag = ReadBits(ref pos, ref acc, ref bitsAvail,1, data);
            if (flag == 0)
            {
                int sym = tLit.GetSymbol(sLit);
                int q = ReadBits(ref pos, ref acc, ref bitsAvail,tLit.SymBitsQ(sym), data) + 1;
                tLit.TryDecode(sLit, q, out sLit);
                sm.OnLiteral();
                if (op < originalSize) result[op++] = (byte)(sym & 0xFF);
            }
            else
            {
                int isRep = ReadBits(ref pos, ref acc, ref bitsAvail,1, data);
                if (isRep == 1)
                {
                    int ri = ReadBits(ref pos, ref acc, ref bitsAvail,1, data) | (ReadBits(ref pos, ref acc, ref bitsAvail,1, data) << 1);
                    bool isShortRep = false;
                    if (ri == 0) { isShortRep = ReadBits(ref pos, ref acc, ref bitsAvail,1, data) == 0; }
                    if (isShortRep)
                    {
                        sm.OnShortRep();
                        int dist = sm.Rep0;
                        int rp = op - dist;
                        if (rp >= 0)
                            for (int j = 0, cl = Math.Min(1, originalSize - op); j < cl; j++) result[op++] = result[rp + j];
                        else if (history != null)
                        {
                            int hi = history.Length + rp;
                            if (hi < 0) hi = 0;
                            if (hi < history.Length) result[op++] = history[hi];
                            else { int src = hi - history.Length; result[op++] = src >= 0 && src < op ? result[src] : (byte)0; }
                        }
                    }
                    else
                    {
                        int symL = tLen.GetSymbol(sLen);
                        int qL = ReadBits(ref pos, ref acc, ref bitsAvail,tLen.SymBitsQ(symL), data) + 1;
                        tLen.TryDecode(sLen, qL, out sLen);
                        int len = (symL >= 256 ? symL - 256 : symL) + CkcConstants.MinMatchLen;
                        int dist;
                        if (ri == 0) dist = sm.Rep0;
                        else if (ri == 1) dist = sm.Rep1;
                        else if (ri == 2) dist = sm.Rep2;
                        else dist = sm.Rep3;
                        sm.OnLongRep(ri);
                        int rp = op - dist;
                        if (rp >= 0)
                            for (int j = 0, cl = Math.Min(len, originalSize - op); j < cl; j++) result[op++] = result[rp + j];
                        else if (history != null)
                        {
                            int hi = history.Length + rp;
                            if (hi < 0) hi = 0;
                            for (int j = 0, cl = Math.Min(len, originalSize - op); j < cl; j++)
                            {
                                int idx = hi + j;
                                result[op++] = idx < history.Length ? history[idx] : result[idx - history.Length];
                            }
                        }
                    }
                }
                else
                {
                    int symL = tLen.GetSymbol(sLen);
                    int qL = ReadBits(ref pos, ref acc, ref bitsAvail,tLen.SymBitsQ(symL), data) + 1;
                    tLen.TryDecode(sLen, qL, out sLen);

                    int symD = tDst.GetSymbol(sDst);
                    int qD = ReadBits(ref pos, ref acc, ref bitsAvail,tDst.SymBitsQ(symD), data) + 1;
                    tDst.TryDecode(sDst, qD, out sDst);

                    bool dstShort = symD < CkcDistSlot.SlotCount;
                    int slot = dstShort ? symD : (symD - CkcDistSlot.SlotCount);
                    int extra = GetExtraBits(slot), ev = extra > 0 ? ReadBits(ref pos, ref acc, ref bitsAvail,extra, data) : 0;
                    int dist = GetDistBase(slot) + ev;
                    int len = (symL >= 256 ? symL - 256 : symL) + CkcConstants.MinMatchLen;
                    sm.OnNormalMatch(dist);
                    int rp = op - dist;
                    if (rp >= 0)
                        for (int j = 0, cl = Math.Min(len, originalSize - op); j < cl; j++) result[op++] = result[rp + j];
                    else if (history != null)
                    {
                        int hi = history.Length + rp;
                        if (hi < 0) hi = 0;
                        for (int j = 0, cl = Math.Min(len, originalSize - op); j < cl; j++)
                        {
                            int idx = hi + j;
                            result[op++] = idx < history.Length ? history[idx] : result[idx - history.Length];
                        }
                    }
                }
            }
        }
        startPos = pos; startAcc = acc; startBitsAvail = bitsAvail;
        return result;
    }
}
