namespace RDRF.Core.Compression.Ckc;

internal sealed class TansTable
{
    private readonly int _L, _ns, _bitsQ;
    private readonly int[] _cum;
    private readonly int[] _f;
    private readonly int[] _symBitsQ;
    private readonly int[] _symOfSlot;

    public int StateCount => _L;
    public int BitsPerQ => _bitsQ;

    private TansTable(int L, int ns, int bitsQ, int[] cum, int[] f,
        int[] symBitsQ, int[] symOfSlot)
    {
        _L=L; _ns=ns; _bitsQ=bitsQ; _cum=cum; _f=f;
        _symBitsQ=symBitsQ; _symOfSlot=symOfSlot;
    }

    public int SymBitsQ(int sym) => _symBitsQ[sym];

    public static TansTable Build(int[] rawFreq, int L)
    {
        int ns=rawFreq.Length;
        var f=Norm(rawFreq,ns,L);
        var cum=new int[ns+1];
        for(int i=0;i<ns;i++) cum[i+1]=cum[i]+f[i];

        var symBitsQ = new int[ns];
        for (int s = 0; s < ns; s++)
        {
            int smaxQ = (L * 2 - 1) / f[s];
            int sb = 1;
            while ((1 << sb) <= smaxQ) sb++;
            symBitsQ[s] = sb;
        }

        var symOfSlot = new int[L];
        int symC = 0;
        for (int slot = 0; slot < L; slot++)
        {
            while (cum[symC + 1] <= slot) symC++;
            symOfSlot[slot] = symC;
        }

        int minFs = f.Min();
        int maxQ = (L*2-1)/minFs;
        int bitsQ = 1;
        while ((1<<bitsQ) <= maxQ) bitsQ++;

        return new TansTable(L,ns,bitsQ,cum,f,symBitsQ,symOfSlot);
    }

    private static int[] Norm(int[] raw,int ns,int L)
    {
        var f=new int[ns]; long tot=0;
        for(int i=0;i<ns;i++){f[i]=Math.Max(raw[i],1);tot+=f[i];}
        for(int i=0;i<ns;i++){f[i]=(int)(f[i]*L/tot);if(f[i]<1)f[i]=1;}
        long sm=0;for(int i=0;i<ns;i++)sm+=f[i];
        int d=(int)(L-sm);
        for(int i=0;d>0;i=(i+1)%ns,d--) f[i]++;
        for(int i=0;d<0;i=(i+1)%ns){if(f[i]>1){f[i]--;d++;}}
        return f;
    }

    public int GetSymbol(int st) => _symOfSlot[st - _L];

    public (int next, int qVal) Encode(int st, int sym)
    {
        if (st < _L || st >= _L*2) st = _L;
        int fs = _f[sym];
        int cs = _cum[sym];
        int q = st / fs;
        int r = st - q * fs;
        int nx = _L + r + cs;
        return (nx, q);
    }

    public bool TryDecode(int st, int qVal, out int prev)
    {
        if (st < _L || st >= _L * 2) { prev = _L; return false; }
        int sym = _symOfSlot[st - _L];
        int fs = _f[sym];
        int cs = _cum[sym];
        int r = st - _L - cs;
        prev = qVal * fs + r;
        return prev >= _L && prev < _L * 2;
    }
}
