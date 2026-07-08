using System.IO.Hashing;

string testFile = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "..", "tests", "RDRF_TestInput"));
if (!Directory.Exists(testFile)) { Console.Error.WriteLine($"Test input dir not found: {testFile}"); return; }
var tfs = Directory.GetFiles(testFile);
testFile = tfs.Length > 0 ? tfs[0] : (Console.Error.WriteLine("No test files in RDRF_TestInput"), "");
int blockSize = 1024;
int regionSize = 32;
int sampleBits = 4;
int trials = 5;
string outBase = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "..", "tests", "RDRF_TestOutput", "duip_sim");

for (int i = 0; i < args.Length; i++)
{
    if (args[i] == "-r" && i + 1 < args.Length) regionSize = int.Parse(args[++i]);
    else if (args[i] == "-b" && i + 1 < args.Length) sampleBits = int.Parse(args[++i]);
    else if (args[i] == "-t" && i + 1 < args.Length) trials = int.Parse(args[++i]);
}
if (Directory.Exists(outBase)) { Directory.Delete(outBase, true); }
Directory.CreateDirectory(outBase);

byte[] fileData = File.ReadAllBytes(testFile);
int K = (fileData.Length + blockSize - 1) / blockSize;
var source = new byte[K][];
for (int i = 0; i < K; i++)
{
    source[i] = new byte[blockSize];
    Array.Copy(fileData, i * blockSize, source[i], 0, Math.Min(blockSize, fileData.Length - i * blockSize));
}

ulong XorShift64(ref ulong s) { s ^= s >> 12; s ^= s << 25; s ^= s >> 27; return s * 2685821657736338717UL; }
int Prng(ref ulong s, int mod) => (int)((XorShift64(ref s) >> 32) & 0x7FFFFFFF) % Math.Max(1, mod);

int regCnt = (K + regionSize - 1) / regionSize;
byte[][] regEnt = new byte[regCnt][];
for (int ri = 0; ri < regCnt; ri++)
{
    int s = ri * regionSize, e = Math.Min(s + regionSize, K);
    var xa = new byte[64];
    for (int si = s; si < e; si++)
        for (int b = 0; b < 64; b++) xa[b] ^= source[si][b];
    regEnt[ri] = XxHash64.Hash(xa.AsSpan());
}

int EntDeg(byte[] ent, int off) => (ent[off % ent.Length] & ((1 << sampleBits) - 1)) switch
{
    < 2 => 2, < 6 => 3, < 10 => 4, < 14 => 5, _ => 6
};
int RevDeg(int d) => Math.Max(2, Math.Min(8, 10 - d));

(int[][] symIdx, int[] coverage) BuildSymbols(double ratio)
{
    var cov = new int[K];
    int R = Math.Max(4, (int)(K * ratio));
    int r1 = (int)(R * 0.40), r2a = (int)(R * 0.25), r2b = (int)(R * 0.25), r3 = 1;
    int totalR = r1 + r2a + r2b + r3;
    var symIdx = new int[totalR][];
    ulong seed = 42;
    int pos = 0;

    void GenLayer(int cnt, Func<int> degFn)
    {
        for (int si = 0; si < cnt; si++)
        {
            int d = degFn(); if (d > K) d = K;
            var used = new HashSet<int>();
            int best = 0, bv = int.MaxValue;
            for (int c = 0; c < K; c++) if (cov[c] < bv) { bv = cov[c]; best = c; }
            used.Add(best); cov[best]++;

            while (used.Count < d && used.Count < K)
            {
                int col;
                int uc = 0; for (int c = 0; c < K; c++) if (cov[c] < 2 && !used.Contains(c)) uc++;
                if (Prng(ref seed, 3) > 0 && uc > 0)
                {
                    int pk = Prng(ref seed, uc);
                    for (int c = 0; c < K; c++) if (cov[c] < 2 && !used.Contains(c) && pk-- == 0) { col = c; goto add; }
                }
                col = Prng(ref seed, K);
            add:
                if (used.Add(col)) cov[col]++;
            }
            symIdx[pos++] = used.ToArray();
        }
    }

    GenLayer(r1, () => { int col = Prng(ref seed, K); return EntDeg(regEnt[col / regionSize], col); });
    GenLayer(r2a, () =>
    {
        int mr = 0, mc = int.MaxValue;
        for (int ri = 0; ri < regCnt; ri++)
        {
            int cc = 0;
            for (int ci = ri * regionSize; ci < Math.Min(K, ri * regionSize + regionSize); ci++) cc += cov[ci];
            if (cc < mc) { mc = cc; mr = ri; }
        }
        return RevDeg(EntDeg(regEnt[Math.Min(mr, regCnt - 1)], mr));
    });
    GenLayer(r2b, () => { int ri = Prng(ref seed, Math.Max(1, regCnt / 3)); return EntDeg(regEnt[ri], ri); });
    if (pos < totalR) symIdx[pos++] = Enumerable.Range(0, K).ToArray();
    return (symIdx, cov);
}

(int recovered, int totalLost, int rounds, int nAfterBP) DuipDecode(int[][] symIdx, double lossRate, int seed)
{
    var rng = new Random(seed);
    bool[] known = new bool[K];
    int lost = 0;
    for (int c = 0; c < K; c++)
        if (rng.NextDouble() < lossRate) { lost++; } else { known[c] = true; }
    if (lost == 0) return (0, 0, 0, 0);

    int totalR = symIdx.Length;
    var rep = new byte[totalR][];
    for (int si = 0; si < totalR; si++)
    {
        rep[si] = new byte[blockSize];
        foreach (int c in symIdx[si])
            for (int b = 0; b < blockSize; b++) rep[si][b] ^= source[c][b];
    }
    var allSymIdx = new List<int[]>(symIdx);
    var allRep = new List<byte[]>(rep);

    int recovered = 0;
    int rounds = 0;

    // BP loop
    {
        int Rcur = allRep.Count;
        var remDeg = new int[Rcur];
        var queue = new Queue<int>();
        for (int si = 0; si < Rcur; si++)
        {
            int deg = allSymIdx[si].Length;
            int kc = 0;
            foreach (int c in allSymIdx[si]) if (c < K && known[c]) kc++;
            remDeg[si] = deg - kc;
            if (remDeg[si] == 1) queue.Enqueue(si);
        }

        while (queue.Count > 0)
        {
            rounds++;
            int si = queue.Dequeue();
            if (remDeg[si] != 1) continue;
            int target = -1;
            foreach (int c in allSymIdx[si]) if (c < K && !known[c]) { target = c; break; }
            if (target < 0) continue;
            Array.Copy(allRep[si], 0, source[target], 0, blockSize);
            known[target] = true; recovered++;
            for (int sj = 0; sj < Rcur; sj++)
            {
                bool hit = false;
                foreach (int c in allSymIdx[sj]) if (c == target) { hit = true; break; }
                if (!hit) continue;
                for (int b = 0; b < blockSize; b++) allRep[sj][b] ^= source[target][b];
                remDeg[sj]--;
                if (remDeg[sj] == 1) queue.Enqueue(sj);
            }
        }
    }

    // Global
    if (recovered < lost)
    {
        int ks = 0; int miss = -1;
        for (int c = 0; c < K; c++) if (known[c]) ks++; else miss = c;
        if (ks == K - 1 && miss >= 0)
        {
            int gsi = allSymIdx.Count - 1;
            var gd = new byte[blockSize];
            Array.Copy(allRep[gsi], gd, blockSize);
            for (int c = 0; c < K; c++) if (known[c])
                for (int b = 0; b < blockSize; b++) gd[b] ^= source[c][b];
            Array.Copy(gd, 0, source[miss], 0, blockSize);
            known[miss] = true; recovered++;
        }
    }

    // Small matrix (remaining N <= 3)
    if (recovered < lost)
    {
        int Nremain = lost - recovered;
        if (Nremain <= 3)
        {
            int Rcur = allRep.Count;
            var remDeg = new int[Rcur];
            for (int si = 0; si < Rcur; si++)
            {
                int d = allSymIdx[si].Length;
                int kc = 0;
                foreach (int c in allSymIdx[si]) if (c < K && known[c]) kc++;
                remDeg[si] = d - kc;
            }

            var stuckRows = new List<(int si, int[] cols)>();
            for (int si = 0; si < Rcur; si++)
            {
                if (remDeg[si] < 2) continue;
                var ucols = new List<int>();
                foreach (int c in allSymIdx[si]) if (c < K && !known[c]) ucols.Add(c);
                if (ucols.Count >= 2) stuckRows.Add((si, ucols.ToArray()));
            }

            if (stuckRows.Count >= Nremain + 2)
            {
                var unkList = new List<int>();
                for (int c = 0; c < K; c++) if (!known[c]) unkList.Add(c);
                var colToIdx = new Dictionary<int, int>();
                for (int i = 0; i < unkList.Count; i++) colToIdx[unkList[i]] = i;
                int nMat = unkList.Count;
                if (nMat <= 3 && stuckRows.Count >= nMat + 2)
                {
                    int rc = Math.Min(stuckRows.Count, nMat + 4);
                    var work = new byte[rc][];
                    for (int ri = 0; ri < rc; ri++)
                    {
                        work[ri] = new byte[nMat + blockSize];
                        var (si, cols) = stuckRows[ri];
                        foreach (int t in cols)
                            if (colToIdx.TryGetValue(t, out int ci) && ci < nMat) work[ri][ci] = 1;
                        for (int b = 0; b < blockSize; b++) work[ri][nMat + b] = allRep[si][b];
                    }

                    bool solved = true;
                    for (int col = 0; col < nMat; col++)
                    {
                        int pivot = -1;
                        for (int r = col; r < rc; r++) if (work[r][col] != 0) { pivot = r; break; }
                        if (pivot < 0) { solved = false; break; }
                        (work[col], work[pivot]) = (work[pivot], work[col]);
                        for (int r = 0; r < rc; r++)
                        {
                            if (r == col || work[r][col] == 0) continue;
                            for (int j = col; j < nMat + blockSize; j++)
                                work[r][j] ^= work[col][j];
                        }
                    }

                    if (solved)
                    {
                        for (int i = 0; i < nMat; i++)
                        {
                            int col_ = unkList[i];
                            if (!known[col_])
                            {
                                var rd = new byte[blockSize];
                                Buffer.BlockCopy(work[i], nMat, rd, 0, blockSize);
                                Array.Copy(rd, 0, source[col_], 0, blockSize);
                                known[col_] = true; recovered++;
                            }
                        }
                    }
                }
            }
        }
    }

    return (recovered, lost, rounds, lost - recovered);
}

// -- Run --
var ratios = new[] { 0.10, 0.15, 0.20, 0.25, 0.30, 0.40, 0.50, 0.60, 0.75, 1.0 };
var lossRates = new[] { 0.05, 0.10, 0.15, 0.20, 0.30, 0.50, 0.70, 0.80, 0.85, 0.90, 0.95, 0.97, 0.99 };
var csv = new List<string> { "ratio,loss_pct,trial,recovered,lost,pct,rounds,n_after_bp" };

Console.Error.WriteLine($"Duip B+C (no P4): K={K} region={regionSize} bits={sampleBits} trials={trials}");

foreach (var ratio in ratios)
{
    var (symIdx, cov) = BuildSymbols(ratio);
    var cl = cov.ToList(); cl.Sort();
    foreach (var loss in lossRates)
    {
        int totalRec = 0, totalLost = 0;
        for (int t = 0; t < trials; t++)
        {
            var (rec, lost, rds, nBP) = DuipDecode(symIdx, loss, t * 113 + (int)(loss * 997));
            totalRec += rec; totalLost += lost;
            double pct = lost > 0 ? (double)rec / lost * 100 : 100;
            csv.Add($"{ratio:F3},{loss * 100:F0},{t},{rec},{lost},{pct:F1},{rds},{nBP}");
        }
        double avgPct = totalLost > 0 ? (double)totalRec / totalLost * 100 : 100;
        Console.WriteLine($"  ratio={ratio:F2} loss={loss*100:F0}%  recovery={avgPct:F1}% ({totalRec}/{totalLost})");
    }
}

string ts = DateTime.Now.ToString("yyyyMMdd_HHmmss");
string csvPath = Path.Combine(outBase, $"duip_{ts}_noP4.csv");
File.WriteAllLines(csvPath, csv);
Console.WriteLine($"\nCSV: {csvPath}");
