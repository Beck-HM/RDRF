using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.ETN;
using RDRF.Core.FSS;
using RDRF.Core.Index;
using RDRF.Core.Dssa;

string testFile = args.Length > 0 && File.Exists(args[0])
    ? args[0]
    : Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "..", "tests", "2.mp4"));
if (!File.Exists(testFile)) { Console.Error.WriteLine($"File not found: {testFile}"); return 1; }

byte[] originalHash = SHA256.HashData(File.ReadAllBytes(testFile));
int fragSize = 256 * 1024;

string[] strategies = { "FSS6.1", "FSS6.2" };
double[] ratios = { 0.5, 1.0, 2.0 };

// Parse flags
for (int ai = 0; ai < args.Length; ai++)
{
    if ((args[ai] == "-r" || args[ai] == "--ratio") && ai + 1 < args.Length)
        ratios = args[++ai].Split(',', StringSplitOptions.TrimEntries)
            .Select(double.Parse).ToArray();
    if (args[ai] == "-m")
        DuipCode.EnableMultiPass = true;
}

foreach (double ratio in ratios)
{
    LtCode.RepairRatio = ratio;
    DuipCode.RepairRatio = ratio;

    foreach (string strategy in strategies)
    {
        string pwd = strategy == "FSS6.1" ? "fss61_test" : "fss62_test";
        byte[] rcMaster = Encoding.UTF8.GetBytes(pwd);

        string resultDir = Path.Combine(@"F:\RDRF\RDRF.NET\tests\RDRF_TestOutput",
            $"lt_{strategy.Replace(".", "_")}_r{ratio:F1}_{Guid.NewGuid():N}");
        Directory.CreateDirectory(resultDir);
        // Don't print resultDir per test, we'll aggregate

        // ──── Backup ────
        var storage = new LocalDssaAdapter(resultDir);
        string fingerprint;
        using (var engine = new RDRFEngine(rcMaster, storage))
            fingerprint = engine.BackupFile(testFile, strategy, fragmentSize: fragSize);

    byte[] encIndex = storage.ReadIndex(fingerprint);
    var (aesKey, idxCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encIndex, rcMaster);
    var index = IndexManager.DeserializeIndex(idxCbor);
    string prefix = index.CustomName ?? fingerprint;
    int totalFrags = index.FragmentCount;

    Console.WriteLine($"Backup: {totalFrags} fragments, strategy={index.FssStrategy}");

    // ──── Pre-load ────
    var allFragBytes = new byte[totalFrags][];
    for (int i = 0; i < totalFrags; i++)
        allFragBytes[i] = File.ReadAllBytes(Path.Combine(resultDir, $"{prefix}_{i}.rdrf"));
    byte[] idxBytes = File.ReadAllBytes(Path.Combine(resultDir, $"{prefix}.indrdrf"));

    // Block size from RC
    int blockSize = 512;
    string rcPath = Path.Combine(resultDir, $"{prefix}.rdrc");
    if (File.Exists(rcPath))
    {
        byte[] encRc = File.ReadAllBytes(rcPath);
        byte[] rcDec = EncryptionLayer.DecryptFragmentWithKey(encRc, aesKey);
        var rcFile = RcFile.FromCbor(rcDec);
        if (rcFile.RepairB?.BlockSize > 0)
            blockSize = rcFile.RepairB.BlockSize;
        else if (rcFile.Repair62B?.BlockSize > 0)
            blockSize = rcFile.Repair62B.BlockSize;
    }
    Console.WriteLine($"Block size: {blockSize}");

    bool is62 = strategy == "FSS6.2";

    int[] blocksPerFrag = new int[totalFrags];
    int totalBlocks = 0;
    int[] fragDataStart = new int[totalFrags];

    for (int i = 0; i < totalFrags; i++)
    {
        byte[] encrypted = allFragBytes[i];
        int hdrSize = FragmentFileHeader.GetTotalHeaderSize(encrypted);
        byte[] decrypted = EncryptionLayer.DecryptFragmentCtrWithKey(encrypted, hdrSize, aesKey);
        int idxLen = BitConverter.ToInt32(decrypted.AsSpan(0, 4));

        // Raw data starts after the embedded index; its length is always fragSize(262144)
        blocksPerFrag[i] = (fragSize + blockSize - 1) / blockSize;
        totalBlocks += blocksPerFrag[i];
        fragDataStart[i] = hdrSize + 12 + 4 + idxLen;
    }

    Console.WriteLine($"Total blocks: {totalBlocks}, blockSize={blockSize}");

    int[] cumBlocks = new int[totalFrags + 1];
    for (int i = 0; i < totalFrags; i++)
        cumBlocks[i + 1] = cumBlocks[i] + blocksPerFrag[i];

    Console.WriteLine($"==== {strategy} Block Corruption Test ====");

    // Parse args
    var (corruptPcts, trials) = ParseArgs(args);
    if (corruptPcts.Length == 0) corruptPcts = [10, 30, 50, 70, 80, 85, 90, 95, 97, 98, 99, 100];
    if (trials <= 0) trials = 3;

    Console.WriteLine($"Corruption set: [{string.Join(", ", corruptPcts)}] Trials: {trials}");

    var csv = new List<string> { "strategy,corrupt_pct,blocks_corrupted,blocks_total,trial,recovered,sha_match,time_ms" };
    int maxSurvived = 0, minFailed = int.MaxValue;

    foreach (int cpct in corruptPcts)
    {
        int blocksToCorrupt = Math.Max(1, totalBlocks * cpct / 100);
        if (blocksToCorrupt >= totalBlocks) blocksToCorrupt = totalBlocks - 1;

        for (int t = 0; t < trials; t++)
        {
            var trialDir = Path.Combine(resultDir, $"corrupt_{cpct}_{t}");
            Directory.CreateDirectory(trialDir);
            File.WriteAllBytes(Path.Combine(trialDir, $"{prefix}.indrdrf"), idxBytes);
            string rcP = Path.Combine(resultDir, $"{prefix}.rdrc");
            if (File.Exists(rcP))
                File.WriteAllBytes(Path.Combine(trialDir, $"{prefix}.rdrc"), File.ReadAllBytes(rcP));

            var rng = new Random(42 + t * 100 + cpct);
            var badBlocks = new HashSet<int>();
            while (badBlocks.Count < blocksToCorrupt)
                badBlocks.Add(rng.Next(totalBlocks));

            var fragCorrupt = new Dictionary<int, byte[]>();
            foreach (int bi in badBlocks)
            {
                int fi = 0;
                while (fi < totalFrags && bi >= cumBlocks[fi + 1]) fi++;
                int localBlock = bi - cumBlocks[fi];
                int fragByteOff = localBlock * blockSize;

                if (!fragCorrupt.ContainsKey(fi))
                    fragCorrupt[fi] = (byte[])allFragBytes[fi].Clone();
                byte[] corruptCopy = fragCorrupt[fi];
                int fileOff = fragDataStart[fi] + fragByteOff;

                if (fileOff < corruptCopy.Length)
                {
                    int maxOff = Math.Min(blockSize, corruptCopy.Length - fileOff);
                    int xorOff = rng.Next(maxOff);
                    corruptCopy[fileOff + xorOff] ^= (byte)(1 + rng.Next(254));
                }
            }
            foreach (var kv in fragCorrupt)
                File.WriteAllBytes(Path.Combine(trialDir, $"{prefix}_{kv.Key}.rdrf"), kv.Value);

            var trialStorage = new LocalDssaAdapter(trialDir);
            string outPath = Path.Combine(trialDir, "restored.bin");
            bool hasRb = is62
                ? IndexManager.DeserializeIndex(idxCbor)?.Fss62RepairB != null
                : IndexManager.DeserializeIndex(idxCbor)?.Fss61RepairB != null;

            bool rcExists = File.Exists(Path.Combine(trialDir, $"{prefix}.rdrc"));
            bool frag0Exists = File.Exists(Path.Combine(trialDir, $"{prefix}_0.rdrf"));

            var sw = Stopwatch.StartNew();
            bool recovered;
            try
            {
                using (var r = new RestoreOrchestrator(aesKey, rcMaster, trialStorage))
                    recovered = r.RestoreFileAsync(fingerprint, outPath).GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"  [ERR] {ex.GetType().Name}: {ex.Message}");
                recovered = false;
            }
            sw.Stop();

            bool shaOk = recovered && File.Exists(outPath) && VerifySha(outPath, originalHash);
            bool ok = recovered && shaOk;
            long outSize = File.Exists(outPath) ? new FileInfo(outPath).Length : -1;
            Console.Error.WriteLine($"  [TIME] {cpct}% corrupt: {sw.ElapsedMilliseconds}ms  ok={ok} rcvd={recovered} shaOk={shaOk} outSize={outSize} expected={new FileInfo(testFile).Length}");

            csv.Add($"{strategy},{cpct},{blocksToCorrupt},{totalBlocks},{t},{ok},{shaOk},{sw.ElapsedMilliseconds}");
            if (ok && cpct > maxSurvived) maxSurvived = cpct;
            if (!ok && cpct < minFailed) minFailed = cpct;
        }
    }

    Console.WriteLine($"==== {strategy} Repair Strength (blockSize={blockSize}) ====");
    Console.WriteLine($"Total blocks: {totalBlocks}");
    Console.WriteLine($"Max survived: {maxSurvived}%  |  Min failed: {(minFailed > 100 ? "none" : minFailed + "%")}");
    Console.WriteLine();
    Console.Write("Corrupt%    ");
    foreach (int cp in corruptPcts) Console.Write($"  {cp,3}%  ");
    Console.WriteLine();
    Console.Write("Bad blocks  ");
    foreach (int cp in corruptPcts)
    {
        int b = Math.Max(1, totalBlocks * cp / 100);
        if (b >= totalBlocks) b = totalBlocks - 1;
        Console.Write($" {b,5} ");
    }
    Console.WriteLine();
    Console.Write("Pass rate   ");
    foreach (int cp in corruptPcts)
    {
        int pass = 0;
        for (int t = 0; t < trials; t++)
        {
            int b = Math.Max(1, totalBlocks * cp / 100);
            if (b >= totalBlocks) b = totalBlocks - 1;
            var m = csv.FirstOrDefault(l => l.StartsWith($"{strategy},{cp},{b},"));
            if (m != null) { var p = m.Split(','); if (p[5] == "True") pass++; }
        }
        Console.Write(pass == trials ? "  3/3 " : pass >= 2 ? "  2/3 " : pass >= 1 ? "  1/3 " : "  0/3 ");
    }
    Console.WriteLine();
    Console.Write("SHA match   ");
    foreach (int cp in corruptPcts)
    {
        int match = 0;
        for (int t = 0; t < trials; t++)
        {
            int b = Math.Max(1, totalBlocks * cp / 100);
            if (b >= totalBlocks) b = totalBlocks - 1;
            var m = csv.FirstOrDefault(l => l.StartsWith($"{strategy},{cp},{b},"));
            if (m != null) { var p = m.Split(','); if (p[6] == "True") match++; }
        }
        Console.Write(match == 3 ? "  3/3 " : match >= 2 ? "  2/3 " : match >= 1 ? "  1/3 " : "  0/3 ");
    }
    Console.WriteLine();
    Console.WriteLine(new string('-', 70));
    Console.WriteLine($"Legend: 3/3= {trials}/{trials}");
    Console.WriteLine($"Threshold: <={maxSurvived}% OK, >={minFailed}% FAIL");

    // Collect file sizes before cleanup
    var f0 = new FileInfo(Path.Combine(resultDir, $"{prefix}_0.rdrf"));
    var idx = new FileInfo(Path.Combine(resultDir, $"{prefix}.indrdrf"));
    var rc = new FileInfo(Path.Combine(resultDir, $"{prefix}.rdrc"));
    Console.WriteLine($"Size: frag={f0.Length,10:N0} idx={idx.Length,10:N0} rc={rc.Length,10:N0}");

    try { Directory.Delete(resultDir, true); }
    catch (Exception ex) { Console.Error.WriteLine($"Cleanup failed: {ex.Message}"); }
}
}
Console.WriteLine("\nDone.");
return 0;

static bool VerifySha(string filePath, byte[] expectedHash)
{
    try
    {
        byte[] actual = SHA256.HashData(File.ReadAllBytes(filePath));
        return CryptographicOperations.FixedTimeEquals(actual, expectedHash);
    }
    catch { return false; }
}

static (int[] pcts, int tcount) ParseArgs(string[] a)
{
    var set = new List<int>();
    int tc = 3;
    for (int i = 0; i < a.Length; i++)
    {
        if (a[i] == "-set" && i + 1 < a.Length)
        {
            foreach (string part in a[++i].Split('&', StringSplitOptions.TrimEntries))
            {
                if (part.Contains('-'))
                {
                    var seg = part.Split('/');
                    var se = seg[0].Split('-');
                    int lo = int.Parse(se[0]), hi = int.Parse(se[1]);
                    int step = seg.Length > 1 ? int.Parse(seg[1]) : 1;
                    for (int v = lo; v <= hi; v += step) set.Add(v);
                }
                else
                {
                    foreach (var v in part.Split(',', StringSplitOptions.TrimEntries))
                        if (int.TryParse(v, out int n)) set.Add(n);
                }
            }
        }
        else if (a[i] == "-trials" && i + 1 < a.Length)
            tc = int.Parse(a[++i]);
    }
    return (set.Distinct().OrderBy(x => x).ToArray(), tc);
}