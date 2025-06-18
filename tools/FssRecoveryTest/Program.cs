using System.Diagnostics;
using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.FSS;
using RDRF.Core.Index;
using RDRF.Core.Storage;

string testFile = args.Length > 0 && File.Exists(args[0])
    ? args[0]
    : Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "..", "tests", "1.mp4"));

if (!File.Exists(testFile))
{
    Console.Error.WriteLine($"Test file not found: {testFile}");
    return 1;
}

long fileSize = new FileInfo(testFile).Length;
byte[] originalHash = SHA256.HashData(File.ReadAllBytes(testFile));
int fragSize = 256 * 1024;

string[] strategies = ["FSS1", "FSS2", "FSS2R", "FSS3", "FSS5", "FSS5+", "FSS6", "FSS6.1"];
string testsDir = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "..", "tests", "tests"));
string resultDir = Path.Combine(testsDir, $"FssRecovery_{Guid.NewGuid():N}");
Directory.CreateDirectory(resultDir);

var csv = new List<string>
{
    "strategy,test_type,loss_pct,trial,frags_total,frags_lost,recovered,sha256_match,time_ms,notes"
};
var summaryRows = new List<SummaryRow>();

Console.ForegroundColor = ConsoleColor.Cyan;
Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
Console.WriteLine("║         FSS Recovery Test —  All Strategies                ║");
Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
Console.ResetColor();
Console.WriteLine($"  Test file: {testFile} ({fileSize:N0} bytes)");
Console.WriteLine($"  Fragment size: {fragSize:N0} bytes");
Console.WriteLine($"  Result dir: {resultDir}");
Console.WriteLine();

foreach (string strategy in strategies)
{
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine($"── [{strategy}] ──");
    Console.ResetColor();

    var testRoot = Path.Combine(resultDir, strategy);
    Directory.CreateDirectory(testRoot);
    var storage = new LocalFileAdapter(testRoot);
    byte[] password = EncryptionLayer.GenerateRcCode(32);
    byte[] rcMaster = (byte[])password.Clone();
    byte[] rcClone() => (byte[])rcMaster.Clone();

    string fingerprint;
    var sw = Stopwatch.StartNew();
    using (var engine = new RDRFEngine(password, storage))
        fingerprint = engine.BackupFile(testFile, strategy, fragmentSize: fragSize);
    sw.Stop();
    double backupTime = sw.Elapsed.TotalMilliseconds;

    byte[] encIndex = storage.ReadIndex(fingerprint);
    var (aesKey, idxCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encIndex, rcClone());
    var index = IndexManager.DeserializeIndex(idxCbor);
    string prefix = index.CustomName ?? fingerprint;
    int totalFrags = index.FragentCount;
    int origCount = index.OriginalFragentCount > 0 ? index.OriginalFragentCount : totalFrags;

    int baseFrags = origCount;
    Console.WriteLine($"  Backup: {totalFrags} total frags ({origCount} original, sizes={index.OriginalFragentSizes.Count})");
    Console.WriteLine($"  Time: {backupTime:F0}ms");

    // ── Baseline ──
    bool baselineOk = false;
    sw.Restart();
    string baseOut = Path.Combine(testRoot, "baseline_restored.bin");
    using (var restore = new RestoreOrchestrator(rcClone(), storage))
        baselineOk = restore.RestoreFileAsync(fingerprint, baseOut).GetAwaiter().GetResult();
    double baseTime = sw.Elapsed.TotalMilliseconds;

    bool baseShaOk = VerifySha(baseOut, originalHash);
    if (File.Exists(baseOut)) File.Delete(baseOut);

    csv.Add($"\"{strategy}\",baseline,0,0,{totalFrags},0,{baselineOk},{baseShaOk},{baseTime:F0},\"baseline\"");
    Console.WriteLine($"  Baseline: {(baselineOk && baseShaOk ? "PASS" : "FAIL")} ({baseTime:F0}ms)");

    if (!baselineOk || !baseShaOk)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"  SKIP {strategy}: baseline failed");
        Console.ResetColor();
        continue;
    }

    // ── Incremental loss ──
    var incResults = new List<(double lossPct, int trial, bool ok)>();
    int[] lossPcts = strategy is "FSS3" or "FSS6" or "FSS6.1"
        ? [5, 10, 15, 20, 30]
        : [5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70, 75, 80, 85, 90];

    // Pre-load all fragment bytes + index bytes to avoid file-system issues
    var allFragBytes = new byte[totalFrags][];
    for (int i = 0; i < totalFrags; i++)
        allFragBytes[i] = File.ReadAllBytes(Path.Combine(testRoot, $"{prefix}_{i}.rdrf"));
    byte[] idxBytes = File.ReadAllBytes(Path.Combine(testRoot, $"{prefix}.indrdrf"));

    void WriteTrialDir(string dir, HashSet<int>? excludeFrags)
    {
        File.WriteAllBytes(Path.Combine(dir, $"{prefix}.indrdrf"), idxBytes);
        for (int i = 0; i < totalFrags; i++)
            if (excludeFrags == null || !excludeFrags.Contains(i))
                File.WriteAllBytes(Path.Combine(dir, $"{prefix}_{i}.rdrf"), allFragBytes[i]);
        string rcP = Path.Combine(testRoot, $"{prefix}.rdrc");
        if (File.Exists(rcP))
            File.WriteAllBytes(Path.Combine(dir, $"{prefix}.rdrc"), File.ReadAllBytes(rcP));
        string metaP = Path.Combine(testRoot, "rdrf_metadata.json");
        if (File.Exists(metaP))
            File.WriteAllBytes(Path.Combine(dir, "rdrf_metadata.json"), File.ReadAllBytes(metaP));
    }

        foreach (int lossPct in lossPcts)
        {
            int fragsToDelete = (int)Math.Ceiling(totalFrags * lossPct / 100.0);
            fragsToDelete = Math.Min(fragsToDelete, totalFrags - 1);

            for (int trial = 0; trial < 3; trial++)
        {
            var trialDir = Path.Combine(testRoot, $"inc_{lossPct}_{trial}");
            Directory.CreateDirectory(trialDir);

            // Write index once
            File.WriteAllBytes(Path.Combine(trialDir, $"{prefix}.indrdrf"), idxBytes);

            // Write only the fragments that survive (pre-delete)
            var rand = new Random(42 + trial * 100 + lossPct);
            var toDelete = new HashSet<int>();
            while (toDelete.Count < fragsToDelete)
                toDelete.Add(rand.Next(totalFrags));

            if (lossPct == lossPcts[0] && trial == 0)
                Console.WriteLine($"  Deleted: [{string.Join(",", toDelete)}]");

            for (int i = 0; i < totalFrags; i++)
                if (!toDelete.Contains(i))
                    File.WriteAllBytes(Path.Combine(trialDir, $"{prefix}_{i}.rdrf"), allFragBytes[i]);
            // NOTE: deleted fragments are NOT written at all → file doesn't exist

            // Also copy the .rdrc file if present (needed for ETN cross-validation)
            string rcSrcP = Path.Combine(testRoot, $"{prefix}.rdrc");
            if (File.Exists(rcSrcP))
                File.WriteAllBytes(Path.Combine(trialDir, $"{prefix}.rdrc"), File.ReadAllBytes(rcSrcP));

            var trialStorage = new LocalFileAdapter(trialDir);
            string trialOut = Path.Combine(trialDir, "restored.bin");

            if (lossPct == lossPcts[0] && trial == 0)
            {
                Console.WriteLine($"  Trial0 test: storage base={trialStorage.GetBasePath()}");
                Console.WriteLine($"  Trial0 test: index exists={trialStorage.IndexExists(fingerprint)}");
            }

            sw.Restart();
            bool recovered;
            using (var r = new RestoreOrchestrator(rcClone(), trialStorage))
                recovered = r.RestoreFileAsync(fingerprint, trialOut).GetAwaiter().GetResult();
            double t = sw.Elapsed.TotalMilliseconds;

            bool shaOk = false;
            if (recovered && File.Exists(trialOut))
                shaOk = VerifySha(trialOut, originalHash);

            double actualPct = (double)fragsToDelete / totalFrags * 100;
            csv.Add($"\"{strategy}\",incremental,{actualPct:F1},{trial},{totalFrags},{fragsToDelete},{recovered},{shaOk},{t:F0},\"\"");
            incResults.Add((actualPct, trial, recovered && shaOk));
        }
    }

    // ── Greedy test (流程一): from i=0..N-1, delete each, recover, keep if ok, skip if fail ──
    var greedyDir = Path.Combine(testRoot, "greedy");
    Directory.CreateDirectory(greedyDir);
    var greedyKept = new HashSet<int>();
    for (int i = 0; i < totalFrags; i++)
    {
        var td = Path.Combine(greedyDir, $"try_{i}");
        Directory.CreateDirectory(td);
        WriteTrialDir(td, null);
        var toDel = new HashSet<int>(greedyKept) { i };
        foreach (int d in toDel)
            File.Delete(Path.Combine(td, $"{prefix}_{d}.rdrf"));

        var ts = new LocalFileAdapter(td);
        string outPath = Path.Combine(td, "restored.bin");
        sw.Restart();
        bool r = false;
        try
        {
            using (var ro = new RestoreOrchestrator(rcClone(), ts))
                r = ro.RestoreFileAsync(fingerprint, outPath).GetAwaiter().GetResult();
        }
        catch
        {
            // expected when all fragments are deleted
        }
        double t = sw.Elapsed.TotalMilliseconds;
        bool sha = r && File.Exists(outPath) && VerifySha(outPath, originalHash);
        bool ok = r && sha;
        csv.Add($"\"{strategy}\",greedy,{(double)toDel.Count/totalFrags*100:F1},{i},{totalFrags},{toDel.Count},{r},{sha},{t:F0},\"greedy_try_{i}\"");
        if (ok) { greedyKept.Add(i); }
    }
    double greedyStrength = (double)greedyKept.Count / totalFrags * 100;
    Console.WriteLine($"  Greedy: max deleted {greedyKept.Count}/{totalFrags} = {greedyStrength:F1}%");

    // ── Custom tests (流程二): strategy-specific targeted patterns ──
    var customResults = new List<(string name, double lossPct, bool ok)>();

    if (strategy is "FSS1" or "FSS2" or "FSS2R")
    {
        // Even indices
        var eDir = Path.Combine(testRoot, "custom_even");
        Directory.CreateDirectory(eDir);
        WriteTrialDir(eDir, null);
        int eDel = 0;
        for (int i = 0; i < totalFrags; i += 2)
        { File.Delete(Path.Combine(eDir, $"{prefix}_{i}.rdrf")); eDel++; }
        var eTs = new LocalFileAdapter(eDir);
        sw.Restart();
        bool eR;
        using (var ro = new RestoreOrchestrator(rcClone(), eTs))
            eR = ro.RestoreFileAsync(fingerprint, Path.Combine(eDir, "restored.bin")).GetAwaiter().GetResult();
        bool eSha = eR && VerifySha(Path.Combine(eDir, "restored.bin"), originalHash);
        csv.Add($"\"{strategy}\",custom_even,{(double)eDel/totalFrags*100:F1},0,{totalFrags},{eDel},{eR},{eSha},{sw.Elapsed.TotalMilliseconds:F0},\"delete_even\"");
        customResults.Add(("even", (double)eDel / totalFrags * 100, eR && eSha));

        // Odd indices
        var oDir = Path.Combine(testRoot, "custom_odd");
        Directory.CreateDirectory(oDir);
        WriteTrialDir(oDir, null);
        int oDel = 0;
        for (int i = 1; i < totalFrags; i += 2)
        { File.Delete(Path.Combine(oDir, $"{prefix}_{i}.rdrf")); oDel++; }
        var oTs = new LocalFileAdapter(oDir);
        sw.Restart();
        bool oR;
        using (var ro = new RestoreOrchestrator(rcClone(), oTs))
            oR = ro.RestoreFileAsync(fingerprint, Path.Combine(oDir, "restored.bin")).GetAwaiter().GetResult();
        bool oSha = oR && VerifySha(Path.Combine(oDir, "restored.bin"), originalHash);
        csv.Add($"\"{strategy}\",custom_odd,{(double)oDel/totalFrags*100:F1},0,{totalFrags},{oDel},{oR},{oSha},{sw.Elapsed.TotalMilliseconds:F0},\"delete_odd\"");
        customResults.Add(("odd", (double)oDel / totalFrags * 100, oR && oSha));
    }

    if (strategy == "FSS5+")
    {
        // Keep only 1 fragment (survivor = 0)
        var sDir = Path.Combine(testRoot, "custom_one_survivor");
        Directory.CreateDirectory(sDir);
        WriteTrialDir(sDir, new HashSet<int>(Enumerable.Range(1, totalFrags - 1)));
        var sTs = new LocalFileAdapter(sDir);
        sw.Restart();
        bool sR;
        using (var ro = new RestoreOrchestrator(rcClone(), sTs))
            sR = ro.RestoreFileAsync(fingerprint, Path.Combine(sDir, "restored.bin")).GetAwaiter().GetResult();
        bool sSha = sR && VerifySha(Path.Combine(sDir, "restored.bin"), originalHash);
        int sDel = totalFrags - 1;
        csv.Add($"\"{strategy}\",custom_one_survivor,{(double)sDel/totalFrags*100:F1},0,{totalFrags},{sDel},{sR},{sSha},{sw.Elapsed.TotalMilliseconds:F0},\"keep_one\"");
        customResults.Add(("keep_one", (double)sDel / totalFrags * 100, sR && sSha));
    }

    // FSS6.1: block corruption test (ETN detects, LT repairs)
    if (strategy == "FSS6.1")
    {
        var bcDir = Path.Combine(testRoot, "custom_block_corrupt");
        Directory.CreateDirectory(bcDir);
        WriteTrialDir(bcDir, null);

        var (embeddedIdx, fragData, bcSalt) = RDRFEngine.DecryptFragment(
            allFragBytes[0], aesKey);
        if (embeddedIdx != null)
        {
            int corruptOff = Math.Min(4096, Math.Max(1, fragData.Length - 256));
            RandomNumberGenerator.Fill(fragData.AsSpan(corruptOff, 128));

            byte[] reEnc = FragmentFileHeader.EncryptWithEmbeddedIndex(
                fragData, embeddedIdx, aesKey, bcSalt);
            File.WriteAllBytes(Path.Combine(bcDir, $"{prefix}_0.rdrf"), reEnc);

            var bcTs = new LocalFileAdapter(bcDir);
            sw.Restart();
            bool bcR;
            using (var r = new RestoreOrchestrator(rcClone(), bcTs))
                bcR = r.RestoreFileAsync(fingerprint, Path.Combine(bcDir, "restored.bin")).GetAwaiter().GetResult();
            bool bcSha = bcR && VerifySha(Path.Combine(bcDir, "restored.bin"), originalHash);
            csv.Add($"\"{strategy}\",custom_block_corrupt,0,0,{totalFrags},0,{bcR},{bcSha},{sw.Elapsed.TotalMilliseconds:F0},\"block_corrupted_repaired\"");
            customResults.Add(("block_corrupt", 0, bcR && bcSha));
        }
    }

    // ── Targeted tests ──
    var targetResults = new List<(string testName, double lossPct, bool ok)>();

    // FSS3: exact boundary tests
    if (strategy == "FSS3")
    {
        // Delete exactly 1 fragment (theoretical max)
        var td1Dir = Path.Combine(testRoot, "target_1lost");
        Directory.CreateDirectory(td1Dir);
        WriteTrialDir(td1Dir, null);
        File.Delete(Path.Combine(td1Dir, $"{prefix}_0.rdrf"));
        var ts1 = new LocalFileAdapter(td1Dir);
        sw.Restart();
        bool r1;
        using (var r = new RestoreOrchestrator(rcClone(), ts1))
            r1 = r.RestoreFileAsync(fingerprint, Path.Combine(td1Dir, "restored.bin")).GetAwaiter().GetResult();
        bool sha1 = r1 && VerifySha(Path.Combine(td1Dir, "restored.bin"), originalHash);
        csv.Add($"\"{strategy}\",targeted,{1.0/totalFrags*100:F1},0,{totalFrags},1,{r1},{sha1},{sw.Elapsed.TotalMilliseconds:F0},\"exact_max_1_lost\"");
        targetResults.Add(("exact_max_1_lost", 1.0/totalFrags*100, r1 && sha1));

        // Delete exactly 2 fragments (beyond theoretical max)
        var td2Dir = Path.Combine(testRoot, "target_2lost");
        Directory.CreateDirectory(td2Dir);
        WriteTrialDir(td2Dir, null);
        File.Delete(Path.Combine(td2Dir, $"{prefix}_0.rdrf"));
        File.Delete(Path.Combine(td2Dir, $"{prefix}_1.rdrf"));
        var ts2 = new LocalFileAdapter(td2Dir);
        bool r2;
        using (var r = new RestoreOrchestrator(rcClone(), ts2))
            r2 = r.RestoreFileAsync(fingerprint, Path.Combine(td2Dir, "restored.bin")).GetAwaiter().GetResult();
        csv.Add($"\"{strategy}\",targeted,{2.0/totalFrags*100:F1},0,{totalFrags},2,{r2},false,{sw.Elapsed.TotalMilliseconds:F0},\"beyond_max_2_lost\"");
        targetResults.Add(("beyond_max_2_lost", 2.0/totalFrags*100, r2));
    }

    // FSS1/2/2R/5+: consecutive pair test
    if (strategy is "FSS1" or "FSS2" or "FSS2R" or "FSS5+")
    {
        var tDir = Path.Combine(testRoot, "target_adjacent_pair");
        Directory.CreateDirectory(tDir);
        WriteTrialDir(tDir, null);
        File.Delete(Path.Combine(tDir, $"{prefix}_0.rdrf"));
        File.Delete(Path.Combine(tDir, $"{prefix}_1.rdrf"));
        var ts = new LocalFileAdapter(tDir);
        bool ro;
        using (var r = new RestoreOrchestrator(rcClone(), ts))
            ro = r.RestoreFileAsync(fingerprint, Path.Combine(tDir, "restored.bin")).GetAwaiter().GetResult();
        double lp = 2.0 / totalFrags * 100;
        csv.Add($"\"{strategy}\",targeted,{lp:F1},0,{totalFrags},2,{ro},{ro && VerifySha(Path.Combine(tDir, "restored.bin"), originalHash)},{sw.Elapsed.TotalMilliseconds:F0},\"adjacent_pair\"");
        targetResults.Add(("adjacent_pair", lp, ro));
    }

    // FSS1/2/2R/5+: every-other pattern
    if (strategy is "FSS1" or "FSS2" or "FSS2R" or "FSS5+")
    {
        var tDir = Path.Combine(testRoot, "target_every_other");
        Directory.CreateDirectory(tDir);
        WriteTrialDir(tDir, null);
        int deleted = 0;
        for (int i = 0; i < totalFrags; i += 2)
        {
            var f = Path.Combine(tDir, $"{prefix}_{i}.rdrf");
            if (File.Exists(f)) { File.Delete(f); deleted++; }
        }
        var ts = new LocalFileAdapter(tDir);
        bool ro;
        sw.Restart();
        using (var r = new RestoreOrchestrator(rcClone(), ts))
            ro = r.RestoreFileAsync(fingerprint, Path.Combine(tDir, "restored.bin")).GetAwaiter().GetResult();
        double lp2 = (double)deleted / totalFrags * 100;
        bool sh = ro && File.Exists(Path.Combine(tDir, "restored.bin")) && VerifySha(Path.Combine(tDir, "restored.bin"), originalHash);
        csv.Add($"\"{strategy}\",targeted,{lp2:F1},0,{totalFrags},{deleted},{ro},{sh},{sw.Elapsed.TotalMilliseconds:F0},\"every_other\"");
        targetResults.Add(("every_other", lp2, ro && sh));
    }

    // FSS5: step-pattern targeted
    if (strategy == "FSS5")
    {
        int step1, step2;
        if (origCount <= 4) (step1, step2) = (1, 2);
        else if (origCount <= 8) (step1, step2) = (1, 3);
        else if (origCount <= 16) (step1, step2) = (2, 5);
        else (step1, step2) = (3, 7);

        // Delete frags at positions that kill all copies of one fragment
        // For a fragment at position i, copies are in: encoded[i-1].n1, encoded[i-step2].n2
        // Losing {i-1, i-step2, ...} kills recovery for position i
        var tDir = Path.Combine(testRoot, "target_step_pattern");
        Directory.CreateDirectory(tDir);
        WriteTrialDir(tDir, null);
        var toKill = new HashSet<int>();
        int targetFrag = 0;
        toKill.Add((targetFrag - step1 + totalFrags) % totalFrags);
        toKill.Add((targetFrag - step2 + totalFrags) % totalFrags);
        toKill.Add(targetFrag);
        foreach (int fi in toKill)
            File.Delete(Path.Combine(tDir, $"{prefix}_{fi}.rdrf"));
        var ts = new LocalFileAdapter(tDir);
        bool ro;
        sw.Restart();
        using (var r = new RestoreOrchestrator(rcClone(), ts))
            ro = r.RestoreFileAsync(fingerprint, Path.Combine(tDir, "restored.bin")).GetAwaiter().GetResult();
        double lp3 = (double)toKill.Count / totalFrags * 100;
        csv.Add($"\"{strategy}\",targeted,{lp3:F1},0,{totalFrags},{toKill.Count},{ro},false,{sw.Elapsed.TotalMilliseconds:F0},\"step_pattern_3copies_killed\"");
        targetResults.Add(("step_pattern_kill", lp3, ro));
    }

    // FSS6/6.1: delete 1 fragment (should fail)
    if (strategy is "FSS6" or "FSS6.1")
    {
        var tDir = Path.Combine(testRoot, "target_one_lost");
        Directory.CreateDirectory(tDir);
        WriteTrialDir(tDir, null);
        File.Delete(Path.Combine(tDir, $"{prefix}_0.rdrf"));
        var ts = new LocalFileAdapter(tDir);
        bool ro;
        sw.Restart();
        using (var r = new RestoreOrchestrator(rcClone(), ts))
            ro = r.RestoreFileAsync(fingerprint, Path.Combine(tDir, "restored.bin")).GetAwaiter().GetResult();
        csv.Add($"\"{strategy}\",targeted,{1.0/totalFrags*100:F1},0,{totalFrags},1,{ro},false,{sw.Elapsed.TotalMilliseconds:F0},\"no_redundancy_1_lost\"");
        targetResults.Add(("no_redundancy", 1.0/totalFrags*100, !ro));
    }

    // ── Compute max loss from incremental data ──
    double maxSurvivedPct = 0;
    double maxFailedPct = 0;
    foreach (var inc in incResults)
    {
        if (inc.ok && inc.lossPct > maxSurvivedPct)
            maxSurvivedPct = inc.lossPct;
        if (!inc.ok && (maxFailedPct == 0 || inc.lossPct < maxFailedPct))
            maxFailedPct = inc.lossPct;
    }

    // FSS3 starts failing at 2 lost, which is 2/21 ≈ 9.5%
    double theoreticalMax = strategy switch
    {
        "FSS1" => 50.0,
        "FSS2" => 50.0,
        "FSS2R" => 50.0,
        "FSS3" => 100.0 / totalFrags,
        "FSS5" => 66.0,
        "FSS5+" => 95.0,
        "FSS6" or "FSS6.1" => 0.0,
        _ => 0
    };

    summaryRows.Add(new SummaryRow
    {
        Strategy = strategy,
        TotalFrags = totalFrags,
        BaselineOk = baselineOk && baseShaOk,
        TheoreticalMax = theoreticalMax,
        MaxSurvived = maxSurvivedPct,
        MinFailed = maxFailedPct,
        GreedyStrength = greedyStrength,
        BackupMs = backupTime
    });

    Console.WriteLine($"  Fragments: {totalFrags} total ({origCount} orig)");
    Console.WriteLine($"  Incremental: {incResults.Count} levels × 3 trials");
    Console.WriteLine($"  Greedy: {greedyKept.Count}/{totalFrags} = {greedyStrength:F1}%");
    Console.WriteLine($"  Custom: {customResults.Count} tests");
    Console.WriteLine($"  Targeted tests: {targetResults.Count}");
    Console.WriteLine();
}

// ── Summary Table ──
Console.ForegroundColor = ConsoleColor.White;
Console.WriteLine("┌──────────┬──────┬──────────┬──────────────┬──────────────┬────────────┬──────────┬──────────────────────┐");
Console.WriteLine("│ Strategy │ Frags│ Baseline │ Theoretical  │ Max Survived │ Min Failed │  Greedy  │ Notes                │");
Console.WriteLine("│          │      │          │ Max Loss %   │ Loss %       │ Loss %     │ Strength │                      │");
Console.WriteLine("├──────────┼──────┼──────────┼──────────────┼──────────────┼────────────┼──────────┼──────────────────────┤");
Console.ResetColor();

foreach (var row in summaryRows)
{
    string baselineStr = row.BaselineOk ? "PASS" : "FAIL";
    string theoStr = row.TheoreticalMax == 0 ? "0% (none)" : $"{row.TheoreticalMax:F1}%";
    string maxStr = row.TheoreticalMax >= row.MaxSurvived
        ? $"{row.MaxSurvived:F1}% >="
        : $"{row.MaxSurvived:F1}% !";

    string greedyStr = row.GreedyStrength == 0 ? "0%" : $"{row.GreedyStrength:F1}%";

    string note = row.Strategy switch
    {
        "FSS1" => "no consecutive",
        "FSS2" => "+ SHA256 check",
        "FSS2R" => "+ auto-repair",
        "FSS3" => $"RS({row.TotalFrags - 1},1)",
        "FSS5" => "3-way cross",
        "FSS5+" => "RS seed (1 recovers all)",
        "FSS6" => "validation only",
        "FSS6.1" => "ETN + LT repair",
        _ => ""
    };

    Console.WriteLine(
        $"│ {row.Strategy,-7} │ {row.TotalFrags,4} │ {baselineStr,-8} │ {theoStr,-12} │ {row.MaxSurvived,11:F1}% │ {row.MinFailed,10:F1}% │ {greedyStr,8} │ {note,-20} │");
}

Console.ForegroundColor = ConsoleColor.White;
Console.WriteLine("└──────────┴──────┴──────────┴──────────────┴──────────────┴────────────┴──────────┴──────────────────────┘");
Console.ResetColor();

// ── Write CSV ──
string csvPath = Path.Combine(resultDir, "fss_recovery_results.csv");
File.WriteAllLines(csvPath, csv);
Console.WriteLine($"\n  CSV: {csvPath}");

// ── Print CSV to console ──
Console.WriteLine("\n── Raw CSV Data ──");
    foreach (string line in csv)
        Console.WriteLine($"  {line}");

Console.WriteLine($"\n  Result dir: {resultDir}");

// Cleanup test data
try { Directory.Delete(resultDir, recursive: true); Console.WriteLine($"  Cleaned: {resultDir}"); }
catch (Exception ex) { Console.Error.WriteLine($"  Cleanup failed: {ex.Message}"); }

return 0;

// ═══════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════

static bool VerifySha(string filePath, byte[] expectedHash)
{
    try
    {
        byte[] actual = SHA256.HashData(File.ReadAllBytes(filePath));
        return CryptographicOperations.FixedTimeEquals(actual, expectedHash);
    }
    catch { return false; }
}

record SummaryRow
{
    public string Strategy { get; init; } = "";
    public int TotalFrags { get; init; }
    public bool BaselineOk { get; init; }
    public double TheoreticalMax { get; init; }
    public double MaxSurvived { get; init; }
    public double MinFailed { get; init; }
    public double GreedyStrength { get; init; }
    public double BackupMs { get; init; }
}
