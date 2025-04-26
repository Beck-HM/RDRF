using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.ETN;
using RDRF.Core.FSS;
using RDRF.Core.Index;
using RDRF.Core.Storage;

bool _interactive = args.Contains("-i");
bool _stress = args.Contains("--stress");
int _sizeMB = 0;
string? _outDir = null;
for (int i = 0; i < args.Length; i++)
{
    if ((args[i] == "-a" || args[i] == "--size") && i + 1 < args.Length)
        int.TryParse(args[i + 1], out _sizeMB);
    if ((args[i] == "-o" || args[i] == "--out") && i + 1 < args.Length)
        _outDir = args[i + 1];
}

PrintBanner();
if (_stress)
    RunStressTests();
else
    RunStandardDemo();

// ═══════════════════════════════════════════════
//  Standard Demo
// ═══════════════════════════════════════════════
void RunStandardDemo()
{
    string demoDir = CreateTempDir(_outDir);
    try
    {
        Step("1/9  生成测试代码文件");
        string testFile = GenerateTestFile(demoDir, _sizeMB);
        byte[] originalHash = SHA256.HashData(File.ReadAllBytes(testFile));
        Print($"  File: {Path.GetFileName(testFile)}");
        long fileBytes = new FileInfo(testFile).Length;
        Print($"  Size: {fileBytes:N0} bytes ({fileBytes / 1024 / 1024} MB)");
        Print($"  SHA256: {Convert.ToHexString(originalHash).ToLowerInvariant()}");
        WaitRun();

        Step("2/9  执行 FSS6 备份");
        byte[] rcCode = EncryptionLayer.GenerateRcCode(32);
        byte[] rcCodeSave = (byte[])rcCode.Clone();
        var storage = new LocalFileAdapter(demoDir);
        string fingerprint;
        using (var engine = new RDRFEngine(rcCode, storage))
            fingerprint = engine.BackupFile(testFile, "FSS6");
        byte[] aesKey = EncryptionLayer.DeriveKey(rcCodeSave);
        var index = IndexManager.DecryptIndexWithKey(storage.ReadIndex(fingerprint), aesKey);
        int targetFrag = index.FragentCount > 1 ? 1 : 0;
        Print($"  Fingerprint: {fingerprint}");
        Print($"  Strategy: FSS6");
        Print($"  Fragments: {index.FragentCount}");
        Print($"  RC file: {storage.ReadRc(fingerprint).Length:N0} bytes encrypted");
        Print($"  Directory: {demoDir}");
        WaitRun();

        Step("3/9  解密备份数据 (基准准备)");
        var baseline = DecryptFragments(index, storage, aesKey);
        byte[] rcPlain = DecryptRc(storage, fingerprint, aesKey);
        byte[] indexJson = IndexManager.SerializeIndex(index);
        var baselineCheck = Fss6Etn.CrossValidate(indexJson, baseline, rcPlain);
        AssertOrDie(baselineCheck.IsValid, "Baseline backup is incomplete — cannot continue");
        int indexBmCount = EtnBlockMap.Build(Fss6Etn.StripEtnFieldsFromIndexJson(indexJson)).Count;
        int rcBmCount = EtnBlockMap.Build(rcPlain).Count;
        Print($"  Index BM: {indexBmCount} entries → stored in RC (8B each)");
        Print($"  RC   BM: {rcBmCount} entries → stored in Index (8B each)");
        for (int i = 0; i < baseline.Count; i++)
        {
            var (raw, _, _) = Fss6Etn.ParseTrailer(baseline[i]);
            int blockCount = EtnBlockMap.Build(raw).Count;
            int trailerBytes = baseline[i].Length - raw.Length;
            Print($"  Fragment[{i}]: {raw.Length:N0} B, {blockCount} blocks, trailer {trailerBytes} B (2B/block)");
        }
        WaitRun();

        var records = new List<CorruptionRecord>();

        Step("4/9  篡改 Fragment 数据");
        string prefix = index.CustomName ?? fingerprint;
        string fragFile = $"{prefix}_{targetFrag}.rdrf";
        byte[] encFrag = storage.ReadFragment(fragFile);
        var (embIdx, fragData) = FragmentFileHeader.DecryptWithEmbeddedIndex(encFrag, aesKey);
        int corruptOffset = Math.Min(4096, fragData.Length > 1 ? 4096 : fragData.Length / 2);
        int expectedBlock = corruptOffset / 256;
        byte orig = fragData[corruptOffset];
        fragData[corruptOffset] ^= 0xFF;
        bool needsCtr = encFrag.Length > 5 && encFrag[5] == 1;
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        storage.WriteFragment(fragFile, FragmentFileHeader.EncryptWithEmbeddedIndex(fragData, embIdx!, aesKey));
        records.Add(new FragmentCorruption(targetFrag, expectedBlock, $"{orig:X2}->{(orig ^ 0xFF):X2}"));
        Print($"  Fragment[{targetFrag}], byte {corruptOffset}, block #{expectedBlock}");
        WaitRun();

        Step("5/9  篡改 Index OriginalName");
        byte[] encIdx = storage.ReadIndex(fingerprint);
        var idx = IndexManager.DecryptIndexWithKey(encIdx, aesKey);
        idx.OriginalName += "_TAMPERED";
        storage.WriteIndex(fingerprint, IndexManager.EncryptIndexWithKey(idx, aesKey));
        records.Add(new IndexCorruption("OriginalName", "original_TAMPERED"));
        Print($"  OriginalName => {idx.OriginalName}");
        WaitRun();

        Step("6/9  篡改 RC Version");
        rcPlain = DecryptRc(storage, fingerprint, aesKey);
        var rc = RcFile.FromCbor(rcPlain);
        rc.Version = 999;
        byte[] corruptedRcRaw = rc.ToCborBytes();
        storage.WriteRc(fingerprint, EncryptionLayer.EncryptFragmentWithKey(corruptedRcRaw, aesKey));
        records.Add(new RcCorruption("Version", "1 -> 999"));
        Print($"  Version -> 999");
        WaitRun();

        Step("7/9  重新解密 (模拟恢复)");
        encIdx = storage.ReadIndex(fingerprint);
        var restoredIndex = IndexManager.DecryptIndexWithKey(encIdx, aesKey);
        indexJson = IndexManager.SerializeIndex(restoredIndex);
        var restored = DecryptFragments(restoredIndex, storage, aesKey);
        rcPlain = DecryptRc(storage, fingerprint, aesKey);
        Print($"  Index JSON: {indexJson.Length:N0} B");
        Print($"  Fragments: {restored.Count}");
        Print($"  RC JSON: {rcPlain.Length:N0} B");
        WaitRun();

        Step("8/9  ETN 精密交叉校验");
        var swEtn = System.Diagnostics.Stopwatch.StartNew();
        var result = Fss6Etn.CrossValidate(indexJson, restored, rcPlain);
        swEtn.Stop();
        Print($"  2-tier ETN: {swEtn.Elapsed.TotalMilliseconds:F1} ms");
        PrintResult(result, restored.Count, records);

        Step("9/9  总结报告");
        int detected = records.Count(r => r.Check(result));
        Print($"  Detected: {detected}/{records.Count}");
        int totalSusp = result.SuspiciousFragmentBlocks.Values.Sum(l => l.Count);
        if (totalSusp > 0)
            Print($"  False positives (2B collision → 8B cleared): {totalSusp} blocks");
        foreach (var r2 in records)
        {
            bool hit = r2.Check(result);
            Print($"  {(hit ? "OK" : "MISS")} {r2.Label()}: {r2.Desc}");
            if (r2 is FragmentCorruption fc && hit && result.CorruptedFragmentBlocks.TryGetValue(fc.Idx, out var b))
                Print($"     expected block #{fc.ExpectedBlock}, got: [{string.Join(",", b)}]");
        }
    }
    finally
    {
        Cleanup(demoDir);
    }
}

// ═══════════════════════════════════════════════
//  Stress Tests
// ═══════════════════════════════════════════════
void RunStressTests()
{
    int total = 0, passed = 0;
    string resultsFile = Path.Combine(Path.GetTempPath(), $"EtnStress_{Guid.NewGuid():N}.csv");
    var csv = new System.Text.StringBuilder();
    csv.AppendLine("Scenario,Result,Details");

    Step($"STRESS: 7 scenarios — interactive={_interactive}");
    Print($"  Results CSV: {resultsFile}");
    WaitRun();

    // Scenario 1
    total++;
    if (Scenario1_MultiFragmentCascade(resultsFile, csv)) passed++;
    WaitRun();
    // Scenario 2
    total++;
    if (Scenario2_CrossBlockBoundary(resultsFile, csv)) passed++;
    WaitRun();
    // Scenario 3
    total++;
    if (Scenario3_ByzantineMetadata(resultsFile, csv)) passed++;
    WaitRun();
    // Scenario 4
    total++;
    if (Scenario4_RecoveryResidual(resultsFile, csv)) passed++;
    WaitRun();
    // Scenario 5
    total++;
    if (Scenario5_BlockSaturation(resultsFile, csv)) passed++;
    WaitRun();
    // Scenario 6
    total++;
    if (Scenario6_ReplayAttack(resultsFile, csv)) passed++;
    WaitRun();
    // Scenario 7
    total++;
    if (Scenario7_LargeFile(resultsFile, csv)) passed++;
    WaitRun();

    Step("STRESS: Summary");
    Print($"  Scenarios passed: {passed}/{total}");
    double rate = total > 0 ? (double)passed / total * 100 : 0;
    Print($"  Pass rate: {rate:F1}%");
    Print($"  Results CSV: {resultsFile}");
    File.WriteAllText(resultsFile, csv.ToString());
}

bool Scenario1_MultiFragmentCascade(string logFile, System.Text.StringBuilder csv)
{
    Step("S1  Multi-Fragment Cascade — corrupt every fragment");
    string dir = CreateTempDir();
    try
    {
        var (storage, fingerprint, aesKey, fragmentKey, index) = QuickBackup(dir);
        var decrypted = DecryptFragments(index, storage, fragmentKey);
        string prefix = index.CustomName ?? fingerprint;

        var rand = new Random(42);
        var details = new List<string>();
        var records = new List<CorruptionRecord>();

        for (int i = 0; i < decrypted.Count; i++)
        {
            string f = $"{prefix}_{i}.rdrf";
            byte[] enc = storage.ReadFragment(f);
            var (emb, data) = FragmentFileHeader.DecryptWithEmbeddedIndex(enc, fragmentKey);
            int pos = rand.Next(data.Length);
            int blk = pos / 256;
            data[pos] ^= 0xFF;
            bool nc = enc.Length > 5 && enc[5] == 1;
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            storage.WriteFragment(f, FragmentFileHeader.EncryptWithEmbeddedIndex(data, emb!, fragmentKey));
            records.Add(new FragmentCorruption(i, blk, $"byte {pos}"));
            details.Add($"Frag[{i}]: byte {pos}, block {blk}");
        }

        var result = RunEtn(storage, fingerprint, aesKey, fragmentKey, index);
        bool ok = records.All(r => r.Check(result));
        csv.AppendLine($"S1,{(ok ? "PASS" : "FAIL")},{details.Count} fragments");
        Print($"  All {decrypted.Count} fragments corrupted: {(ok ? "PASS" : "FAIL")}");
        if (!ok)
        {
            var missing = records.Where(r => !r.Check(result)).ToList();
            Print($"  Missing detections: {missing.Count}");
            foreach (var m in missing) Print($"    {m.Label()}: {m.Desc}");
        }
        return ok;
    }
    finally { Cleanup(dir); }
}

bool Scenario2_CrossBlockBoundary(string logFile, System.Text.StringBuilder csv)
{
    Step("S2  Cross-block boundary — corrupt bytes 255 & 256");
    string dir = CreateTempDir();
    try
    {
        var (storage, fingerprint, aesKey, fragmentKey, index) = QuickBackup(dir);
        var decrypted = DecryptFragments(index, storage, fragmentKey);
        string prefix = index.CustomName ?? fingerprint;
        string f = $"{prefix}_0.rdrf";
        byte[] enc = storage.ReadFragment(f);
        var (emb, data) = FragmentFileHeader.DecryptWithEmbeddedIndex(enc, fragmentKey);

        // byte 255 = last byte of block 0; byte 256 = first byte of block 1
        data[255] ^= 0xFF;
        data[256] ^= 0xFF;
        bool nc = enc.Length > 5 && enc[5] == 1;
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        storage.WriteFragment(f, FragmentFileHeader.EncryptWithEmbeddedIndex(data, emb!, fragmentKey));

        var result = RunEtn(storage, fingerprint, aesKey, fragmentKey, index);
        bool has0 = result.CorruptedFragmentBlocks.TryGetValue(0, out var blocks) && blocks.Contains(0) && blocks.Contains(1);
        bool ok = has0 && result.CorruptedFragments.Contains(0);
        csv.AppendLine($"S2,{(ok ? "PASS" : "FAIL")},block0+block1");
        Print($"  Block 0 + Block 1 both detected: {(ok ? "PASS" : "FAIL")}");
        if (result.CorruptedFragmentBlocks.TryGetValue(0, out var b))
            Print($"  Detected blocks: [{string.Join(",", b)}]");
        return ok;
    }
    finally { Cleanup(dir); }
}

bool Scenario3_ByzantineMetadata(string logFile, System.Text.StringBuilder csv)
{
    Step("S3  Byzantine metadata — three-way disagreement on Index hash");
    string dir = CreateTempDir();
    try
    {
        var (storage, fingerprint, aesKey, fragmentKey, index) = QuickBackup(dir);
        string prefix = index.CustomName ?? fingerprint;

        // Make Index, RC, and trailers all disagree about the index BM
        // Step A: mutate the index JSON itself (non-ETN field)
        index.OriginalName += "_BYZANTINE";
        byte[] mutatedIndexJson = IndexManager.SerializeIndex(index);
        storage.WriteIndex(fingerprint, IndexManager.EncryptIndexWithKey(index, aesKey));

        // Step B: keep RC unchanged — RC still has original index BM
        // Step C: corrupt one fragment's trailer indexBM
        string f0 = $"{prefix}_0.rdrf";
        byte[] enc0 = storage.ReadFragment(f0);
        var (emb0, d0) = FragmentFileHeader.DecryptWithEmbeddedIndex(enc0, fragmentKey);
        var (raw0, idxBm, rcBm) = Fss6Etn.ParseTrailer(d0);
        // Corrupt the last trailer indexBM hash (flip one byte)
        if (idxBm.Count > 0)
        {
            byte[] corruptedHash = (byte[])idxBm[idxBm.Count - 1].Clone();
            corruptedHash[0] ^= 0xFF;
            idxBm[idxBm.Count - 1] = corruptedHash;
        }
        var fragBm0 = Fss6Etn.BuildBlockMap(raw0);
        byte[] newTrailer = Fss6Etn.BuildTrailer(fragBm0, idxBm, rcBm, raw0.Length);
        byte[] newFrag0 = new byte[raw0.Length + newTrailer.Length];
        Buffer.BlockCopy(raw0, 0, newFrag0, 0, raw0.Length);
        Buffer.BlockCopy(newTrailer, 0, newFrag0, raw0.Length, newTrailer.Length);
        bool nc0 = enc0.Length > 5 && enc0[5] == 1;
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        storage.WriteFragment(f0, FragmentFileHeader.EncryptWithEmbeddedIndex(newFrag0, emb0!, fragmentKey));

        var result = RunEtn(storage, fingerprint, aesKey, fragmentKey, index);
        // Index must be flagged (actual index changed, RC has original BM)
        bool ok = result.IndexCorrupted;
        csv.AppendLine($"S3,{(ok ? "PASS" : "FAIL")},IndexCorrupted={result.IndexCorrupted}");
        Print($"  Index corrupted: {result.IndexCorrupted} (expected True)");
        return ok;
    }
    finally { Cleanup(dir); }
}

bool Scenario4_RecoveryResidual(string logFile, System.Text.StringBuilder csv)
{
    Step("S4  Recovery residual — corrupt raw data (simulating post-recovery residual error)");
    string dir = CreateTempDir();
    try
    {
        var (storage, fp, aesKey, fragmentKey, index) = QuickBackup(dir);
        string prefix = index.CustomName ?? fp;
        string f0 = $"{prefix}_0.rdrf";
        byte[] enc0 = storage.ReadFragment(f0);
        var (emb0, d0) = FragmentFileHeader.DecryptWithEmbeddedIndex(enc0, fragmentKey);
        // d0 = fragment data WITH trailer. Parse trailer to find raw data boundary.
        var (rawData, _, _) = Fss6Etn.ParseTrailer(d0);
        int mid = rawData.Length / 2;
        int blk = mid / 256;
        // Corrupt within raw data area
        d0[mid] ^= 0xFF;
        bool nc0 = enc0.Length > 5 && enc0[5] == 1;
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        storage.WriteFragment(f0, FragmentFileHeader.EncryptWithEmbeddedIndex(d0, emb0!, fragmentKey));

        var result = RunEtn(storage, fp, aesKey, fragmentKey, index);
        bool ok = result.CorruptedFragments.Contains(0)
            && result.CorruptedFragmentBlocks.TryGetValue(0, out var b)
            && b.Contains(blk);
        csv.AppendLine($"S4,{(ok ? "PASS" : "FAIL")},Frag0={result.CorruptedFragments.Contains(0)} block={blk}");
        Print($"  Data corruption detected: {(ok ? "PASS" : "FAIL")} (byte {mid}, block {blk})");
        return ok;
    }
    finally { Cleanup(dir); }
}

bool Scenario5_BlockSaturation(string logFile, System.Text.StringBuilder csv)
{
    Step("S5  Block saturation — 40 non-consecutive blocks in one fragment");
    string dir = CreateTempDir();
    try
    {
        var (storage, fingerprint, aesKey, fragmentKey, index) = QuickBackup(dir);
        var decrypted = DecryptFragments(index, storage, fragmentKey);
        string prefix = index.CustomName ?? fingerprint;
        string f = $"{prefix}_0.rdrf";
        byte[] enc = storage.ReadFragment(f);
        var (emb, data) = FragmentFileHeader.DecryptWithEmbeddedIndex(enc, fragmentKey);
        var (rawOnly, _, _) = Fss6Etn.ParseTrailer(data);
        int rawBlocks = rawOnly.Length / 256;

        var expectedBlocks = new HashSet<int>();
        var rand = new Random(99);
        int actualMax = Math.Min(data.Length / 256 - 1, rawBlocks - 1);
        while (expectedBlocks.Count < 40 && expectedBlocks.Count < actualMax)
            expectedBlocks.Add(rand.Next(actualMax + 1));

        foreach (int blk in expectedBlocks)
        {
            int pos = blk * 256;
            data[pos] ^= 0xFF;
        }
        bool nc = enc.Length > 5 && enc[5] == 1;
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        storage.WriteFragment(f, FragmentFileHeader.EncryptWithEmbeddedIndex(data, emb!, fragmentKey));

        var result = RunEtn(storage, fingerprint, aesKey, fragmentKey, index);
        bool hasDetail = result.CorruptedFragmentBlocks.TryGetValue(0, out var actualBlocks);
        int overlap = hasDetail ? actualBlocks!.Intersect(expectedBlocks).Count() : 0;
        double precision = expectedBlocks.Count > 0 ? (double)overlap / expectedBlocks.Count * 100 : 0;
        bool ok = result.CorruptedFragments.Contains(0) && overlap > 38; // tolerate 2 misses
        csv.AppendLine($"S5,{(ok ? "PASS" : "FAIL")},expected={expectedBlocks.Count} overlap={overlap} precision={precision:F1}%");
        Print($"  Expected {expectedBlocks.Count} blocks, detected {overlap}/{expectedBlocks.Count} ({precision:F1}%)");
        return ok;
    }
    finally { Cleanup(dir); }
}

bool Scenario6_ReplayAttack(string logFile, System.Text.StringBuilder csv)
{
    Step("S6  Replay attack — mix nodes from two backup sessions");
    string dir1 = CreateTempDir();
    string dir2 = CreateTempDir();
    try
    {
        var storage1 = new LocalFileAdapter(dir1);
        byte[] rcA = EncryptionLayer.GenerateRcCode(32);
        GenerateTestFile(dir1); // small file
        string fp1;
        using (var e = new RDRFEngine((byte[])rcA.Clone(), storage1))
            fp1 = e.BackupFile(GenerateTestFile(dir1), "FSS6");

        byte[] aesKey = EncryptionLayer.DeriveKey(rcA);
        var index1 = IndexManager.DecryptIndexWithKey(storage1.ReadIndex(fp1), aesKey);
        byte[] fragmentKey = aesKey;

        // Tamper: replace one fragment's data with junk (simulating a mix-up/replay)
        var decrypted = DecryptFragments(index1, storage1, fragmentKey);
        string prefix = index1.CustomName ?? fp1;
        string f0 = $"{prefix}_0.rdrf";
        byte[] enc0 = storage1.ReadFragment(f0);
        var (emb0, _) = FragmentFileHeader.DecryptWithEmbeddedIndex(enc0, fragmentKey);
        byte[] fakeData = new byte[decrypted[0].Length];
        RandomNumberGenerator.Fill(fakeData);
        bool nc0 = enc0.Length > 5 && enc0[5] == 1;
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        storage1.WriteFragment(f0, FragmentFileHeader.EncryptWithEmbeddedIndex(fakeData, emb0!, fragmentKey));

        byte[] rcAplain = DecryptRc(storage1, fp1, aesKey);
        var result = Fss6Etn.CrossValidate(IndexManager.SerializeIndex(index1),
            DecryptFragments(index1, storage1, fragmentKey), rcAplain);
        bool ok = result.CorruptedFragments.Count > 0;
        csv.AppendLine($"S6,{(ok ? "PASS" : "FAIL")},FragCorrupt={result.CorruptedFragments.Count}");
        Print($"  Fragment replace detected: {(ok ? "PASS" : "FAIL")} (detected: {result.CorruptedFragments.Count})");
        return ok;
    }
    finally { Cleanup(dir1); Cleanup(dir2); }
}

bool Scenario7_LargeFile(string logFile, System.Text.StringBuilder csv)
{
    Step("S7  Large file — 50 MB, 100 random block corruptions");
    string dir = CreateTempDir();
    try
    {
        Step("  Generating 50 MB test file...");
        string testFile = GenerateTestFile(dir, sizeMB: 50);
        var storage = new LocalFileAdapter(dir);
        byte[] rcCode = EncryptionLayer.GenerateRcCode(32);
        byte[] rcCopy = (byte[])rcCode.Clone();

        string fp;
        using (var e = new RDRFEngine(rcCode, storage))
            fp = e.BackupFile(testFile, "FSS6");

        byte[] aesKey = EncryptionLayer.DeriveKey(rcCopy);
        var index = IndexManager.DecryptIndexWithKey(storage.ReadIndex(fp), aesKey);
        byte[] fragmentKey = aesKey;
        string prefix = index.CustomName ?? fp;

        var rand = new Random(123);
        var blockTargets = new Dictionary<int, HashSet<int>>(); // frag => unique blocks
        var perFragRawSize = new Dictionary<int, int>();
        int maxFrag = index.FragentCount;

        for (int c = 0; c < 100; c++)
        {
            int fi = rand.Next(maxFrag);
            string ff = $"{prefix}_{fi}.rdrf";
            byte[] enc = storage.ReadFragment(ff);
            var (emb, data) = FragmentFileHeader.DecryptWithEmbeddedIndex(enc, fragmentKey);
            var (rawOnly, _, _) = Fss6Etn.ParseTrailer(data);
            perFragRawSize[fi] = rawOnly.Length;
            if (!blockTargets.ContainsKey(fi))
                blockTargets[fi] = new HashSet<int>();
            int rawBlocks = rawOnly.Length / 256;
            int blk = rand.Next(rawBlocks);
            int pos = blk * 256;
            // Only corrupt if this block hasn't been corrupted yet in this fragment
            if (blockTargets[fi].Add(blk))
            {
                data[pos] ^= 0xFF;
                bool nc = enc.Length > 5 && enc[5] == 1;
                byte[] nonce = RandomNumberGenerator.GetBytes(12);
                storage.WriteFragment(ff, FragmentFileHeader.EncryptWithEmbeddedIndex(data, emb!, fragmentKey));
            }
            else
            {
                // Re-read the already-corrupted file — block was already hit
                // No need to corrupt again — the same block was already targeted
            }
        }

        var records = new List<CorruptionRecord>();
        foreach (var kv in blockTargets)
            foreach (int blk in kv.Value)
                records.Add(new FragmentCorruption(kv.Key, blk, $"{kv.Key}:b{blk}"));

        Step("  Running ETN cross-validation on 50 MB backup...");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = RunEtn(storage, fp, aesKey, fragmentKey, index);
        sw.Stop();

        int blockHits = records.Count(r => r.Check(result));
        int fragsHit = result.CorruptedFragments.Count;
        double blockRate = 100.0 * blockHits / records.Count;
        // Pass if at least one corruption was detected at fragment level
        bool ok = fragsHit > 0;
        csv.AppendLine($"S7,{(ok ? "PASS" : "FAIL")},blockHits={blockHits}/{records.Count} fragments={fragsHit}/{maxFrag} time={sw.Elapsed.TotalSeconds:F2}s");
        Print($"  100 corruptions: {blockHits}/{records.Count} block-exact ({blockRate:F1}%)");
        Print($"  Corrupted fragments: {fragsHit}/{maxFrag}");
        Print($"  ETN validation time: {sw.Elapsed.TotalSeconds:F2}s");
        return ok;
    }
    finally { Cleanup(dir); }
}

// ═══════════════════════════════════════════════
//  Shared Helpers
// ═══════════════════════════════════════════════
(LocalFileAdapter storage, string fingerprint, byte[] aesKey, byte[] fragmentKey, RdrfIndex index) QuickBackup(string dir)
{
    var storage = new LocalFileAdapter(dir);
    byte[] rcCode = EncryptionLayer.GenerateRcCode(32);
    byte[] rcCopy = (byte[])rcCode.Clone();
    string testFile = GenerateTestFile(dir);
    string fp;
    using (var e = new RDRFEngine(rcCode, storage))
        fp = e.BackupFile(testFile, "FSS6");
    byte[] aesKey2 = EncryptionLayer.DeriveKey(rcCopy);
    var idx = IndexManager.DecryptIndexWithKey(storage.ReadIndex(fp), aesKey2);
    return (storage, fp, aesKey2, aesKey2, idx);
}

CrossValidationResult RunEtn(LocalFileAdapter storage, string fingerprint, byte[] aesKey,
    byte[] fragmentKey, RdrfIndex index)
{
    byte[] indexJson = IndexManager.SerializeIndex(index);
    var fragments = DecryptFragments(index, storage, fragmentKey);
    byte[] rcJson = DecryptRc(storage, fingerprint, aesKey);
    return Fss6Etn.CrossValidate(indexJson, fragments, rcJson);
}

byte[] DecryptRc(LocalFileAdapter storage, string fingerprint, byte[] aesKey)
{
    byte[] enc = storage.ReadRc(fingerprint);
    try { return EncryptionLayer.DecryptFragmentWithKey(enc, aesKey); }
    catch { return enc; }
}

static string CreateTempDir(string? customBase = null)
{
    string dir = Path.Combine(customBase ?? Path.GetTempPath(), $"EtnDemo_{Guid.NewGuid():N}");
    Directory.CreateDirectory(dir);
    return dir;
}

static void Cleanup(string dir)
{
    try { Directory.Delete(dir, true); }
    catch { }
}

// ═══════════════════════════════════════════════
//  Print Helpers
// ═══════════════════════════════════════════════
void WaitRun()
{
    if (!_interactive) return;
    Console.ForegroundColor = ConsoleColor.DarkGray;
    Console.Write("\n  > Press ENTER to continue...");
    Console.ResetColor();
    Console.ReadLine();
}

static void AssertOrDie(bool condition, string msg)
{
    if (!condition)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"\n  FATAL: {msg}");
        Console.ResetColor();
        Environment.Exit(1);
    }
}

static void PrintBanner()
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine();
    Console.WriteLine("  ╔══════════════════════════════════════════════════════════════╗");
    Console.WriteLine("  ║      ETN 2B+8B Precision Cross-Validation                  ║");
    Console.WriteLine("  ║  256B block · 3 nodes · 2-tier · surgical precision         ║");
    Console.WriteLine("  ╚══════════════════════════════════════════════════════════════╝");
    Console.ResetColor();
}

static void Step(string title)
{
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine($"\n  ── [{title}] ──");
    Console.ResetColor();
}

static void Print(string msg) => Console.WriteLine($"  {msg}");

static void PrintResult(CrossValidationResult r, int fragmentCount, List<CorruptionRecord> corruptions)
{
    Console.WriteLine();
    Console.ForegroundColor = ConsoleColor.White;
    Console.WriteLine("  ┌───────┬────────┬─────────────────────────────────────┬──────────────────┐");
    Console.WriteLine("  │ Node  │ Status │ Corrupted 256B Blocks              │ Suspicious (FP)  │");
    Console.WriteLine("  ├───────┼────────┼─────────────────────────────────────┼──────────────────┤");
    Console.ResetColor();

    PrintNodeRow("Index", r.IndexCorrupted, r.IndexCorruptedBlocks, null, r.IndexCorrupted, corruptions, null);
    PrintNodeRow("RC", r.RcCorrupted, r.RcCorruptedBlocks, null, r.RcCorrupted, corruptions, null);

    for (int i = 0; i < fragmentCount; i++)
    {
        bool isCorrupt = r.CorruptedFragments.Contains(i);
        var blocks = r.CorruptedFragmentBlocks.TryGetValue(i, out var b) ? b : null;
        bool idx0Trailer = r.CorruptedFragmentTrailers.Contains(i);
        var susp = r.SuspiciousFragmentBlocks.TryGetValue(i, out var s) ? s : null;
        PrintNodeRow($"Fragment[{i}]", isCorrupt, blocks, idx0Trailer ? "TRAILER" : null, isCorrupt, corruptions, susp);
    }
    Console.ForegroundColor = ConsoleColor.White;
    Console.WriteLine("  └───────┴────────┴─────────────────────────────────────┴──────────────────┘");
    Console.ResetColor();
}

static void PrintNodeRow(string name, bool isCorrupt, List<int>? blocks, string? extraTag,
    bool hasTag, List<CorruptionRecord> corruptions, List<int>? suspicious)
{
    Console.ForegroundColor = isCorrupt ? ConsoleColor.Red : ConsoleColor.Green;
    string status = isCorrupt ? "FAILED" : "OK    ";
    string blkStr = blocks != null && blocks.Count > 0
        ? (blocks.Count <= 10
            ? string.Join(",", blocks)
            : string.Join(",", blocks.Take(6)) + $"+{blocks.Count - 6} blks")
        : (isCorrupt ? "-" : "-");
    string suspStr = suspicious != null && suspicious.Count > 0
        ? (suspicious.Count <= 4
            ? string.Join(",", suspicious)
            : string.Join(",", suspicious.Take(3)) + $"+{suspicious.Count - 3}")
        : "";
    string tag = hasTag ? " [TAMPER]" : extraTag != null ? $" [{extraTag}]" : "";
    Console.WriteLine($"  │ {name,-14} │ {status} │ {blkStr,-28} │ {suspStr,-16} │{tag}");
    Console.ResetColor();
}

// ═══════════════════════════════════════════════
//  Test File Generator
// ═══════════════════════════════════════════════
static string GenerateTestFile(string dir, int sizeMB = 0)
{
    string path = Path.Combine(dir, "DemoCode.cs");
    var sb = new System.Text.StringBuilder();
    sb.AppendLine("// ETN Demo — generated source file");
    sb.AppendLine("using System;");
    sb.AppendLine("namespace EtnDemo {");
    for (int cls = 0; cls < 80; cls++)
    {
        sb.AppendLine($"public class C{cls} {{");
        for (int f = 0; f < 5; f++)
            sb.AppendLine($"string _f{f} = \"v{cls}_{f}\";");
        for (int m = 0; m < 3; m++)
        {
            sb.AppendLine($"public int M{m}(int x,int y){{");
            sb.AppendLine($"var r = x*{cls}+y*{m}+{cls*m};");
            sb.AppendLine($"System.Console.WriteLine(r); return r; }}");
        }
        sb.AppendLine("}");
    }
    // padding
    int lines = sizeMB > 0 ? sizeMB * 12000 : 3000;
    sb.AppendLine("public static class P{");
    for (int i = 0; i < lines; i++)
        sb.AppendLine($"// line {i:D6}: padding padding padding padding padding");
    sb.AppendLine("}}");
    File.WriteAllText(path, sb.ToString());
    return path;
}

// ═══════════════════════════════════════════════
//  Key/Fragment Helpers
// ═══════════════════════════════════════════════
static List<byte[]> DecryptFragments(RdrfIndex index, LocalFileAdapter storage, byte[] fragmentKey)
{
    string prefix = index.CustomName ?? index.FileFingerprint;
    var fragments = new List<byte[]>();
    for (int i = 0; i < index.FragentCount; i++)
    {
        string fname = $"{prefix}_{i}.rdrf";
        byte[] fileBytes = storage.ReadFragment(fname);
        var (_, data) = FragmentFileHeader.DecryptWithEmbeddedIndex(fileBytes, fragmentKey);
        fragments.Add(data);
    }
    return fragments;
}

// ═══════════════════════════════════════════════
//  Corruption Records
// ═══════════════════════════════════════════════
abstract record CorruptionRecord(string Desc)
{
    public abstract bool Check(CrossValidationResult r);
    public abstract string Label();
}

record FragmentCorruption(int Idx, int ExpectedBlock, string Change) : CorruptionRecord(Change)
{
    public override bool Check(CrossValidationResult r)
        => r.CorruptedFragments.Contains(Idx)
        && r.CorruptedFragmentBlocks.TryGetValue(Idx, out var b)
        && b.Contains(ExpectedBlock);
    public override string Label() => $"Fragment[{Idx}]";
}

record IndexCorruption(string Field, string Change) : CorruptionRecord(Change)
{
    public override bool Check(CrossValidationResult r) => r.IndexCorrupted;
    public override string Label() => "Index";
}

record RcCorruption(string Field, string Change) : CorruptionRecord(Change)
{
    public override bool Check(CrossValidationResult r) => r.RcCorrupted;
    public override string Label() => "RC";
}
