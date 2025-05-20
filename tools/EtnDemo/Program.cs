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
int stressSize = _sizeMB > 0 ? _sizeMB : 500;
if (_stress)
    RunStressTests(stressSize);
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
        Step("1/9  Generate test file");
        string testFile = GenerateTestFile(demoDir, _sizeMB);
        byte[] originalHash = SHA256.HashData(File.ReadAllBytes(testFile));
        Print($"  File: {Path.GetFileName(testFile)}");
        long fileBytes = new FileInfo(testFile).Length;
        Print($"  Size: {fileBytes:N0} bytes ({fileBytes / 1024 / 1024} MB)");
        Print($"  SHA256: {Convert.ToHexString(originalHash).ToLowerInvariant()}");
        WaitRun();

        Step("2/9  Run FSS6 backup");
        byte[] rcCode = EncryptionLayer.GenerateRcCode(32);
        byte[] rcCodeSave = (byte[])rcCode.Clone();
        var storage = new LocalFileAdapter(demoDir);
        string fingerprint;
        using (var engine = new RDRFEngine(rcCode, storage))
            fingerprint = engine.BackupFile(testFile, "FSS6");
        byte[] aesKey = EncryptionLayer.DeriveKey(rcCodeSave);
        var index = IndexManager.DecryptIndexWithKey(storage.ReadIndex(fingerprint), aesKey);
        int etnBlockSize = EtnBlockMap.GetBlockSize(index.FileSize);
        int targetFrag = index.FragentCount > 1 ? 1 : 0;
        Print($"  Fingerprint: {fingerprint}");
        Print($"  Strategy: FSS6");
        Print($"  Fragments: {index.FragentCount}");
        Print($"  RC file: {storage.ReadRc(fingerprint).Length:N0} bytes encrypted");
        Print($"  Directory: {demoDir}");
        WaitRun();

        Step("3/9  Decrypt backup data (baseline)");
        var baseline = DecryptFragments(index, storage, aesKey);
        byte[] rcPlain = DecryptRc(storage, fingerprint, aesKey);
        byte[] indexJson = IndexManager.SerializeIndex(index);
        var baselineCheck = Fss6Etn.CrossValidate(indexJson, baseline, rcPlain);
        AssertOrDie(baselineCheck.IsValid, "Baseline backup is incomplete — cannot continue");
        int indexBmCount = EtnBlockMap.BlockCount(EtnBlockMap.Build(Fss6Etn.StripEtnFieldsFromIndexJson(indexJson), etnBlockSize));
        int rcBmCount = EtnBlockMap.BlockCount(EtnBlockMap.Build(rcPlain, etnBlockSize));
        Print($"  Index BM: {indexBmCount} entries → stored in RC (8B each)");
        Print($"  RC   BM: {rcBmCount} entries → stored in Index (8B each)");
        Print($"  Block size: {etnBlockSize}B");
        for (int i = 0; i < baseline.Count; i++)
        {
            var (raw, _, _, _, _) = Fss6Etn.ParseTrailer(baseline[i]);
            int blockCount = EtnBlockMap.BlockCount(EtnBlockMap.Build(raw, etnBlockSize));
            int trailerBytes = baseline[i].Length - raw.Length;
            Print($"  Fragment[{i}]: {raw.Length:N0} B, {blockCount} blocks, trailer {trailerBytes} B (2B/block)");
        }
        WaitRun();

        var records = new List<CorruptionRecord>();

        Step("4/9  Corrupt fragment data");
        string prefix = index.CustomName ?? fingerprint;
        string fragFile = $"{prefix}_{targetFrag}.rdrf";
        byte[] encFrag = storage.ReadFragment(fragFile);
        var (embIdx, fragData) = FragmentFileHeader.DecryptWithEmbeddedIndex(encFrag, aesKey);
        int corruptOffset = Math.Min(4096, fragData.Length > 1 ? 4096 : fragData.Length / 2);
        int expectedBlock = corruptOffset / etnBlockSize;
        byte orig = fragData[corruptOffset];
        fragData[corruptOffset] ^= 0xFF;
        bool needsCtr = encFrag.Length > 5 && encFrag[5] == 1;
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        storage.WriteFragment(fragFile, FragmentFileHeader.EncryptWithEmbeddedIndex(fragData, embIdx!, aesKey));
        records.Add(new FragmentCorruption(targetFrag, expectedBlock, $"{orig:X2}->{(orig ^ 0xFF):X2}"));
        Print($"  Fragment[{targetFrag}], byte {corruptOffset}, block #{expectedBlock}");
        WaitRun();

        Step("5/9  Corrupt Index OriginalName");
        byte[] encIdx = storage.ReadIndex(fingerprint);
        var idx = IndexManager.DecryptIndexWithKey(encIdx, aesKey);
        idx.OriginalName += "_TAMPERED";
        storage.WriteIndex(fingerprint, IndexManager.EncryptIndexWithKey(idx, aesKey));
        records.Add(new IndexCorruption("OriginalName", "original_TAMPERED"));
        Print($"  OriginalName => {idx.OriginalName}");
        WaitRun();

        Step("6/9  Corrupt RC Version");
        rcPlain = DecryptRc(storage, fingerprint, aesKey);
        var rc = RcFile.FromCbor(rcPlain);
        rc.Version = 999;
        byte[] corruptedRcRaw = rc.ToCborBytes();
        storage.WriteRc(fingerprint, EncryptionLayer.EncryptFragmentWithKey(corruptedRcRaw, aesKey));
        records.Add(new RcCorruption("Version", "1 -> 999"));
        Print($"  Version -> 999");
        WaitRun();

        Step("7/9  Re-decrypt (simulate restore)");
        encIdx = storage.ReadIndex(fingerprint);
        var restoredIndex = IndexManager.DecryptIndexWithKey(encIdx, aesKey);
        indexJson = IndexManager.SerializeIndex(restoredIndex);
        var restored = DecryptFragments(restoredIndex, storage, aesKey);
        rcPlain = DecryptRc(storage, fingerprint, aesKey);
        Print($"  Index JSON: {indexJson.Length:N0} B");
        Print($"  Fragments: {restored.Count}");
        Print($"  RC JSON: {rcPlain.Length:N0} B");
        WaitRun();

        Step("8/9  ETN precision cross-validation");
        var swEtn = System.Diagnostics.Stopwatch.StartNew();
        var result = Fss6Etn.CrossValidate(indexJson, restored, rcPlain);
        swEtn.Stop();
        Print($"  2-tier ETN: {swEtn.Elapsed.TotalMilliseconds:F1} ms");
        PrintResult(result, restored.Count, records);

        Step("9/9  Summary report");
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
void RunStressTests(int sizeMB)
{
    int total = 0, passed = 0;
    string resultsFile = Path.Combine(Path.GetTempPath(), $"EtnStress_{Guid.NewGuid():N}.csv");
    var csv = new System.Text.StringBuilder();
    csv.AppendLine("Scenario,Result,Details,Time");
    var swTotal = System.Diagnostics.Stopwatch.StartNew();

    Step($"STRESS: 11 scenarios, {sizeMB}MB — interactive={_interactive}");
    Print($"  Results CSV: {resultsFile}");
    WaitRun();

    // Scenario 1
    total++;
    var sw = System.Diagnostics.Stopwatch.StartNew();
    if (Scenario1_MultiFragmentCascade(resultsFile, csv)) passed++;
    csv.AppendLine($"S1_T,{sw.Elapsed.TotalSeconds:F2}s");
    WaitRun(); sw.Restart();
    // Scenario 2
    total++;
    if (Scenario2_CrossBlockBoundary(resultsFile, csv)) passed++;
    csv.AppendLine($"S2_T,{sw.Elapsed.TotalSeconds:F2}s");
    WaitRun(); sw.Restart();
    // Scenario 3
    total++;
    if (Scenario3_ByzantineMetadata(resultsFile, csv)) passed++;
    csv.AppendLine($"S3_T,{sw.Elapsed.TotalSeconds:F2}s");
    WaitRun(); sw.Restart();
    // Scenario 4
    total++;
    if (Scenario4_RecoveryResidual(resultsFile, csv)) passed++;
    csv.AppendLine($"S4_T,{sw.Elapsed.TotalSeconds:F2}s");
    WaitRun(); sw.Restart();
    // Scenario 5
    total++;
    if (Scenario5_BlockSaturation(resultsFile, csv)) passed++;
    csv.AppendLine($"S5_T,{sw.Elapsed.TotalSeconds:F2}s");
    WaitRun(); sw.Restart();
    // Scenario 6
    total++;
    if (Scenario6_ReplayAttack(resultsFile, csv)) passed++;
    csv.AppendLine($"S6_T,{sw.Elapsed.TotalSeconds:F2}s");
    WaitRun(); sw.Restart();
    // Scenario 7
    total++;
    if (Scenario7_LargeFile(resultsFile, csv, sizeMB)) passed++;
    csv.AppendLine($"S7_T,{sw.Elapsed.TotalSeconds:F2}s");
    WaitRun(); sw.Restart();
    // Scenario 8 - Extreme bit rot
    total++;
    if (Scenario8_ExtremeBitRot(resultsFile, csv, sizeMB)) passed++;
    csv.AppendLine($"S8_T,{sw.Elapsed.TotalSeconds:F2}s");
    WaitRun(); sw.Restart();
    // Scenario 9 - Contiguous stripe kill
    total++;
    if (Scenario9_ContiguousStripeKill(resultsFile, csv, sizeMB)) passed++;
    csv.AppendLine($"S9_T,{sw.Elapsed.TotalSeconds:F2}s");
    WaitRun(); sw.Restart();
    // Scenario 10 - Combined multi-layer attack
    total++;
    if (Scenario10_CombinedAttack(resultsFile, csv, sizeMB)) passed++;
    csv.AppendLine($"S10_T,{sw.Elapsed.TotalSeconds:F2}s");
    WaitRun(); sw.Restart();
    // Scenario 11 - Trailer 2B false positive stress
    total++;
    if (Scenario11_TrailerFPStress(resultsFile, csv, sizeMB)) passed++;
    csv.AppendLine($"S11_T,{sw.Elapsed.TotalSeconds:F2}s");

    swTotal.Stop();
    Step("STRESS: Summary");
    Print($"  Scenarios passed: {passed}/{total}");
    double rate = total > 0 ? (double)passed / total * 100 : 0;
    Print($"  Pass rate: {rate:F1}%");
    Print($"  Total time: {swTotal.Elapsed.TotalSeconds:F1}s");
    Print($"  Results CSV: {resultsFile}");
    File.WriteAllText(resultsFile, csv.ToString());
}

bool Scenario1_MultiFragmentCascade(string logFile, System.Text.StringBuilder csv)
{
    Step("S1  Multi-Fragment Cascade — corrupt every fragment");
    string dir = CreateTempDir(_outDir);
    try
    {
        var (storage, fingerprint, aesKey, fragmentKey, index, _) = QuickBackup(dir); int blockSize = EtnBlockMap.GetBlockSize(index.FileSize);
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
            int blk = pos / blockSize;
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
    string dir = CreateTempDir(_outDir);
    try
    {
        var (storage, fingerprint, aesKey, fragmentKey, index, _) = QuickBackup(dir); int blockSize = EtnBlockMap.GetBlockSize(index.FileSize);
        var decrypted = DecryptFragments(index, storage, fragmentKey);
        string prefix = index.CustomName ?? fingerprint;
        string f = $"{prefix}_0.rdrf";
        byte[] enc = storage.ReadFragment(f);
        var (emb, data) = FragmentFileHeader.DecryptWithEmbeddedIndex(enc, fragmentKey);

        // byte blockSize-1 = last byte of block 0; byte blockSize = first byte of block 1
        data[blockSize - 1] ^= 0xFF;
        data[blockSize] ^= 0xFF;
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
    string dir = CreateTempDir(_outDir);
    try
    {
        var (storage, fingerprint, aesKey, fragmentKey, index, _) = QuickBackup(dir); int blockSize = EtnBlockMap.GetBlockSize(index.FileSize);
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
        var (raw0, idxFlat, idxCnt, rcFlat, rcCnt) = Fss6Etn.ParseTrailer(d0);
        // Corrupt the last trailer indexBM hash (flip first byte)
        if (idxCnt > 0)
            idxFlat[(idxCnt - 1) * EtnBlockMap.TrailerHashLen] ^= 0xFF;
        byte[] fragFlat = Fss6Etn.BuildBlockMap(raw0);
        // BuildTrailer expects 32B stride source arrays, but idxFlat/rcFlat from
        // ParseTrailer are 2B stride. Expand to 32B stride (zero-padded) for
        // AppendTruncated to read correctly.
        byte[] idxFull = ExpandTruncatedFlat(idxFlat, idxCnt, EtnBlockMap.FullHashLen);
        byte[] rcFull = ExpandTruncatedFlat(rcFlat, rcCnt, EtnBlockMap.FullHashLen);
        byte[] newTrailer = Fss6Etn.BuildTrailer(fragFlat, EtnBlockMap.BlockCount(fragFlat), idxFull, idxCnt, rcFull, rcCnt, raw0.Length);
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
    string dir = CreateTempDir(_outDir);
    try
    {
        var (storage, fp, aesKey, fragmentKey, index, _) = QuickBackup(dir); int blockSize = index.FileSize > 0 ? EtnBlockMap.GetBlockSize(index.FileSize) : 256;
        string prefix = index.CustomName ?? fp;
        string f0 = $"{prefix}_0.rdrf";
        byte[] enc0 = storage.ReadFragment(f0);
        var (emb0, d0) = FragmentFileHeader.DecryptWithEmbeddedIndex(enc0, fragmentKey);
        // d0 = fragment data WITH trailer. Parse trailer to find raw data boundary.
        var (rawData, _, _, _, _) = Fss6Etn.ParseTrailer(d0);
        int mid = rawData.Length / 2;
        int blk = mid / blockSize;
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
    string dir = CreateTempDir(_outDir);
    try
    {
        var (storage, fingerprint, aesKey, fragmentKey, index, _) = QuickBackup(dir); int blockSize = EtnBlockMap.GetBlockSize(index.FileSize);
        var decrypted = DecryptFragments(index, storage, fragmentKey);
        string prefix = index.CustomName ?? fingerprint;
        string f = $"{prefix}_0.rdrf";
        byte[] enc = storage.ReadFragment(f);
        var (emb, data) = FragmentFileHeader.DecryptWithEmbeddedIndex(enc, fragmentKey);
        var (rawOnly, _, _, _, _) = Fss6Etn.ParseTrailer(data);
        int rawBlocks = rawOnly.Length / blockSize;

        var expectedBlocks = new HashSet<int>();
        var rand = new Random(99);
        int actualMax = Math.Min(data.Length / blockSize - 1, rawBlocks - 1);
        while (expectedBlocks.Count < 40 && expectedBlocks.Count < actualMax)
            expectedBlocks.Add(rand.Next(actualMax + 1));

        foreach (int blk in expectedBlocks)
        {
            int pos = blk * blockSize;
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
    string dir1 = CreateTempDir(_outDir);
    string dir2 = CreateTempDir(_outDir);
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

bool Scenario7_LargeFile(string logFile, System.Text.StringBuilder csv, int sizeMB)
{
    Step($"S7  Large file — {sizeMB} MB, {sizeMB * 2} random block corruptions");
    string dir = CreateTempDir(_outDir);
    try
    {
        Step($"  Generating {sizeMB} MB test file...");
        string testFile = GenerateTestFile(dir, sizeMB);
        var storage = new LocalFileAdapter(dir);
        byte[] rcCode = EncryptionLayer.GenerateRcCode(32);
        byte[] rcCopy = (byte[])rcCode.Clone();

        string fp;
        using (var e = new RDRFEngine(rcCode, storage))
            fp = e.BackupFile(testFile, "FSS6");

        byte[] aesKey = EncryptionLayer.DeriveKey(rcCopy);
        var index = IndexManager.DecryptIndexWithKey(storage.ReadIndex(fp), aesKey);
        int blockSize = EtnBlockMap.GetBlockSize(index.FileSize);
        byte[] fragmentKey = aesKey;
        string prefix = index.CustomName ?? fp;

        var rand = new Random(123);
        var blockTargets = new Dictionary<int, HashSet<int>>();
        int maxFrag = index.FragentCount;
        int corruptCount = Math.Max(100, sizeMB * 2);

        for (int c = 0; c < corruptCount; c++)
        {
            int fi = rand.Next(maxFrag);
            string ff = $"{prefix}_{fi}.rdrf";
            byte[] enc = storage.ReadFragment(ff);
            var (emb, data) = FragmentFileHeader.DecryptWithEmbeddedIndex(enc, fragmentKey);
            var (rawOnly, _, _, _, _) = Fss6Etn.ParseTrailer(data);
            if (!blockTargets.ContainsKey(fi))
                blockTargets[fi] = new HashSet<int>();
            int rawBlocks = rawOnly.Length / blockSize;
            int blk = rand.Next(rawBlocks);
            int pos = blk * blockSize;
            // Only corrupt if this block hasn't been corrupted yet in this fragment
            if (blockTargets[fi].Add(blk))
            {
                data[pos] ^= 0xFF;
                storage.WriteFragment(ff, FragmentFileHeader.EncryptWithEmbeddedIndex(data, emb!, fragmentKey));
            }
        }

        var records = new List<CorruptionRecord>();
        foreach (var kv in blockTargets)
            foreach (int blk in kv.Value)
                records.Add(new FragmentCorruption(kv.Key, blk, $"{kv.Key}:b{blk}"));

        Step($"  Running ETN cross-validation on {sizeMB} MB backup ({maxFrag} fragments)...");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = RunEtn(storage, fp, aesKey, fragmentKey, index);
        sw.Stop();

        int blockHits = records.Count(r => r.Check(result));
        int fragsHit = result.CorruptedFragments.Count;
        double blockRate = blockHits > 0 ? 100.0 * blockHits / records.Count : 0;
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
//  Extreme Stress Scenarios
// ═══════════════════════════════════════════════

bool Scenario8_ExtremeBitRot(string logFile, System.Text.StringBuilder csv, int sizeMB)
{
    Step("S8  Extreme bit rot — 0.01% scattered byte flips across ALL fragments");
    string dir = CreateTempDir(_outDir);
    try
    {
        var (storage, fingerprint, aesKey, _, index, blockSize) = QuickBackup(dir, sizeMB);
        string prefix = index.CustomName ?? fingerprint;
        var rand = new Random(42);
        var records = new List<CorruptionRecord>();

        for (int i = 0; i < index.FragentCount; i++)
        {
            string f = $"{prefix}_{i}.rdrf";
            byte[] enc = storage.ReadFragment(f);
            var (emb, data) = FragmentFileHeader.DecryptWithEmbeddedIndex(enc, aesKey);
            var (rawOnly, _, _, _, _) = Fss6Etn.ParseTrailer(data);
            int rotBytes = Math.Max(1, rawOnly.Length / 10000);
            var flippedBlocks = new HashSet<int>();
            for (int b = 0; b < rotBytes; b++)
            {
                int pos = rand.Next(rawOnly.Length);
                int blk = pos / blockSize;
                data[pos] ^= (byte)(1 << rand.Next(8));
                flippedBlocks.Add(blk);
            }
            storage.WriteFragment(f, FragmentFileHeader.EncryptWithEmbeddedIndex(data, emb!, aesKey));
            foreach (int blk in flippedBlocks)
                records.Add(new FragmentCorruption(i, blk, $"rot@{i}:b{blk}"));
        }

        Step("  Running ETN cross-validation...");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = RunEtn(storage, fingerprint, aesKey, aesKey, index);
        sw.Stop();

        int detected = records.Count(r => r.Check(result));
        double rate = records.Count > 0 ? 100.0 * detected / records.Count : 100;
        bool ok = detected > 0;
        csv.AppendLine($"S8,{(ok ? "PASS" : "FAIL")},detected={detected}/{records.Count} frags={result.CorruptedFragments.Count} time={sw.Elapsed.TotalSeconds:F2}s");
        Print($"  Bit rot: {detected}/{records.Count} blocks detected ({rate:F1}%)");
        Print($"  Corrupted fragments: {result.CorruptedFragments.Count}/{index.FragentCount}");
        Print($"  ETN time: {sw.Elapsed.TotalSeconds:F2}s");
        return ok;
    }
    finally { Cleanup(dir); }
}

bool Scenario9_ContiguousStripeKill(string logFile, System.Text.StringBuilder csv, int sizeMB)
{
    Step("S9  Contiguous stripe kill — zero large block ranges (simulating media failure)");
    string dir = CreateTempDir(_outDir);
    try
    {
        var (storage, fingerprint, aesKey, _, index, blockSize) = QuickBackup(dir, sizeMB);
        string prefix = index.CustomName ?? fingerprint;
        var rand = new Random(77);
        var records = new List<CorruptionRecord>();

        int stripeCount = Math.Min(6, Math.Max(3, index.FragentCount / 10));
        for (int s = 0; s < stripeCount; s++)
        {
            int fi = rand.Next(index.FragentCount);
            string f = $"{prefix}_{fi}.rdrf";
            byte[] enc = storage.ReadFragment(f);
            var (emb, data) = FragmentFileHeader.DecryptWithEmbeddedIndex(enc, aesKey);
            var (rawOnly, _, _, _, _) = Fss6Etn.ParseTrailer(data);
            int rawBlocks = rawOnly.Length / blockSize;
            if (rawBlocks < 100) continue;

            int startBlk = rand.Next(rawBlocks / 2);
            int maxKill = Math.Min(500, rawBlocks / 4);
            int killBlocks = Math.Min(rawBlocks - startBlk, rand.Next(100, Math.Max(101, maxKill)));
            for (int b = startBlk; b < startBlk + killBlocks; b++)
            {
                int pos = b * 256;
                int wipeLen = Math.Min(256, rawOnly.Length - pos);
                Array.Fill<byte>(data, 0, pos, wipeLen);
                records.Add(new FragmentCorruption(fi, b, $"kill@{fi}:b{b}"));
            }
            storage.WriteFragment(f, FragmentFileHeader.EncryptWithEmbeddedIndex(data, emb!, aesKey));
        }

        Step("  Running ETN cross-validation...");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = RunEtn(storage, fingerprint, aesKey, aesKey, index);
        sw.Stop();

        int detected = records.Count(r => r.Check(result));
        double rate = records.Count > 0 ? 100.0 * detected / records.Count : 100;
        bool ok = detected > records.Count * 0.9;
        csv.AppendLine($"S9,{(ok ? "PASS" : "FAIL")},detected={detected}/{records.Count} frags={result.CorruptedFragments.Count} time={sw.Elapsed.TotalSeconds:F2}s");
        Print($"  Stripe kill: {detected}/{records.Count} blocks detected ({rate:F1}%)");
        Print($"  Corrupted fragments: {result.CorruptedFragments.Count}/{index.FragentCount}");
        Print($"  ETN time: {sw.Elapsed.TotalSeconds:F2}s");
        return ok;
    }
    finally { Cleanup(dir); }
}

bool Scenario10_CombinedAttack(string logFile, System.Text.StringBuilder csv, int sizeMB)
{
    Step("S10  Combined multi-layer attack — data + Index + RC + trailer");
    string dir = CreateTempDir(_outDir);
    try
    {
        var (storage, fingerprint, aesKey, _, index, blockSize) = QuickBackup(dir, sizeMB);
        string prefix = index.CustomName ?? fingerprint;
        var rand = new Random(2024);
        var records = new List<CorruptionRecord>();

        for (int i = 0; i < index.FragentCount; i++)
        {
            if (rand.NextDouble() > 0.3) continue;
            string f = $"{prefix}_{i}.rdrf";
            byte[] enc = storage.ReadFragment(f);
            var (emb, data) = FragmentFileHeader.DecryptWithEmbeddedIndex(enc, aesKey);
            var (rawOnly, _, _, _, _) = Fss6Etn.ParseTrailer(data);
            int rotBytes = Math.Max(1, rawOnly.Length / 20000);
            var flipped = new HashSet<int>();
            for (int b = 0; b < rotBytes; b++)
            {
                int pos = rand.Next(rawOnly.Length);
                int blk = pos / blockSize;
                data[pos] ^= (byte)(1 << rand.Next(8));
                flipped.Add(blk);
            }
            storage.WriteFragment(f, FragmentFileHeader.EncryptWithEmbeddedIndex(data, emb!, aesKey));
            foreach (int blk in flipped)
                records.Add(new FragmentCorruption(i, blk, $"layer1@{i}:b{blk}"));
        }

        byte[] encIdx = storage.ReadIndex(fingerprint);
        var idx = IndexManager.DecryptIndexWithKey(encIdx, aesKey);
        idx.OriginalName += "_TAMPERED";
        storage.WriteIndex(fingerprint, IndexManager.EncryptIndexWithKey(idx, aesKey));
        records.Add(new IndexCorruption("OriginalName", "tampered"));

        byte[] rcPlain = DecryptRc(storage, fingerprint, aesKey);
        var rc = RcFile.FromCbor(rcPlain);
        rc.Version = 999;
        storage.WriteRc(fingerprint, EncryptionLayer.EncryptFragmentWithKey(rc.ToCborBytes(), aesKey));
        records.Add(new RcCorruption("Version", "1->999"));

        if (index.FragentCount > 0)
        {
            int ti = rand.Next(index.FragentCount);
            string tf = $"{prefix}_{ti}.rdrf";
            byte[] tenc = storage.ReadFragment(tf);
            var (temb, tdata) = FragmentFileHeader.DecryptWithEmbeddedIndex(tenc, aesKey);
            var (rawData, idxFlat, idxCnt, rcFlat, rcCnt) = Fss6Etn.ParseTrailer(tdata);
            if (idxCnt > 0)
            {
                int hi = rand.Next(idxCnt);
                idxFlat[hi * EtnBlockMap.TrailerHashLen] ^= 0xFF;
                byte[] fragFlat = Fss6Etn.BuildBlockMap(rawData);
                byte[] idxFull = ExpandTruncatedFlat(idxFlat, idxCnt, EtnBlockMap.FullHashLen);
                byte[] rcFull = ExpandTruncatedFlat(rcFlat, rcCnt, EtnBlockMap.FullHashLen);
                byte[] newTrailer = Fss6Etn.BuildTrailer(fragFlat, EtnBlockMap.BlockCount(fragFlat), idxFull, idxCnt, rcFull, rcCnt, rawData.Length);
                byte[] newFrag = new byte[rawData.Length + newTrailer.Length];
                Buffer.BlockCopy(rawData, 0, newFrag, 0, rawData.Length);
                Buffer.BlockCopy(newTrailer, 0, newFrag, rawData.Length, newTrailer.Length);
                storage.WriteFragment(tf, FragmentFileHeader.EncryptWithEmbeddedIndex(newFrag, temb!, aesKey));
            }
        }

        Step("  Running ETN cross-validation...");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = RunEtn(storage, fingerprint, aesKey, aesKey, index);
        sw.Stop();

        int dataDetected = records.Count(r => r.Check(result));
        bool ok = (result.IndexCorrupted || result.RcCorrupted) && dataDetected > 0;
        csv.AppendLine($"S10,{(ok ? "PASS" : "FAIL")},idx={result.IndexCorrupted} rc={result.RcCorrupted} data={dataDetected} time={sw.Elapsed.TotalSeconds:F2}s");
        Print($"  Index corrupted: {result.IndexCorrupted}");
        Print($"  RC corrupted: {result.RcCorrupted}");
        Print($"  Data blocks detected: {dataDetected}");
        Print($"  Corrupted fragments: {result.CorruptedFragments.Count}/{index.FragentCount}");
        Print($"  ETN time: {sw.Elapsed.TotalSeconds:F2}s");
        return ok;
    }
    finally { Cleanup(dir); }
}

bool Scenario11_TrailerFPStress(string logFile, System.Text.StringBuilder csv, int sizeMB)
{
    Step("S11  Trailer false positive stress — corrupt only 2B trailer hashes, data intact");
    string dir = CreateTempDir(_outDir);
    try
    {
        var (storage, fingerprint, aesKey, _, index, blockSize) = QuickBackup(dir, sizeMB);
        string prefix = index.CustomName ?? fingerprint;
        var rand = new Random(2024);
        int fpBlocks = 0;

        for (int i = 0; i < Math.Min(20, index.FragentCount); i++)
        {
            string f = $"{prefix}_{i}.rdrf";
            byte[] enc = storage.ReadFragment(f);
            var (emb, data) = FragmentFileHeader.DecryptWithEmbeddedIndex(enc, aesKey);
            var (rawData, tFragFlat, tFragCnt, tIdxFlat, tIdxCnt, tRcFlat, tRcCnt) = EtnTrailer.Parse(data);
            if (tFragCnt == 0) continue;

            for (int h = 0; h < 2; h++)
            {
                int flipIdx = rand.Next(tFragCnt);
                tFragFlat[flipIdx * EtnBlockMap.TrailerHashLen] = (byte)rand.Next(256);
                tFragFlat[flipIdx * EtnBlockMap.TrailerHashLen + 1] = (byte)rand.Next(256);
                fpBlocks++;
            }

            byte[] fragFull = ExpandTruncatedFlat(tFragFlat, tFragCnt, EtnBlockMap.FullHashLen);
            byte[] idxFull = ExpandTruncatedFlat(tIdxFlat, tIdxCnt, EtnBlockMap.FullHashLen);
            byte[] rcFull = ExpandTruncatedFlat(tRcFlat, tRcCnt, EtnBlockMap.FullHashLen);
            byte[] newTrailer = EtnTrailer.Build(fragFull, tFragCnt, idxFull, tIdxCnt, rcFull, tRcCnt, rawData.Length);
            byte[] newFrag = new byte[rawData.Length + newTrailer.Length];
            Buffer.BlockCopy(rawData, 0, newFrag, 0, rawData.Length);
            Buffer.BlockCopy(newTrailer, 0, newFrag, rawData.Length, newTrailer.Length);
            storage.WriteFragment(f, FragmentFileHeader.EncryptWithEmbeddedIndex(newFrag, emb!, aesKey));
        }

        Step("  Running ETN cross-validation...");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = RunEtn(storage, fingerprint, aesKey, aesKey, index);
        sw.Stop();

        int totalSusp = result.SuspiciousFragmentBlocks.Values.Sum(l => l.Count);
        int totalCorrupt = result.CorruptedFragmentBlocks.Values.Sum(l => l.Count);
        bool ok = totalSusp > 0 && totalCorrupt == 0;
        csv.AppendLine($"S11,{(ok ? "PASS" : "FAIL")},suspicious={totalSusp} corrupted={totalCorrupt} time={sw.Elapsed.TotalSeconds:F2}s");
        Print($"  Trailer FPs injected: {fpBlocks}");
        Print($"  Suspicious (2B flagged, 8B cleared): {totalSusp}");
        Print($"  False corrupted (should be 0): {totalCorrupt}");
        Print($"  ETN time: {sw.Elapsed.TotalSeconds:F2}s");
        return ok;
    }
    finally { Cleanup(dir); }
}

// ═══════════════════════════════════════════════
//  Shared Helpers
// ═══════════════════════════════════════════════
(LocalFileAdapter storage, string fingerprint, byte[] aesKey, byte[] fragmentKey, RdrfIndex index, int blockSize) QuickBackup(string dir, int sizeMB = 0)
{
    var storage = new LocalFileAdapter(dir);
    byte[] rcCode = EncryptionLayer.GenerateRcCode(32);
    byte[] rcCopy = (byte[])rcCode.Clone();
    string testFile = GenerateTestFile(dir, sizeMB);
    string fp;
    using (var e = new RDRFEngine(rcCode, storage))
        fp = e.BackupFile(testFile, "FSS6");
    byte[] aesKey2 = EncryptionLayer.DeriveKey(rcCopy);
    var idx = IndexManager.DecryptIndexWithKey(storage.ReadIndex(fp), aesKey2);
    int bs = EtnBlockMap.GetBlockSize(idx.FileSize);
    return (storage, fp, aesKey2, aesKey2, idx, bs);
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

static byte[] ExpandTruncatedFlat(byte[] truncatedFlat, int count, int targetStride)
{
    byte[] result = new byte[count * targetStride];
    for (int i = 0; i < count; i++)
        Buffer.BlockCopy(truncatedFlat, i * EtnBlockMap.TrailerHashLen, result, i * targetStride, EtnBlockMap.TrailerHashLen);
    return result;
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
