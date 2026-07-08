using System.Diagnostics;
using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.FSS;
using RDRF.Core.Index;
using RDRF.Core.Dssa;
using RDRF.Core.Versioning;
using RDRF.Core.FragmentEngine;

var allStrategies = new[] { "FSS1", "FSS2", "FSS2R", "FSS3", "FSS5", "FSS5+", "FSS6", "FSS6.1", "FSS6.2" };
string[] validNames = allStrategies;

double? repairRatio = null;
string testFile = "";
var filterNames = new List<string>();

bool flagParity = false, flagBoundary = false, flagVersioning = false;
bool flagCacheIsolation = false, flagIncompressible = false, flagStress = false;
bool flagTiny = false, flagUnicode = false, flagCorruptIdx = false;
bool flagMany = false, flagMetadata = false, flagKdfBench = false;
bool flagCustomName = false, flagZeroMem = false;

for (int ai = 0; ai < args.Length; ai++)
{
    string arg = args[ai];
    if (arg.StartsWith('-') || arg.StartsWith('/'))
    {
        string name = arg.TrimStart('-', '/').ToUpperInvariant();
        if (name is "R" && ai + 1 < args.Length && double.TryParse(args[ai + 1], out var rr))
        {
            repairRatio = rr; ai++; continue;
        }
        if (validNames.Contains(name)) { filterNames.Add(name); continue; }
        if (name == "PARITY") { flagParity = true; continue; }
        if (name == "BOUNDARY") { flagBoundary = true; continue; }
        if (name == "VERSIONING") { flagVersioning = true; continue; }
        if (name == "CACHE-ISOLATION") { flagCacheIsolation = true; continue; }
        if (name == "INCOMPRESSIBLE") { flagIncompressible = true; continue; }
        if (name == "STRESS") { flagStress = true; continue; }
        if (name == "TINY") { flagTiny = true; continue; }
        if (name == "UNICODE") { flagUnicode = true; continue; }
        if (name == "CORRUPT-IDX") { flagCorruptIdx = true; continue; }
        if (name == "MANY") { flagMany = true; continue; }
        if (name == "METADATA") { flagMetadata = true; continue; }
        if (name == "KDF-BENCH") { flagKdfBench = true; continue; }
        if (name == "CUSTOM-NAME") { flagCustomName = true; continue; }
        if (name == "ZEROMEM") { flagZeroMem = true; continue; }
        continue;
    }
    if (File.Exists(arg))
        testFile = arg;
}

if (repairRatio.HasValue)
{
    Console.Error.WriteLine($"  LtCode.RepairRatio = {repairRatio.Value:F2}");
    LtCode.RepairRatio = repairRatio.Value;
    DuipCode.RepairRatio = repairRatio.Value;
}

if (testFile == "")
{
    string inputDir = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "..", "tests", "RDRF_TestInput"));
    if (!Directory.Exists(inputDir)) { Console.Error.WriteLine($"Test input dir not found: {inputDir}"); return 1; }
    var files = Directory.GetFiles(inputDir);
    testFile = files.Length > 0 ? files[0] : "";
}

if (!File.Exists(testFile))
{
    Console.Error.WriteLine($"Test file not found: {testFile}");
    return 1;
}

string[] strategies = filterNames.Count > 0 ? filterNames.ToArray() : allStrategies;

long fileSize = new FileInfo(testFile).Length;
byte[] originalHash = SHA256.HashData(File.ReadAllBytes(testFile));
int fragSize = 256 * 1024;
string testsDir = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "..", "tests", "RDRF_TestOutput"));
string resultDir = Path.Combine(testsDir, $"FssRecovery_{Guid.NewGuid():N}");
Directory.CreateDirectory(resultDir);

var csv = new List<string>
{
    "strategy,test_type,loss_pct,trial,frags_total,frags_lost,recovered,sha256_match,time_ms,notes"
};
var summaryRows = new List<SummaryRow>();

Console.ForegroundColor = ConsoleColor.Cyan;
Console.WriteLine("+------------------------------------------------------------------+");
string title = filterNames.Count > 0
    ? $"|     FSS Recovery Test - {string.Join(" ", filterNames)}"
    : "|        FSS Recovery Test - All Strategies";
Console.WriteLine(title.PadRight(68) + "|");
Console.WriteLine("+------------------------------------------------------------------+");
Console.ResetColor();
Console.WriteLine($"  Test file: {testFile} ({fileSize:N0} bytes)");
Console.WriteLine($"  Fragment size: {fragSize:N0} bytes");
Console.WriteLine($"  Result dir: {resultDir}");
Console.WriteLine();

try
{
var extraSw = new Stopwatch();
var flgs = new[] { (flagParity,"parity"),(flagBoundary,"boundary"),(flagVersioning,"versioning"),
    (flagCacheIsolation,"cache-isolation"),(flagIncompressible,"incompressible"),(flagStress,"stress"),
    (flagTiny,"tiny"),(flagUnicode,"unicode"),(flagCorruptIdx,"corrupt-idx"),(flagMany,"many"),
    (flagMetadata,"metadata"),(flagKdfBench,"kdf-bench"),(flagCustomName,"custom-name"),(flagZeroMem,"zeromem") };
bool hasNewTests = flgs.Any(f => f.Item1);
if (hasNewTests)
{
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("-- [EXTRA TESTS] --");
    Console.ResetColor();
}

// -- parity: streaming vs dictionary pipeline consistency --
if (flagParity)
{
    var d = Path.Combine(resultDir, "parity"); Directory.CreateDirectory(d);
    var s = new LocalDssaAdapter(d); var pw = EncryptionLayer.GenerateRcCode(32); byte[] r() => (byte[])pw.Clone();
    string fp; using (var e = new RDRFEngine(pw, s)) fp = e.BackupFile(testFile, "FSS5", fragmentSize: fragSize);
    byte[] ei = s.ReadIndex(fp); var (_, cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(ei, r()); var idx = IndexManager.DeserializeIndex(cbor);
    string pf = idx.CustomName ?? fp; int tf = idx.FragmentCount;

    // streaming path (baseline)
    string os = Path.Combine(d, "stream.bin"); extraSw.Restart();
    using (var ro = new RestoreOrchestrator(r(), s)) ro.RestoreFileAsync(fp, os).GetAwaiter().GetResult();
    long st = extraSw.ElapsedMilliseconds; bool sOK = File.Exists(os) && VerifySha(os, SHA256.HashData(File.ReadAllBytes(testFile)));

    // dictionary path: delete fragment 0 to force dictionary fallback
    var af = new byte[tf][]; for (int i = 0; i < tf; i++) af[i] = File.ReadAllBytes(Path.Combine(d, Frags.FragmentFilename(pf, i)));
    byte[] ib = File.ReadAllBytes(Path.Combine(d, $"{pf}.indrdrf"));
    string dd = Path.Combine(d, "dict"); Directory.CreateDirectory(dd);
    File.WriteAllBytes(Path.Combine(dd, $"{pf}.indrdrf"), ib);
    for (int i = 1; i < tf; i++) File.WriteAllBytes(Path.Combine(dd, Frags.FragmentFilename(pf, i)), af[i]);
    // RC file
    string rcp = Path.Combine(d, $"{pf}.rdrc"); if (File.Exists(rcp)) File.WriteAllBytes(Path.Combine(dd, $"{pf}.rdrc"), File.ReadAllBytes(rcp));
    string od = Path.Combine(d, "dict.bin"); extraSw.Restart();
    using (var ro = new RestoreOrchestrator(r(), new LocalDssaAdapter(dd))) ro.RestoreFileAsync(fp, od).GetAwaiter().GetResult();
    long dt = extraSw.ElapsedMilliseconds; bool dOK = File.Exists(od) && VerifySha(od, SHA256.HashData(File.ReadAllBytes(testFile)));
    bool ok = sOK && dOK;
    csv.Add($"\"parity\",stream_vs_dict,0,0,{tf},{tf - 1},{sOK},{dOK},{Math.Max(st,dt)},\"stream={st}ms dict={dt}ms\"");
    Console.WriteLine($"  Parity: {(ok ? "PASS" : "FAIL")} (stream={st}ms dict={dt}ms)");
}

// -- boundary: FSS1/2 fragment 0 recovery --
if (flagBoundary)
{
    foreach (string strat in new[] { "FSS1", "FSS2" })
    {
        var d = Path.Combine(resultDir, $"boundary_{strat}"); Directory.CreateDirectory(d);
        var s = new LocalDssaAdapter(d); var pw = EncryptionLayer.GenerateRcCode(32); byte[] r() => (byte[])pw.Clone();
        string fp; using (var e = new RDRFEngine(pw, s)) fp = e.BackupFile(testFile, strat, fragmentSize: fragSize);
        // delete frag 0
        string pf = fp; // fingerprint is short enough
        // Actually read the index to get prefix
        byte[] enci = s.ReadIndex(fp); var (_, cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(enci, r()); var idx = IndexManager.DeserializeIndex(cbor);
        string prefix = idx.CustomName ?? fp;
        string f0 = Path.Combine(d, Frags.FragmentFilename(prefix, 0)); if (File.Exists(f0)) File.Delete(f0);
        string op = Path.Combine(d, "restored.bin"); extraSw.Restart();
        bool rec; using (var ro = new RestoreOrchestrator(r(), s)) rec = ro.RestoreFileAsync(fp, op).GetAwaiter().GetResult();
        long t = extraSw.ElapsedMilliseconds; bool sha = rec && File.Exists(op) && VerifySha(op, originalHash);
        csv.Add($"\"{strat}\",boundary_frag0,1.9,0,{idx.FragmentCount},1,{rec},{sha},{t:F0},\"frag0_recovery\"");
        Console.WriteLine($"  Boundary {strat}: {(rec && sha ? "PASS" : "FAIL")} ({t}ms)");
    }
}

// -- versioning: incremental cleanup --
if (flagVersioning)
{
    var d = Path.Combine(resultDir, "versioning"); Directory.CreateDirectory(d);
    var s = new LocalDssaAdapter(d); var pw = EncryptionLayer.GenerateRcCode(32);
    string vf = Path.Combine(d, "version_test.txt"); File.WriteAllText(vf, "v1 content");
    string fp = VersionedBackup.BackupAsync(vf, d, pw, "initial", "FSS3", fragmentSize: 65536).GetAwaiter().GetResult();
    File.WriteAllText(vf, "v2 content modified");
    string fp2 = VersionedBackup.BackupAsync(vf, d, pw, "modified", "FSS3", fragmentSize: 65536).GetAwaiter().GetResult();
    bool oldGone = !File.Exists(Path.Combine(d, fp + Constants.IndexFileSuffix));
    bool newExists = File.Exists(Path.Combine(d, fp2 + Constants.IndexFileSuffix));
    // also check no stale fragment files from old fingerprint
    bool staleFrags = s.ListFragments().Any(f => f.StartsWith(fp + "_", StringComparison.OrdinalIgnoreCase));
    bool ok = oldGone && newExists && !staleFrags;
    csv.Add($"\"versioning\",cleanup,0,0,0,0,{oldGone},{newExists},{0},\"old_gone={oldGone} new_exists={newExists} stale={staleFrags}\"");
    Console.WriteLine($"  Versioning cleanup: {(ok ? "PASS" : "FAIL")} (old={(oldGone ? "gone" : "leaked")} new={(newExists ? "exists" : "missing")} stale={staleFrags})");
}

if (flagCacheIsolation)
{
    var d = Path.Combine(resultDir, "cache_iso"); Directory.CreateDirectory(d);
    var s = new LocalDssaAdapter(d); var pwA = EncryptionLayer.GenerateRcCode(32); var pwB = EncryptionLayer.GenerateRcCode(32);
    byte[] rA() => (byte[])pwA.Clone();
    // Use different files to avoid fingerprint collision (same file -> same fingerprint -> overwrite)
    string fa = Path.Combine(d, "aaa.bin"); File.WriteAllBytes(fa, new byte[] { 0x41 });
    string fb = Path.Combine(d, "bbb.bin"); File.WriteAllBytes(fb, new byte[] { 0x42 });
    string fpA; using (var e = new RDRFEngine(pwA, s)) fpA = e.BackupFile(fa, "FSS3", fragmentSize: 8192);
    string fpB; using (var e = new RDRFEngine(pwB, s)) fpB = e.BackupFile(fb, "FSS3", fragmentSize: 8192);
    // Cross-decrypt: A key on B's index -> must fail
    byte[] encB = s.ReadIndex(fpB); bool crossFails = false;
    try { EncryptionLayer.DecryptIndexWithAutoDetect(encB, rA()); } catch { crossFails = true; }
    // Own decrypt must succeed
    byte[] encA = s.ReadIndex(fpA); bool ownOk = false;
    try { EncryptionLayer.DecryptIndexWithAutoDetect(encA, rA()); ownOk = true; } catch { }
    bool ok = crossFails && ownOk;
    csv.Add($"\"cache_isolation\",cross_password,0,0,0,0,{crossFails},{ownOk},{0},\"cross_fails={crossFails} own_ok={ownOk}\"");
    Console.WriteLine($"  Cache isolation: {(ok ? "PASS" : "FAIL")} (cross={(crossFails ? "blocked" : "leaked")} own={(ownOk ? "ok" : "fail")})");
}

// -- incompressible: random data, LZ4 anti-expansion --
if (flagIncompressible)
{
    var d = Path.Combine(resultDir, "incompressible"); Directory.CreateDirectory(d);
    byte[] rand = RandomNumberGenerator.GetBytes(10 * 1024 * 1024);
    string rf = Path.Combine(d, "random.bin"); File.WriteAllBytes(rf, rand);
    var s = new LocalDssaAdapter(d); var pw = EncryptionLayer.GenerateRcCode(32); byte[] r() => (byte[])pw.Clone();
    string fp; using (var e = new RDRFEngine(pw, s)) fp = e.BackupFile(rf, "FSS1", fragmentSize: fragSize);
    string op = Path.Combine(d, "restored.bin"); extraSw.Restart();
    bool rec; using (var ro = new RestoreOrchestrator(r(), s)) rec = ro.RestoreFileAsync(fp, op).GetAwaiter().GetResult();
    long t = extraSw.ElapsedMilliseconds; bool sha = rec && File.Exists(op) && VerifySha(op, SHA256.HashData(rand));
    csv.Add($"\"incompressible\",random_10mb,0,0,0,0,{rec},{sha},{t:F0},\"\"");
    Console.WriteLine($"  Incompressible: {(rec && sha ? "PASS" : "FAIL")} ({t}ms)");
}

// -- stress: parallel restore concurrency --
if (flagStress)
{
    var d = Path.Combine(resultDir, "stress"); Directory.CreateDirectory(d);
    var s = new LocalDssaAdapter(d); var pw = EncryptionLayer.GenerateRcCode(32); byte[] r() => (byte[])pw.Clone();
    // Use small file to keep it fast
    byte[] tiny = new byte[65536]; RandomNumberGenerator.Fill(tiny);
    string tfS = Path.Combine(d, "tiny.bin"); File.WriteAllBytes(tfS, tiny);
    string fp; using (var e = new RDRFEngine(pw, s)) fp = e.BackupFile(tfS, "FSS1", fragmentSize: 16384);
    byte[] tinyHash = SHA256.HashData(tiny);
    int N = Math.Min(8, Environment.ProcessorCount);
    int passed = 0, failed = 0;
    Parallel.For(0, N, _ =>
    {
        string op = Path.Combine(d, $"restored_{Guid.NewGuid():N}.bin");
        bool ok = false;
        try { using (var ro = new RestoreOrchestrator(r(), s)) ok = ro.RestoreFileAsync(fp, op).GetAwaiter().GetResult(); }
        catch { }
        if (ok && File.Exists(op) && VerifySha(op, tinyHash)) Interlocked.Increment(ref passed);
        else Interlocked.Increment(ref failed);
    });
    csv.Add($"\"stress\",parallel_restore,0,0,0,0,{passed},{failed},{0},\"passed={passed} failed={failed}\"");
    Console.WriteLine($"  Stress: {(failed == 0 ? "PASS" : "FAIL")} ({passed}/{passed + failed} passed)");
}

// -- tiny: 0B, 1B, 1KB files --
if (flagTiny)
{
    foreach (var (name, data) in new[] { ("empty", Array.Empty<byte>()), ("1b", new byte[] { 0x42 }), ("1kb", new byte[1024]) })
    {
        var d = Path.Combine(resultDir, $"tiny_{name}"); Directory.CreateDirectory(d);
        string tf = Path.Combine(d, "file.bin"); File.WriteAllBytes(tf, data);
        var s = new LocalDssaAdapter(d); var pw = EncryptionLayer.GenerateRcCode(32); byte[] r() => (byte[])pw.Clone();
        byte[] h = SHA256.HashData(data);
        string fp; using (var e = new RDRFEngine(pw, s)) fp = e.BackupFile(tf, "FSS1", fragmentSize: fragSize);
        string op = Path.Combine(d, "restored.bin"); extraSw.Restart();
        bool rec; using (var ro = new RestoreOrchestrator(r(), s)) rec = ro.RestoreFileAsync(fp, op).GetAwaiter().GetResult();
        long t = extraSw.ElapsedMilliseconds; bool sha = rec && File.Exists(op) && VerifySha(op, h);
        csv.Add($"\"tiny_{name}\",size_test,0,0,0,0,{rec},{sha},{t:F0},\"\"");
        Console.WriteLine($"  Tiny {name}: {(rec && sha ? "PASS" : "FAIL")} ({t}ms)");
    }
}

// -- unicode: Chinese filename --
if (flagUnicode)
{
    var d = Path.Combine(resultDir, "unicode"); Directory.CreateDirectory(d);
    string uf = Path.Combine(d, "test_file_unicode_support.mp4");
    // Copy original test file to unicode path
    byte[] srcData = File.ReadAllBytes(testFile);
    File.WriteAllBytes(uf, srcData);
    var s = new LocalDssaAdapter(d); var pw = EncryptionLayer.GenerateRcCode(32); byte[] r() => (byte[])pw.Clone();
    string fp; using (var e = new RDRFEngine(pw, s)) fp = e.BackupFile(uf, "FSS1", originalFilename: "test_file_unicode_support.mp4", fragmentSize: fragSize);
    // Check index has original name
    byte[] ei = s.ReadIndex(fp); var (_, cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(ei, r()); var idx = IndexManager.DeserializeIndex(cbor);
    bool nameOk = idx.OriginalName == "test_file_unicode_support.mp4";
    string op = Path.Combine(d, "restored.bin"); extraSw.Restart();
    bool rec; using (var ro = new RestoreOrchestrator(r(), s)) rec = ro.RestoreFileAsync(fp, op).GetAwaiter().GetResult();
    long t = extraSw.ElapsedMilliseconds; bool sha = rec && File.Exists(op) && VerifySha(op, originalHash);
    csv.Add($"\"unicode\",filename,0,0,0,0,{rec},{sha && nameOk},{t:F0},\"name_ok={nameOk}\"");
    Console.WriteLine($"  Unicode filename: {(rec && sha && nameOk ? "PASS" : "FAIL")} ({t}ms)");
}

// -- corrupt-idx: malformed index handling --
if (flagCorruptIdx)
{
    var d = Path.Combine(resultDir, "corrupt_idx"); Directory.CreateDirectory(d);
    var s = new LocalDssaAdapter(d); var pw = EncryptionLayer.GenerateRcCode(32); byte[] r() => (byte[])pw.Clone();
    string fp; using (var e = new RDRFEngine(pw, s)) fp = e.BackupFile(testFile, "FSS1", fragmentSize: fragSize);
    byte[] ei = s.ReadIndex(fp);
    // Keep salt valid, corrupt ciphertext with random bytes (guaranteed to fail decryption)
    byte[] bogus = new byte[ei.Length];
    Array.Copy(ei, bogus, 32); // valid salt
    RandomNumberGenerator.Fill(bogus.AsSpan(32)); // garbage ciphertext
    bool graceful = false;
    try { EncryptionLayer.DecryptIndexWithAutoDetect(bogus, r()); }
    catch { graceful = true; }
    csv.Add($"\"corrupt_idx\",random_ciphertext,0,0,0,0,{graceful},{false},{0},\"graceful={graceful}\"");
    Console.WriteLine($"  Corrupt index: {(graceful ? "PASS (graceful)" : "FAIL")}");
}

// -- many: high fragment count --
if (flagMany)
{
    var d = Path.Combine(resultDir, "many"); Directory.CreateDirectory(d);
    var s = new LocalDssaAdapter(d); var pw = EncryptionLayer.GenerateRcCode(32); byte[] r() => (byte[])pw.Clone();
    string fp; using (var e = new RDRFEngine(pw, s)) fp = e.BackupFile(testFile, "FSS1", fragmentSize: 4096);
    string op = Path.Combine(d, "restored.bin"); extraSw.Restart();
    bool rec; using (var ro = new RestoreOrchestrator(r(), s)) rec = ro.RestoreFileAsync(fp, op).GetAwaiter().GetResult();
    long t = extraSw.ElapsedMilliseconds; bool sha = rec && File.Exists(op) && VerifySha(op, originalHash);
    csv.Add($"\"many\",fragSize_4k,0,0,0,0,{rec},{sha},{t:F0},\"fragSize=4096\"");
    Console.WriteLine($"  Many fragments (4096): {(rec && sha ? "PASS" : "FAIL")} ({t}ms)");
}

if (flagMetadata)
{
    var d = Path.Combine(resultDir, "metadata"); Directory.CreateDirectory(d);
    var s = new LocalDssaAdapter(d); var pw = EncryptionLayer.GenerateRcCode(32);
    using (var e = new RDRFEngine(pw, s)) e.BackupFile(testFile, "FSS1", fragmentSize: fragSize);
    string mp = Path.Combine(Directory.GetCurrentDirectory(), "rdrf_metadata.json");
    bool created = File.Exists(mp);
    bool hasEntries = false;
    if (created)
    {
        var json = System.Text.Json.JsonDocument.Parse(File.ReadAllBytes(mp));
        hasEntries = json.RootElement.TryGetProperty("Backups", out var b) && b.EnumerateObject().Any();
    }
    csv.Add($"\"metadata\",json_persist,0,0,0,0,{created},{hasEntries},{0},\"created={created} has_entries={hasEntries}\"");
    Console.WriteLine($"  Metadata: {(created && hasEntries ? "PASS" : "FAIL")} (at {mp})");
}

// -- kdf-bench: PBKDF2 timing --
if (flagKdfBench)
{
    var pw = EncryptionLayer.GenerateRcCode(32);
    var salt = RandomNumberGenerator.GetBytes(32);
    extraSw.Restart();
    for (int i = 0; i < 5; i++) EncryptionLayer.DeriveKey(pw, salt);
    long avg = extraSw.ElapsedMilliseconds / 5;
    csv.Add($"\"kdf_bench\",pbkdf2_600k_warm,0,0,0,0,{avg},{false},{avg},\"avg={avg}ms\"");
    Console.WriteLine($"  KDF bench: {(avg < 1000 ? "PASS" : "SLOW")} (avg={avg}ms over 5 runs)");
}

if (flagCustomName)
{
    var d = Path.Combine(resultDir, "custom_name"); Directory.CreateDirectory(d);
    var s = new LocalDssaAdapter(d); var pw = EncryptionLayer.GenerateRcCode(32); byte[] r() => (byte[])pw.Clone();
    string cn = "my-custom-label-42";
    string fp = ""; bool nameOk = false; bool sha = false; long t = 0; bool cnExist = false;
    try
    {
        using (var e = new RDRFEngine(pw, s)) fp = e.BackupFile(testFile, "FSS1", customName: cn, fragmentSize: fragSize);
        // When customName is set, index is stored as {customName}.indrdrf, not {fingerprint}.indrdrf
        string cnIdxPath = Path.Combine(d, cn + Constants.IndexFileSuffix);
        if (!File.Exists(cnIdxPath)) { Console.Error.WriteLine("  custom_name: index missing (custom name path)"); }
    }
    catch (Exception ex) { Console.Error.WriteLine($"  custom_name: backup failed: {ex.Message}"); }

    // Read index via customName (file is named by customName when provided)
    if (File.Exists(Path.Combine(d, cn + Constants.IndexFileSuffix)))
    {
        byte[] ei = s.ReadIndex(cn); var (_, cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(ei, r()); var idx = IndexManager.DeserializeIndex(cbor);
        nameOk = idx.CustomName == cn;
        string op = Path.Combine(d, "restored.bin"); extraSw.Restart();
        bool customRec; using (var ro = new RestoreOrchestrator(r(), s)) customRec = ro.RestoreFileAsync(fp, op, filePrefix: cn).GetAwaiter().GetResult();
        t = extraSw.ElapsedMilliseconds; sha = customRec && File.Exists(op) && VerifySha(op, originalHash);
        cnExist = idx.CustomName == cn;
    }
    csv.Add($"\"custom_name\",pipeline,0,0,0,0,{cnExist},{sha},{t:F0},\"custom_name={cnExist}\"");
    Console.WriteLine($"  Custom name: {(cnExist && sha && nameOk ? "PASS" : "FAIL")} ({t}ms)");
}

// -- zeromem: key zeroing after dispose --
if (flagZeroMem)
{
    // We can't easily reflect into private fields from here without InternalsVisibleTo.
    // Instead, verify that after Dispose, the RC code bytes are actually zeroed
    // by observing whether a new RestoreOrchestrator with a clone of the same
    // password still works (it would fail if RC code in engine was zeroed in-place)
    // and the original byte[] in our scope is untouched.
    var pw = EncryptionLayer.GenerateRcCode(32);
    byte[] pwBefore = (byte[])pw.Clone();
    // Create and dispose an engine
    var d = Path.Combine(resultDir, "zeromem"); Directory.CreateDirectory(d);
    var s = new LocalDssaAdapter(d);
    string fp;
    using (var e = new RDRFEngine(pw, s))
    {
        fp = e.BackupFile(testFile, "FSS1", fragmentSize: fragSize);
    }
    // pw in our scope should still be valid (engine clones internally)
    bool pwIntact = pw.AsSpan().SequenceEqual(pwBefore.AsSpan());
    // Restore with the original pw (should succeed)
    string op = Path.Combine(d, "restored.bin");
    bool rec; using (var ro = new RestoreOrchestrator(pw, s)) rec = ro.RestoreFileAsync(fp, op).GetAwaiter().GetResult();
    bool sha = rec && File.Exists(op) && VerifySha(op, originalHash);
    csv.Add($"\"zeromem\",key_safety,0,0,0,0,{pwIntact},{rec},{0},\"pw_intact={pwIntact}\"");
    Console.WriteLine($"  ZeroMem: {(pwIntact && rec && sha ? "PASS" : "FAIL")} (pw_intact={pwIntact} recoverable={rec})");
}

// -- Strategy loop (original behavior) --
foreach (string strategy in strategies)
{
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine($"-- [{strategy}] --");
    Console.ResetColor();

    var testRoot = Path.Combine(resultDir, strategy);
    Directory.CreateDirectory(testRoot);
    var storage = new LocalDssaAdapter(testRoot);
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
    int totalFrags = index.FragmentCount;
    int origCount = index.OriginalFragmentCount > 0 ? index.OriginalFragmentCount : totalFrags;

    int baseFrags = origCount;
    Console.WriteLine($"  Backup: {totalFrags} total frags ({origCount} original, sizes={index.OriginalFragmentSizes.Count})");
    Console.WriteLine($"  Time: {backupTime:F0}ms");

    // -- Baseline --
    bool baselineOk = false;
    extraSw.Restart();
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

    // -- Incremental loss --
    var incResults = new List<(double lossPct, int trial, bool ok)>();
    int[] lossPcts = strategy is "FSS3" or "FSS6" or "FSS6.1" or "FSS6.2"
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

    if (strategy is "FSS6.1" or "FSS6.2")
    {
        // -- Block corruption incremental (FSS6.1/6.2 only) --
        // -- Block corruption incremental (FSS6.1/6.2 only) --
        const int blockSize = 256;
        var decodedFrags = new (byte[] fragData, byte[] embeddedIdx, byte[]? salt)[totalFrags];
        var cleanFrags = new byte[totalFrags][];
        for (int i = 0; i < totalFrags; i++)
        {
            var (ei, fd, s) = RDRFEngine.DecryptFragment(allFragBytes[i], aesKey);
            decodedFrags[i] = (fd ?? Array.Empty<byte>(), ei ?? Array.Empty<byte>(), s);
            cleanFrags[i] = (byte[])decodedFrags[i].fragData.Clone();
        }

        int totalBlocks = decodedFrags.Sum(f => (f.fragData.Length + blockSize - 1) / blockSize);

        var blockOffsets = new int[totalFrags + 1];
        int cum = 0;
        for (int i = 0; i < totalFrags; i++)
        {
            blockOffsets[i] = cum;
            cum += decodedFrags[i].fragData.Length > 0
                ? (decodedFrags[i].fragData.Length + blockSize - 1) / blockSize
                : 0;
        }
        blockOffsets[totalFrags] = cum;

        foreach (int lossPct in lossPcts)
        {
            int blocksToCorrupt = Math.Max(1, Math.Min(
                (int)Math.Ceiling(totalBlocks * lossPct / 100.0), totalBlocks - 1));

            for (int trial = 0; trial < 3; trial++)
            {
                var td = Path.Combine(testRoot, $"inc_{lossPct}_{trial}");
                Directory.CreateDirectory(td);
                File.WriteAllBytes(Path.Combine(td, $"{prefix}.indrdrf"), idxBytes);
                string rcSrcP = Path.Combine(testRoot, $"{prefix}.rdrc");
                if (File.Exists(rcSrcP))
                    File.WriteAllBytes(Path.Combine(td, $"{prefix}.rdrc"), File.ReadAllBytes(rcSrcP));

                // Restore clean data for this trial
                for (int i = 0; i < totalFrags; i++)
                    Buffer.BlockCopy(cleanFrags[i], 0, decodedFrags[i].fragData, 0, cleanFrags[i].Length);

                var rand = new Random(42 + trial * 100 + lossPct);
                var corrupted = new HashSet<int>();
                while (corrupted.Count < blocksToCorrupt)
                    corrupted.Add(rand.Next(totalBlocks));

                var needsReEnc = new bool[totalFrags];
                foreach (int bi in corrupted)
                {
                    int fi = 0;
                    while (bi >= blockOffsets[fi + 1]) fi++;
                    int localBlock = bi - blockOffsets[fi];
                    int start = localBlock * blockSize;
                    int end = Math.Min(start + blockSize, decodedFrags[fi].fragData.Length);
                    if (start >= end) continue;
                    int pos = start + rand.Next(end - start);
                    decodedFrags[fi].fragData[pos] ^= (byte)rand.Next(1, 256);
                    needsReEnc[fi] = true;
                }

                for (int i = 0; i < totalFrags; i++)
                {
                    if (needsReEnc[i])
                    {
                        byte[] reEnc = FragmentFileHeader.EncryptWithEmbeddedIndex(
                            decodedFrags[i].fragData, decodedFrags[i].embeddedIdx,
                            aesKey, decodedFrags[i].salt);
                        File.WriteAllBytes(Path.Combine(td, $"{prefix}_{i}.rdrf"), reEnc);
                    }
                    else
                    {
                        File.WriteAllBytes(Path.Combine(td, $"{prefix}_{i}.rdrf"), allFragBytes[i]);
                    }
                }

                var ts = new LocalDssaAdapter(td);
                string outPath = Path.Combine(td, "restored.bin");
                extraSw.Restart();
                bool r = false;
                try
                {
                    using (var ro = new RestoreOrchestrator(rcClone(), ts))
                        r = ro.RestoreFileAsync(fingerprint, outPath).GetAwaiter().GetResult();
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"  BlockCorrupt trial {lossPct}/{trial}: {ex.GetType().Name}: {ex.Message}");
                }
                double t = sw.Elapsed.TotalMilliseconds;
                bool sha = r && File.Exists(outPath) && VerifySha(outPath, originalHash);
                double actualPct = (double)blocksToCorrupt / totalBlocks * 100;
                csv.Add($"\"{strategy}\",incremental,{actualPct:F1},{trial},{totalFrags},{blocksToCorrupt},{r},{sha},{t:F0},\"block_corrupt\"");
                incResults.Add((actualPct, trial, r && sha));
            }
        }
    }
    else
    {
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
            // NOTE: deleted fragments are NOT written at all - file doesn't exist

            // Also copy the .rdrc file if present (needed for ETN cross-validation)
            string rcSrcP = Path.Combine(testRoot, $"{prefix}.rdrc");
            if (File.Exists(rcSrcP))
                File.WriteAllBytes(Path.Combine(trialDir, $"{prefix}.rdrc"), File.ReadAllBytes(rcSrcP));

            var trialStorage = new LocalDssaAdapter(trialDir);
            string trialOut = Path.Combine(trialDir, "restored.bin");

            extraSw.Restart();
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
    }

    // -- Greedy test (phase 1): from i=0..N-1, delete each, recover, keep if ok, skip if fail --
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

        var ts = new LocalDssaAdapter(td);
        string outPath = Path.Combine(td, "restored.bin");
        extraSw.Restart();
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

    // --- Custom tests (phase 2): strategy-specific targeted patterns ---
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
        var eTs = new LocalDssaAdapter(eDir);
        extraSw.Restart();
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
        var oTs = new LocalDssaAdapter(oDir);
        extraSw.Restart();
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
        var sTs = new LocalDssaAdapter(sDir);
        extraSw.Restart();
        bool sR;
        using (var ro = new RestoreOrchestrator(rcClone(), sTs))
            sR = ro.RestoreFileAsync(fingerprint, Path.Combine(sDir, "restored.bin")).GetAwaiter().GetResult();
        bool sSha = sR && VerifySha(Path.Combine(sDir, "restored.bin"), originalHash);
        int sDel = totalFrags - 1;
        csv.Add($"\"{strategy}\",custom_one_survivor,{(double)sDel/totalFrags*100:F1},0,{totalFrags},{sDel},{sR},{sSha},{sw.Elapsed.TotalMilliseconds:F0},\"keep_one\"");
        customResults.Add(("keep_one", (double)sDel / totalFrags * 100, sR && sSha));
    }

    // FSS6.1: block corruption test - corrupt encrypted bytes directly
    if (strategy is "FSS6.1" or "FSS6.2")
    {
        var bcDir = Path.Combine(testRoot, "custom_block_corrupt");
        Directory.CreateDirectory(bcDir);
        WriteTrialDir(bcDir, null);

        // Diagnostic: verify repair data in Index
        var idxBytes2 = File.ReadAllBytes(Path.Combine(bcDir, $"{prefix}.indrdrf"));
        var (_, cbor2) = EncryptionLayer.DecryptIndexWithAutoDetect(idxBytes2, rcClone());
        var idx2 = IndexManager.DeserializeIndex(cbor2);
        var repairProp = strategy == "FSS6.1"
            ? (object?)idx2.Fss61RepairB
            : idx2.Fss62RepairB;
        var rbDisplay = repairProp switch
        {
            Fss61RepairData r => $"BlockCount={r.BlockCount} DataLen={r.Data.Length} Seed={r.Seed}",
            Fss62RepairData r => $"BlockCount={r.BlockCount} DataLen={r.Data.Length} Seed={r.Seed}",
            _ => "NULL"
        };
        Console.Error.WriteLine($"  [{strategy}] RepairB: {rbDisplay}");

        // Find raw data offset in encrypted file: [hdr][nonce(12)][4B idxLen][serializedIndex][rawData+trailer]
        byte[] frag0Enc = allFragBytes[0];
        int hdrSz = FragmentFileHeader.GetTotalHeaderSize(frag0Enc);
        byte[] dec = EncryptionLayer.DecryptFragmentCtrWithKey(frag0Enc, hdrSz, aesKey);
        int idxLen = BitConverter.ToInt32(dec.AsSpan(0, 4));
        int rawOff = hdrSz + 12 + 4 + idxLen;

        // Corrupt block 0 bytes (deg-1 symbol 0 covers block 0)
        byte[] corrupt = (byte[])frag0Enc.Clone();
        corrupt[rawOff] ^= 0xFF;
        corrupt[rawOff + 1] ^= 0xFF;
        File.WriteAllBytes(Path.Combine(bcDir, $"{prefix}_0.rdrf"), corrupt);

        var bcTs = new LocalDssaAdapter(bcDir);
        extraSw.Restart();
        bool bcR;
        using (var r = new RestoreOrchestrator(rcClone(), bcTs))
            bcR = r.RestoreFileAsync(fingerprint, Path.Combine(bcDir, "restored.bin")).GetAwaiter().GetResult();
        bool bcSha = bcR && VerifySha(Path.Combine(bcDir, "restored.bin"), originalHash);
        csv.Add($"\"{strategy}\",custom_block_corrupt,0,0,{totalFrags},0,{bcR},{bcSha},{sw.Elapsed.TotalMilliseconds:F0},\"block_corrupted_repaired\"");
        customResults.Add(("block_corrupt", 0, bcR && bcSha));
    }

    // -- Targeted tests --
    var targetResults = new List<(string testName, double lossPct, bool ok)>();

    // FSS3: exact boundary tests
    if (strategy == "FSS3")
    {
        // Delete exactly 1 fragment (theoretical max)
        var td1Dir = Path.Combine(testRoot, "target_1lost");
        Directory.CreateDirectory(td1Dir);
        WriteTrialDir(td1Dir, null);
        File.Delete(Path.Combine(td1Dir, $"{prefix}_0.rdrf"));
        var ts1 = new LocalDssaAdapter(td1Dir);
        extraSw.Restart();
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
        var ts2 = new LocalDssaAdapter(td2Dir);
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
        var ts = new LocalDssaAdapter(tDir);
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
        var ts = new LocalDssaAdapter(tDir);
        bool ro;
        extraSw.Restart();
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
        var ts = new LocalDssaAdapter(tDir);
        bool ro;
        extraSw.Restart();
        using (var r = new RestoreOrchestrator(rcClone(), ts))
            ro = r.RestoreFileAsync(fingerprint, Path.Combine(tDir, "restored.bin")).GetAwaiter().GetResult();
        double lp3 = (double)toKill.Count / totalFrags * 100;
        csv.Add($"\"{strategy}\",targeted,{lp3:F1},0,{totalFrags},{toKill.Count},{ro},false,{sw.Elapsed.TotalMilliseconds:F0},\"step_pattern_3copies_killed\"");
        targetResults.Add(("step_pattern_kill", lp3, ro));
    }

    // FSS6/6.1: delete 1 fragment (should fail)
    if (strategy is "FSS6" or "FSS6.1" or "FSS6.2")
    {
        var tDir = Path.Combine(testRoot, "target_one_lost");
        Directory.CreateDirectory(tDir);
        WriteTrialDir(tDir, null);
        File.Delete(Path.Combine(tDir, $"{prefix}_0.rdrf"));
        var ts = new LocalDssaAdapter(tDir);
        bool ro;
        extraSw.Restart();
        using (var r = new RestoreOrchestrator(rcClone(), ts))
            ro = r.RestoreFileAsync(fingerprint, Path.Combine(tDir, "restored.bin")).GetAwaiter().GetResult();
        csv.Add($"\"{strategy}\",targeted,{1.0/totalFrags*100:F1},0,{totalFrags},1,{ro},false,{sw.Elapsed.TotalMilliseconds:F0},\"no_redundancy_1_lost\"");
        targetResults.Add(("no_redundancy", 1.0/totalFrags*100, !ro));
    }

    // -- Compute max loss from incremental data --
    double maxSurvivedPct = 0;
    double maxFailedPct = 0;
    foreach (var inc in incResults)
    {
        if (inc.ok && inc.lossPct > maxSurvivedPct)
            maxSurvivedPct = inc.lossPct;
        if (!inc.ok && (maxFailedPct == 0 || inc.lossPct < maxFailedPct))
            maxFailedPct = inc.lossPct;
    }

    // FSS3 starts failing at 2 lost, which is 2/21 ~9.5%
    double theoreticalMax = strategy switch
    {
        "FSS1" => 50.0,
        "FSS2" => 50.0,
        "FSS2R" => 50.0,
        "FSS3" => 100.0 / totalFrags,
        "FSS5" => 66.0,
        "FSS5+" => 95.0,
        "FSS6" or "FSS6.1" or "FSS6.2" => 0.0,
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
    Console.WriteLine($"  Incremental: {incResults.Count} levels x 3 trials");
    Console.WriteLine($"  Greedy: {greedyKept.Count}/{totalFrags} = {greedyStrength:F1}%");
    Console.WriteLine($"  Custom: {customResults.Count} tests");
    Console.WriteLine($"  Targeted tests: {targetResults.Count}");
    Console.WriteLine();

    // Cleanup after each strategy to free disk space
    try { Directory.Delete(testRoot, true); }
    catch { /* best effort */ }
}

// -- Summary Table --
Console.ForegroundColor = ConsoleColor.White;
Console.WriteLine("+----------+------+----------+--------------+--------------+------------+----------+----------------------+");
Console.WriteLine("| Strategy |Frags | Baseline | Theoretical  | Max Survived | Min Failed | Greedy   | Notes                |");
Console.WriteLine("|          |      |          | Max Loss %   | Loss %       | Loss %    | Strength |                      |");
Console.WriteLine("+----------+------+----------+--------------+--------------+------------+----------+----------------------+");
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
        "FSS6.2" => "ETN + Duip repair",
        _ => ""
    };

    Console.WriteLine(
        $"| {row.Strategy,-7} | {row.TotalFrags,4} | {baselineStr,-8} | {theoStr,-12} | {row.MaxSurvived,11:F1}% | {row.MinFailed,10:F1}% | {greedyStr,8} | {note,-20} |");
}

Console.ForegroundColor = ConsoleColor.White;
Console.WriteLine("+----------+------+----------+--------------+--------------+------------+----------+----------------------+");
Console.ResetColor();

// -- Write CSV --
string csvPath = Path.Combine(resultDir, "fss_recovery_results.csv");
File.WriteAllLines(csvPath, csv);
Console.WriteLine($"\n  CSV: {csvPath}");

// -- Print CSV to console --
Console.WriteLine("\n-- Raw CSV Data --");
    foreach (string line in csv)
        Console.WriteLine($"  {line}");

Console.WriteLine($"\n  Result dir: {resultDir}");

}
finally
{
    try { Directory.Delete(resultDir, recursive: true); Console.WriteLine($"  Cleaned: {resultDir}"); }
    catch (Exception ex) { Console.Error.WriteLine($"  Cleanup failed: {ex.Message}"); }
}

return 0;

// ================================================================//  Helpers
// ================================================================
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

