using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.FSS;
using RDRF.Core.Index;
using RDRF.Core.Storage;

// Test file
string testFile = args.Length > 0 && File.Exists(args[0])
    ? args[0]
    : Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "..", "tests", "1.mp4"));
if (!File.Exists(testFile)) { Console.Error.WriteLine($"File not found: {testFile}"); return 1; }

byte[] originalHash = SHA256.HashData(File.ReadAllBytes(testFile));
long fileSize = new FileInfo(testFile).Length;
int fragSize = 256 * 1024;
string strategy = "FSS6.1";
string pwd = "fss61_test";
byte[] rcMaster = Encoding.UTF8.GetBytes(pwd);
byte[] rcClone() => (byte[])rcMaster.Clone();

string resultDir = Path.Combine(Path.GetTempPath(), $"fss61_test_{Guid.NewGuid():N}");
Directory.CreateDirectory(resultDir);
Console.WriteLine($"Result dir: {resultDir}");

// ── Backup ──
var storage = new LocalFileAdapter(resultDir);
string fingerprint;
using (var engine = new RDRFEngine(rcMaster, storage))
    fingerprint = engine.BackupFile(testFile, strategy, fragmentSize: fragSize);

byte[] encIndex = storage.ReadIndex(fingerprint);
var (aesKey, idxCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encIndex, rcClone());
var index = IndexManager.DeserializeIndex(idxCbor);
string prefix = index.CustomName ?? fingerprint;
int totalFrags = index.FragentCount;

Console.WriteLine($"Backup: {totalFrags} fragments, strategy={index.FssStrategy}, fingerprint={fingerprint}");

// ── Pre-load encrypted fragments ──
var allFragBytes = new byte[totalFrags][];
for (int i = 0; i < totalFrags; i++)
    allFragBytes[i] = File.ReadAllBytes(Path.Combine(resultDir, $"{prefix}_{i}.rdrf"));
byte[] idxBytes = File.ReadAllBytes(Path.Combine(resultDir, $"{prefix}.indrdrf"));

// Read actual block size from RC file repair data
int blockSize = 512;
string rcPath = Path.Combine(resultDir, $"{prefix}.rdrc");
if (File.Exists(rcPath))
{
    byte[] encRc = File.ReadAllBytes(rcPath);
    byte[] rcDec = EncryptionLayer.DecryptFragmentWithKey(encRc, aesKey);
    var rcFile = RDRF.Core.Storage.RcFile.FromCbor(rcDec);
    if (rcFile.RepairB?.BlockSize > 0)
        blockSize = rcFile.RepairB.BlockSize;
}
Console.WriteLine($"Block size from RC: {blockSize}");

// Compute block offsets for each fragment
int[] blocksPerFrag = new int[totalFrags];
int totalBlocks = 0;
int[] fragDataStart = new int[totalFrags];
int[] rawDataLen = new int[totalFrags];

for (int i = 0; i < totalFrags; i++)
{
    byte[] encrypted = allFragBytes[i];
    int hdrSize = FragmentFileHeader.GetTotalHeaderSize(encrypted);
    byte[] decrypted = EncryptionLayer.DecryptFragmentCtrWithKey(encrypted, hdrSize, aesKey);
    int idxLen = BitConverter.ToInt32(decrypted.AsSpan(0, 4));

    // Extract fulldata (raw fragment data + FSS6.1 repair trailer)
    byte[] fulldata = new byte[decrypted.Length - 4 - idxLen];
    Buffer.BlockCopy(decrypted, 4 + idxLen, fulldata, 0, fulldata.Length);

    // Use Fss61RepairTrailer to properly parse and get raw data length
    var (raw, _, _, _, _) = Fss61RepairTrailer.Parse(fulldata);
    rawDataLen[i] = raw.Length;
    blocksPerFrag[i] = (raw.Length + blockSize - 1) / blockSize;
    totalBlocks += blocksPerFrag[i];

    // File offset where raw fragment data starts (in encrypted file)
    fragDataStart[i] = hdrSize + 12 + 4 + idxLen;
}

Console.WriteLine($"Total blocks: {totalBlocks}, blockSize={blockSize}");

// Build cumulative block offsets
int[] cumBlocks = new int[totalFrags + 1];
for (int i = 0; i < totalFrags; i++)
    cumBlocks[i + 1] = cumBlocks[i] + blocksPerFrag[i];

Console.WriteLine($"\n═══ FSS6.1 Block Corruption Incremental Test ═══\n");

// Parse args: -set <range>&<range>... -trials <N>
(int[] pcts, int tcount) ParseArgs(string[] a)
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
var (corruptPcts, trials) = ParseArgs(args);
if (corruptPcts.Length == 0) corruptPcts = [10, 30, 50, 70, 80, 85, 90, 95, 97, 98, 99, 100];
if (trials <= 0) trials = 3;

Console.WriteLine($"Corruption set: [{string.Join(", ", corruptPcts)}]");
Console.WriteLine($"Trials: {trials}");

var csv = new List<string> { "corrupt_pct,blocks_corrupted,blocks_total,trial,recovered,sha_match,time_ms" };
int maxSurvived = 0, minFailed = int.MaxValue;

foreach (int cpct in corruptPcts)
{
    int blocksToCorrupt = Math.Max(1, totalBlocks * cpct / 100);
    if (blocksToCorrupt >= totalBlocks) blocksToCorrupt = totalBlocks - 1;

    for (int t = 0; t < trials; t++)
    {
        // Create trial directory with fresh copies of all files
        var trialDir = Path.Combine(resultDir, $"corrupt_{cpct}_{t}");
        Directory.CreateDirectory(trialDir);
        File.WriteAllBytes(Path.Combine(trialDir, $"{prefix}.indrdrf"), idxBytes);
        string rcP = Path.Combine(resultDir, $"{prefix}.rdrc");
        if (File.Exists(rcP))
            File.WriteAllBytes(Path.Combine(trialDir, $"{prefix}.rdrc"), File.ReadAllBytes(rcP));

        // Pick random blocks to corrupt
        var rng = new Random(42 + t * 100 + cpct);
        var badBlocks = new HashSet<int>();
        while (badBlocks.Count < blocksToCorrupt)
            badBlocks.Add(rng.Next(totalBlocks));

        // Corrupt each selected block in the encrypted fragment data
        // For each block, find which fragment owns it and at which byte offset
        var corruptedFrags = new HashSet<int>();
        foreach (int bi in badBlocks)
        {
            int fi = 0;
            while (fi < totalFrags && bi >= cumBlocks[fi + 1]) fi++;
            int localBlock = bi - cumBlocks[fi];
            int fragByteOff = localBlock * blockSize;

            // Read the encrypted fragment file
            byte[] fragEnc = allFragBytes[fi]; // original encrypted data
            byte[] corruptCopy = (byte[])fragEnc.Clone();

            // Compute the file offset for the raw data byte
            int fileOff = fragDataStart[fi] + fragByteOff;

            if (fileOff < corruptCopy.Length)
            {
                // XOR a random byte at a random position within this block
                int maxOff = Math.Min(blockSize, corruptCopy.Length - fileOff);
                int xorOff = rng.Next(maxOff);
                corruptCopy[fileOff + xorOff] ^= (byte)(1 + rng.Next(254));
                corruptedFrags.Add(fi);
            }

            // Write back the corrupted fragment
            File.WriteAllBytes(Path.Combine(trialDir, $"{prefix}_{fi}.rdrf"), corruptCopy);
        }

        // Attempt restore
        var trialStorage = new LocalFileAdapter(trialDir);
        string outPath = Path.Combine(trialDir, "restored.bin");

        // Pre-check: verify Fss61RepairB and file existence
        var checkIdxBytes = File.ReadAllBytes(Path.Combine(trialDir, $"{prefix}.indrdrf"));
        var (checkKey, checkCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(checkIdxBytes, rcClone());
        var checkIndex = IndexManager.DeserializeIndex(checkCbor);
        var rb = checkIndex.Fss61RepairB;
        bool hasRb = rb != null;
        bool rcExists = File.Exists(Path.Combine(trialDir, $"{prefix}.rdrc"));
        bool frag0Exists = File.Exists(Path.Combine(trialDir, $"{prefix}_0.rdrf"));
        long idxSize = new FileInfo(Path.Combine(trialDir, $"{prefix}.indrdrf")).Length;
        long frag0Size = frag0Exists ? new FileInfo(Path.Combine(trialDir, $"{prefix}_0.rdrf")).Length : 0;

        Console.Error.WriteLine($"  [DBG] {cpct}%/{t}: Fss61RepairB={hasRb} rcExists={rcExists} frag0={frag0Exists}({frag0Size}) idxSize={idxSize} prefix={prefix} blocks={blocksToCorrupt}");

        var sw = Stopwatch.StartNew();
        bool recovered;
        try
        {
            using (var r = new RestoreOrchestrator(rcClone(), trialStorage))
                recovered = r.RestoreFileAsync(fingerprint, outPath).GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"  [ERR] Restore exception: {ex.GetType().Name}: {ex.Message}");
            recovered = false;
        }
        sw.Stop();

        bool shaOk = recovered && File.Exists(outPath) && VerifySha(outPath, originalHash);
        bool ok = recovered && shaOk;
        Console.Error.WriteLine($"  [TIME] {cpct}% corrupt: {sw.ElapsedMilliseconds}ms  ok={ok}");

        csv.Add($"{cpct},{blocksToCorrupt},{totalBlocks},{t},{ok},{shaOk},{sw.ElapsedMilliseconds}");
        if (ok && cpct > maxSurvived) maxSurvived = cpct;
        if (!ok && cpct < minFailed) minFailed = cpct;
    }
}

// ── Results ──
Console.WriteLine($"\n═══ FSS6.1 Repair Strength (blockSize={blockSize}) ═══");
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
        string key = $"{cp},{b},{totalBlocks},{t}";
        var m = csv.FirstOrDefault(l => l.StartsWith(key));
        if (m != null) { var p = m.Split(','); if (p[4] == "True") pass++; }
    }
    Console.Write(pass == trials ? "  ✓✓✓  " : pass >= 2 ? "  ✓✓   " : pass >= 1 ? "  ✓    " : "  ✗✗✗  ");
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
        string key = $"{cp},{b},{totalBlocks},{t}";
        var m = csv.FirstOrDefault(l => l.StartsWith(key));
        if (m != null) { var p = m.Split(','); if (p[5] == "True") match++; }
    }
    Console.Write(match == 3 ? "  ✓✓✓  " : match >= 2 ? "  ✓✓   " : match >= 1 ? "  ✓    " : "  ✗✗✗  ");
}
Console.WriteLine();
Console.WriteLine(new string('─', 70));
Console.WriteLine($"Legend: ✓✓✓ = {trials}/{trials}  ✓✓ = 2/{trials}  ✓ = 1/{trials}  ✗✗✗ = 0/{trials}");
Console.WriteLine($"\nThreshold: repair succeeds at ≤{maxSurvived}% corruption, fails at ≥{minFailed}%");

// ── Cleanup ──
try { Directory.Delete(resultDir, recursive: true); Console.WriteLine($"\nCleaned: {resultDir}"); }
catch (Exception ex) { Console.Error.WriteLine($"Cleanup failed: {ex.Message}"); }
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
