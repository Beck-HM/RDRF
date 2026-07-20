using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using RDRF.Core;
using RDRF.Core.Compression;
using RDRF.Core.DSAA;
using RDRF.Core.Encryption;

// RDRF performance benchmark — strategies, compress/decompress, full backup/restore.
// Paths (repo convention):
//   Input:  tests/RDRF_TestInput/  (default: bench_doc.bin)
//   Output: tests/RDRF_TestOutput/PerfBench_<timestamp>/  (CSV + summary; work dirs cleaned)
//
// Usage:
//   dotnet run -c Release --project tools/RDRF.PerfBench -- [options]
//   --input <path>     payload file (default: tests/RDRF_TestInput/bench_doc.bin)
//   --size-mb <n>      if input missing/small, generate synthetic payload of n MB (default: 32)
//   --quick            fewer combos (FSS1/3/6.1 + lz4/zstd/ckc only)
//   --keep             keep work directories under the run folder (default: delete after measure)
//   --no-compress-api  skip pure Compressor.Compress/Decompress matrix
//   --no-backup        skip full backup/restore matrix
//   --out <dir>        override report root (default: tests/RDRF_TestOutput/PerfBench_<ts>)

static string RepoRoot()
{
    // bin/Release/net8.0 -> tools/RDRF.PerfBench -> tools -> repo
    return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
}

static string[] ParseArgs(string[] args)
{
    return args;
}

var argv = ParseArgs(args);
string? optInput = null;
string? optOut = null;
int sizeMb = 32;
bool quick = false;
bool keep = false;
bool doCompressApi = true;
bool doBackup = true;

for (int i = 0; i < argv.Length; i++)
{
    string a = argv[i];
    string? Next() => i + 1 < argv.Length ? argv[++i] : null;
    switch (a)
    {
        case "--input": optInput = Next(); break;
        case "--out": optOut = Next(); break;
        case "--size-mb":
            if (int.TryParse(Next(), out int mb)) sizeMb = Math.Clamp(mb, 1, 2048);
            break;
        case "--quick": quick = true; break;
        case "--keep": keep = true; break;
        case "--no-compress-api": doCompressApi = false; break;
        case "--no-backup": doBackup = false; break;
        case "-h":
        case "--help":
            Console.WriteLine("""
                RDRF.PerfBench — performance matrix for strategies / compression / backup+restore

                Paths:
                  Input:  tests/RDRF_TestInput/bench_doc.bin  (or --input)
                  Output: tests/RDRF_TestOutput/PerfBench_<timestamp>/

                Options:
                  --input <path>     source payload
                  --size-mb <n>      synthetic size if generating (default 32)
                  --quick            reduced matrix
                  --keep             keep intermediate backup dirs
                  --no-compress-api  skip pure compress/decompress
                  --no-backup        skip full backup/restore
                  --out <dir>        report directory
                """);
            return 0;
        default:
            Console.Error.WriteLine($"Unknown arg: {a}");
            return 2;
    }
}

string repo = RepoRoot();
string defaultInput = Path.Combine(repo, "tests", "RDRF_TestInput", "bench_doc.bin");
string inputPath = optInput ?? defaultInput;
string runId = DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
string reportRoot = optOut ?? Path.Combine(repo, "tests", "RDRF_TestOutput", $"PerfBench_{runId}");
string workRoot = Path.Combine(reportRoot, "work");
Directory.CreateDirectory(workRoot);

// Resolve payload: prefer fixture; optionally truncate/pad to sizeMb when --size-mb forces synthetic
string payloadPath = Path.Combine(workRoot, "payload.bin");
long payloadBytes;
try
{
    payloadBytes = PreparePayload(inputPath, payloadPath, sizeMb, quick);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Payload error: {ex.Message}");
    return 1;
}

byte[]? payloadBytesCache = null; // loaded lazily for compress-api (cap large files)
var rows = new List<ResultRow>();
var proc = Process.GetCurrentProcess();

Console.WriteLine("=== RDRF.PerfBench ===");
Console.WriteLine($"repo     = {repo}");
Console.WriteLine($"input    = {inputPath}");
Console.WriteLine($"payload  = {payloadPath} ({payloadBytes:N0} bytes)");
Console.WriteLine($"report   = {reportRoot}");
Console.WriteLine($"quick    = {quick}  keep_work = {keep}");
Console.WriteLine();

// ---- 1) Pure compress / decompress ----
string[] compressMethods = quick
    ? new[] { "lz4", "zstd", "gzip", "ckc" }
    : new[] { "lz4", "lz4hc", "zstd", "gzip", "brotli", "lzma2", "lzo", "xz", "ckc" };

if (doCompressApi)
{
    Console.WriteLine("--- Compress / Decompress (Compressor API) ---");
    const long maxLoad = 64L * 1024 * 1024; // load at most 64MB for API microbench
    long take = Math.Min(payloadBytes, maxLoad);
    payloadBytesCache = new byte[take];
    using (var fs = File.OpenRead(payloadPath))
    {
        int read = 0;
        while (read < take)
        {
            int n = fs.Read(payloadBytesCache, read, (int)(take - read));
            if (n <= 0) break;
            read += n;
        }
        if (read < take)
            Array.Resize(ref payloadBytesCache, read);
    }

    foreach (string method in compressMethods)
    {
        var row = BenchCompressApi(method, payloadBytesCache, proc);
        rows.Add(row);
        PrintRow(row);
    }
    Console.WriteLine();
}

// ---- 2) Full backup + restore matrix ----
string[] strategies = quick
    ? new[] { "FSS1", "FSS3", "FSS6.1" }
    : new[] { "FSS1", "FSS2", "FSS2R", "FSS3", "FSS5", "FSS5+", "FSS6", "FSS6.1", "FSS6.2" };

// Full strategy × compression can explode; default: all strategies with lz4 + FSS1 × all compressors.
var backupJobs = new List<(string strategy, string compression)>();
if (doBackup)
{
    foreach (string s in strategies)
        backupJobs.Add((s, "lz4"));

    if (!quick)
    {
        foreach (string c in compressMethods)
        {
            if (c == "lz4") continue;
            backupJobs.Add(("FSS1", c));
        }
        // FSS6.x + a couple compressors (heavier)
        backupJobs.Add(("FSS6.1", "zstd"));
        backupJobs.Add(("FSS6", "lz4"));
    }
    else
    {
        backupJobs.Add(("FSS1", "zstd"));
        backupJobs.Add(("FSS1", "ckc"));
    }

    Console.WriteLine("--- Backup / Restore (RDRFEngine, single-strategy) ---");
    foreach (var (strategy, compression) in backupJobs)
    {
        var row = BenchBackupRestore(payloadPath, payloadBytes, strategy, compression, workRoot, proc, keep);
        rows.Add(row);
        PrintRow(row);
    }
    Console.WriteLine();
}

// ---- Write reports ----
Directory.CreateDirectory(reportRoot);
string csvPath = Path.Combine(reportRoot, "results.csv");
string mdPath = Path.Combine(reportRoot, "results.md");
WriteCsv(csvPath, rows);
WriteMarkdown(mdPath, rows, payloadPath, payloadBytes, quick);

// ---- Auto cleanup work dirs ----
if (!keep)
{
    try
    {
        if (Directory.Exists(workRoot))
            Directory.Delete(workRoot, recursive: true);
        Console.WriteLine($"Cleaned work dir: {workRoot}");
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Warning: cleanup failed: {ex.Message}");
    }
}
else
{
    Console.WriteLine($"Kept work dir: {workRoot}");
}

int fails = rows.Count(r => !r.Ok);
Console.WriteLine();
Console.WriteLine($"Done. rows={rows.Count} fails={fails}");
Console.WriteLine($"CSV: {csvPath}");
Console.WriteLine($"MD:  {mdPath}");
return fails > 0 ? 1 : 0;

// ================= helpers =================

static long PreparePayload(string preferredInput, string destPath, int sizeMb, bool quick)
{
    Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);
    long target = (long)sizeMb * 1024 * 1024;
    if (quick && target > 16L * 1024 * 1024)
        target = 16L * 1024 * 1024;

    if (File.Exists(preferredInput))
    {
        long len = new FileInfo(preferredInput).Length;
        // Use fixture as-is when large enough; otherwise generate to target size.
        if (len >= Math.Min(target, 1024 * 1024))
        {
            // Copy or truncate to target for consistent benches when target < file
            using var src = File.OpenRead(preferredInput);
            using var dst = File.Create(destPath);
            long toCopy = Math.Min(len, target);
            byte[] buf = new byte[1024 * 1024];
            long left = toCopy;
            while (left > 0)
            {
                int n = src.Read(buf, 0, (int)Math.Min(buf.Length, left));
                if (n <= 0) break;
                dst.Write(buf, 0, n);
                left -= n;
            }
            // Pad if fixture shorter than target
            if (dst.Length < target)
            {
                var pad = new byte[1024 * 1024];
                new Random(42).NextBytes(pad);
                while (dst.Length < target)
                {
                    int w = (int)Math.Min(pad.Length, target - dst.Length);
                    // make compressible
                    for (int i = 0; i < w; i += 4) pad[i] = 0;
                    dst.Write(pad, 0, w);
                }
            }
            return new FileInfo(destPath).Length;
        }
    }

    // Fully synthetic
    using (var fs = File.Create(destPath))
    {
        var buf = new byte[1024 * 1024];
        var rng = new Random(42);
        long written = 0;
        while (written < target)
        {
            rng.NextBytes(buf);
            for (int i = 0; i < buf.Length; i += 4) buf[i] = 0;
            int w = (int)Math.Min(buf.Length, target - written);
            fs.Write(buf, 0, w);
            written += w;
        }
    }
    return new FileInfo(destPath).Length;
}

static ResultRow BenchCompressApi(string method, byte[] data, Process proc)
{
    var row = new ResultRow
    {
        Category = "compress_api",
        Strategy = "-",
        Compression = method,
        PayloadBytes = data.LongLength,
    };
    try
    {
        GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
        long ws0 = proc.WorkingSet64;
        var sw = Stopwatch.StartNew();
        byte[] compressed = Compressor.AlwaysCompress(data, method);
        sw.Stop();
        row.CompressMs = sw.Elapsed.TotalMilliseconds;
        row.CompressedBytes = compressed.LongLength;

        sw.Restart();
        byte[] round = Compressor.Decompress(compressed, method);
        sw.Stop();
        row.DecompressMs = sw.Elapsed.TotalMilliseconds;
        proc.Refresh();
        row.PeakDeltaMb = Math.Max(0, (proc.WorkingSet64 - ws0) / (1024.0 * 1024.0));

        row.Ok = round.AsSpan().SequenceEqual(data);
        row.Note = row.Ok ? "" : "roundtrip_mismatch";
        if (row.Ok && data.Length > 0)
        {
            row.Ratio = compressed.Length / (double)data.Length;
            row.CompressMBps = (data.Length / (1024.0 * 1024.0)) / Math.Max(row.CompressMs / 1000.0, 1e-9);
            row.DecompressMBps = (data.Length / (1024.0 * 1024.0)) / Math.Max(row.DecompressMs / 1000.0, 1e-9);
        }
    }
    catch (Exception ex)
    {
        row.Ok = false;
        row.Note = ex.GetType().Name + ": " + Trunc(ex.Message, 80);
    }
    return row;
}

static ResultRow BenchBackupRestore(
    string payloadPath, long payloadBytes, string strategy, string compression,
    string workRoot, Process proc, bool keep)
{
    var row = new ResultRow
    {
        Category = "backup_restore",
        Strategy = strategy,
        Compression = compression,
        PayloadBytes = payloadBytes,
    };

    string safe = $"{strategy}_{compression}".Replace('+', 'p').Replace('.', '_');
    string store = Path.Combine(workRoot, "store_" + safe);
    string restored = Path.Combine(workRoot, "restored_" + safe + ".bin");
    try
    {
        if (Directory.Exists(store)) Directory.Delete(store, true);
        Directory.CreateDirectory(store);

        GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
        long ws0 = proc.WorkingSet64;
        byte[] pw = EncryptionLayer.GenerateRcCode(32);

        var sw = Stopwatch.StartNew();
        string fp;
        using (var engine = new RDRFEngine(pw, new LocalDSAAAdapter(store)))
        {
            fp = engine.BackupFile(payloadPath, strategy, compressionMethod: compression);
            sw.Stop();
            row.BackupMs = sw.Elapsed.TotalMilliseconds;

            sw.Restart();
            bool ok = engine.RestoreFile(fp, restored);
            sw.Stop();
            row.RestoreMs = sw.Elapsed.TotalMilliseconds;
            row.Ok = ok;
        }

        proc.Refresh();
        row.PeakDeltaMb = Math.Max(0, (proc.WorkingSet64 - ws0) / (1024.0 * 1024.0));
        row.StoreBytes = DirSize(store);

        if (row.Ok)
        {
            row.Ok = FilesEqualSha256(payloadPath, restored);
            if (!row.Ok) row.Note = "sha256_mismatch";
        }
        else row.Note = "restore_false";

        if (payloadBytes > 0)
        {
            row.BackupMBps = (payloadBytes / (1024.0 * 1024.0)) / Math.Max(row.BackupMs / 1000.0, 1e-9);
            row.RestoreMBps = (payloadBytes / (1024.0 * 1024.0)) / Math.Max(row.RestoreMs / 1000.0, 1e-9);
            if (row.StoreBytes > 0)
                row.Ratio = row.StoreBytes / (double)payloadBytes;
        }
    }
    catch (Exception ex)
    {
        row.Ok = false;
        row.Note = ex.GetType().Name + ": " + Trunc(ex.Message, 100);
    }
    finally
    {
        if (!keep)
        {
            try { if (Directory.Exists(store)) Directory.Delete(store, true); } catch { /* ignore */ }
            try { if (File.Exists(restored)) File.Delete(restored); } catch { /* ignore */ }
        }
    }
    return row;
}

static long DirSize(string dir)
{
    if (!Directory.Exists(dir)) return 0;
    long n = 0;
    foreach (var f in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
        n += new FileInfo(f).Length;
    return n;
}

static bool FilesEqualSha256(string a, string b)
{
    if (!File.Exists(a) || !File.Exists(b)) return false;
    using var fa = File.OpenRead(a);
    using var fb = File.OpenRead(b);
    return CryptographicOperations.FixedTimeEquals(SHA256.HashData(fa), SHA256.HashData(fb));
}

static void PrintRow(ResultRow r)
{
    ConsoleColor prev = Console.ForegroundColor;
    Console.ForegroundColor = r.Ok ? ConsoleColor.Green : ConsoleColor.Red;
    if (r.Category == "compress_api")
    {
        Console.WriteLine(
            $"  [API] {r.Compression,-10} comp={r.CompressMs,8:F1}ms ({r.CompressMBps,6:F1} MB/s)  " +
            $"decomp={r.DecompressMs,8:F1}ms ({r.DecompressMBps,6:F1} MB/s)  " +
            $"ratio={r.Ratio:F3}  peakΔ={r.PeakDeltaMb:F1}MB  {(r.Ok ? "OK" : "FAIL")} {r.Note}");
    }
    else
    {
        Console.WriteLine(
            $"  [BKP] {r.Strategy,-7} {r.Compression,-8} " +
            $"backup={r.BackupMs,8:F0}ms ({r.BackupMBps,6:F1} MB/s)  " +
            $"restore={r.RestoreMs,8:F0}ms ({r.RestoreMBps,6:F1} MB/s)  " +
            $"store={r.StoreBytes / 1024.0 / 1024.0,6:F2}MB  peakΔ={r.PeakDeltaMb:F1}MB  " +
            $"{(r.Ok ? "OK" : "FAIL")} {r.Note}");
    }
    Console.ForegroundColor = prev;
}

static void WriteCsv(string path, List<ResultRow> rows)
{
    var sb = new StringBuilder();
    sb.AppendLine("category,strategy,compression,payload_bytes,compress_ms,decompress_ms,backup_ms,restore_ms,compressed_bytes,store_bytes,ratio,compress_MBps,decompress_MBps,backup_MBps,restore_MBps,peak_delta_mb,ok,note");
    foreach (var r in rows)
    {
        sb.Append(CultureInfo.InvariantCulture,
            $"{r.Category},{r.Strategy},{r.Compression},{r.PayloadBytes}," +
            $"{r.CompressMs:F3},{r.DecompressMs:F3},{r.BackupMs:F3},{r.RestoreMs:F3}," +
            $"{r.CompressedBytes},{r.StoreBytes},{r.Ratio:F6}," +
            $"{r.CompressMBps:F3},{r.DecompressMBps:F3},{r.BackupMBps:F3},{r.RestoreMBps:F3}," +
            $"{r.PeakDeltaMb:F3},{(r.Ok ? 1 : 0)},\"{Escape(r.Note)}\"");
        sb.AppendLine();
    }
    File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
}

static void WriteMarkdown(string path, List<ResultRow> rows, string payloadPath, long payloadBytes, bool quick)
{
    var sb = new StringBuilder();
    sb.AppendLine("# RDRF.PerfBench results");
    sb.AppendLine();
    sb.AppendLine($"- Payload: `{payloadPath}` ({payloadBytes:N0} bytes)");
    sb.AppendLine($"- Quick: {quick}");
    sb.AppendLine($"- Generated: {DateTime.Now:O}");
    sb.AppendLine();
    sb.AppendLine("## Compress API");
    sb.AppendLine();
    sb.AppendLine("| Method | Compress ms | MB/s | Decompress ms | MB/s | Ratio | OK |");
    sb.AppendLine("|--------|-------------|------|---------------|------|-------|----|");
    foreach (var r in rows.Where(x => x.Category == "compress_api"))
    {
        sb.AppendLine(CultureInfo.InvariantCulture,
            $"| {r.Compression} | {r.CompressMs:F1} | {r.CompressMBps:F1} | {r.DecompressMs:F1} | {r.DecompressMBps:F1} | {r.Ratio:F3} | {(r.Ok ? "Y" : "N")} |");
    }
    sb.AppendLine();
    sb.AppendLine("## Backup / Restore");
    sb.AppendLine();
    sb.AppendLine("| Strategy | Compression | Backup ms | MB/s | Restore ms | MB/s | Store MB | PeakΔ MB | OK | Note |");
    sb.AppendLine("|----------|-------------|-----------|------|------------|------|----------|----------|----|------|");
    foreach (var r in rows.Where(x => x.Category == "backup_restore"))
    {
        sb.AppendLine(CultureInfo.InvariantCulture,
            $"| {r.Strategy} | {r.Compression} | {r.BackupMs:F0} | {r.BackupMBps:F1} | {r.RestoreMs:F0} | {r.RestoreMBps:F1} | {r.StoreBytes / 1024.0 / 1024.0:F2} | {r.PeakDeltaMb:F1} | {(r.Ok ? "Y" : "N")} | {r.Note} |");
    }
    File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
}

static string Escape(string s) => s.Replace("\"", "''");
static string Trunc(string s, int n) => s.Length <= n ? s : s[..n] + "…";

sealed class ResultRow
{
    public string Category { get; set; } = "";
    public string Strategy { get; set; } = "";
    public string Compression { get; set; } = "";
    public long PayloadBytes { get; set; }
    public double CompressMs { get; set; }
    public double DecompressMs { get; set; }
    public double BackupMs { get; set; }
    public double RestoreMs { get; set; }
    public long CompressedBytes { get; set; }
    public long StoreBytes { get; set; }
    public double Ratio { get; set; }
    public double CompressMBps { get; set; }
    public double DecompressMBps { get; set; }
    public double BackupMBps { get; set; }
    public double RestoreMBps { get; set; }
    public double PeakDeltaMb { get; set; }
    public bool Ok { get; set; }
    public string Note { get; set; } = "";
}
