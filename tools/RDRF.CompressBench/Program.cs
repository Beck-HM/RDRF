using System.Diagnostics;
using System.Security.Cryptography;

string repoRoot = Path.GetFullPath(Path.Combine(
    AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", ".."));
string cli = Path.Combine(repoRoot, "src", "RDRF.Cli", "bin", "Release", "net8.0", "rdrf.exe");
string testInput = Path.Combine(repoRoot, "tests", "RDRF_TestInput");
string baselineDir = Path.Combine(repoRoot, "tests", "RDRF_TestOutput", "Bench");
string outputRoot = Path.Combine(repoRoot, "tests", "RDRF_TestOutput",
    $"CompressBench_{DateTime.Now:yyyyMMdd_HHmmss}");

const string password = "bench";
const string strategy = "fss1";
string testFile = Path.Combine(testInput, "bench_doc.bin");

var algos = new (string label, string[] cliArgs)[]
{
    ("baseline (v1.4.5)", Array.Empty<string>()),
    ("lz4",      new[]{"-c", "lz4"}),
    ("lz4hc",    new[]{"-c", "lz4hc"}),
    ("zstd def", new[]{"-c", "zstd"}),
    ("zstd 10",  new[]{"-c", "zstd", "10"}),
    ("gzip",     new[]{"-c", "gzip"}),
    ("brotli",   new[]{"-c", "brotli"}),
    ("lzma2",    new[]{"-c", "lzma2"}),
    ("lzo",      new[]{"-c", "lzo"}),
    ("xpress_huff", new[]{"-c", "xpress_huff"}),
    ("lzms",     new[]{"-c", "lzms"}),
    ("ckc",      new[]{"-c", "ckc"}),
    ("xz",       new[]{"-c", "xz"}),
};

long DirSize(string dir) =>
    Directory.Exists(dir)
        ? Directory.GetFiles(dir, "*", SearchOption.AllDirectories).Sum(f => new FileInfo(f).Length)
        : 0;

bool Sha256Match(string a, string b)
{
    if (!File.Exists(a) || !File.Exists(b)) return false;
    return CryptographicOperations.FixedTimeEquals(
        SHA256.HashData(File.ReadAllBytes(a)),
        SHA256.HashData(File.ReadAllBytes(b)));
}

string RunCmd(string exe, string args, out int exitCode)
{
    var psi = new ProcessStartInfo(exe, args)
    {
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
        CreateNoWindow = true,
    };
    using var proc = Process.Start(psi)!;
    proc.WaitForExit(120_000);
    exitCode = proc.ExitCode;
    return proc.StandardOutput.ReadToEnd() + proc.StandardError.ReadToEnd();
}

if (!File.Exists(cli)) { Console.Error.WriteLine($"CLI not found: {cli}"); return 1; }
if (!File.Exists(testFile)) { Console.Error.WriteLine($"Test file not found: {testFile}"); return 1; }

long srcSize = new FileInfo(testFile).Length;
bool hasBaseline = Directory.Exists(baselineDir);
long baselineBytes = hasBaseline ? DirSize(baselineDir) : 0;

var results = new List<(string label, long diskBytes, long backupMs, long restoreMs, bool shaOk, string note)>();
if (hasBaseline) results.Add(("baseline (v1.4.5)", baselineBytes, 0, 0, true, $"{(double)baselineBytes/srcSize:F2}x overhead"));
else results.Add(("baseline (v1.4.5)", 0, 0, 0, false, "N/A (dir not found)"));

Directory.CreateDirectory(outputRoot);
foreach (var algo in algos)
{
    if (algo.cliArgs.Length == 0) continue;

    string outDir = Path.Combine(outputRoot, algo.label.Replace(" ", "_").Replace(".", "_"));
    Directory.CreateDirectory(outDir);

    var swB = Stopwatch.StartNew();
    string backupArgs = $"\"{testFile}\" -password {password} -o \"{outDir}\" --{strategy} {string.Join(" ", algo.cliArgs)}";
    RunCmd(cli, $"backup {backupArgs}", out int bc);
    swB.Stop();

    var idx = Directory.GetFiles(outDir, "*.indrdrf").FirstOrDefault();
    if (idx == null || bc != 0)
    {
        results.Add((algo.label, 0, swB.ElapsedMilliseconds, 0, false, "BACKUP FAILED"));
        continue;
    }

    long diskBytes = DirSize(outDir);

    string restored = Path.Combine(outDir, "restored.bin");
    var swR = Stopwatch.StartNew();
    RunCmd(cli, $"res \"{idx}\" -password {password} -o \"{restored}\"", out int rc);
    swR.Stop();

    bool shaOk = Sha256Match(testFile, restored);
    results.Add((algo.label, diskBytes, swB.ElapsedMilliseconds, swR.ElapsedMilliseconds, shaOk, shaOk ? "" : "SHA256 MISMATCH"));
    Console.Error.Write(".");
}
Console.Error.WriteLine();

Console.WriteLine();
Console.ForegroundColor = ConsoleColor.White;
Console.WriteLine($"  Benchmark: {Path.GetFileName(testFile)} ({srcSize / 1024 / 1024} MB) / FSS1");
Console.WriteLine($"  vs baseline: v1.4.5 ({baselineBytes / 1024 / 1024} MB on disk)");
Console.ResetColor();
Console.WriteLine();
Console.WriteLine($"  {"Algorithm",-16} {"Disk",10} {"Ratio",8} {"vsBase",8} {"Bkp(ms)",8} {"Res(ms)",8}  SHA256");
Console.WriteLine($"  {"─",-16} {"──────",10} {"───",8} {"───",8} {"───",8} {"───",8}  ─────");

foreach (var r in results)
{
    double ratio = r.diskBytes > 0 ? (double)r.diskBytes / srcSize : 0;
    double vsBase = r.diskBytes > 0 ? (double)r.diskBytes / baselineBytes : 0;
    string diskStr = r.diskBytes > 0
        ? $"{(double)r.diskBytes / 1024 / 1024,5:F1} MB"
        : "    FAIL";
    ConsoleColor col = r.shaOk ? ConsoleColor.Green : ConsoleColor.Red;
    string flag = r.note.Length > 0 ? $"  [{r.note}]" : "";
    Console.ForegroundColor = col;
    Console.WriteLine($"  {r.label,-16} {diskStr,10} {ratio,7:F2}x {vsBase,7:F2}x {r.backupMs,8} {r.restoreMs,8}  {(r.shaOk ? "PASS" : "FAIL")}{flag}");
}
Console.ResetColor();

long bestDisk = results.Where(r => r.diskBytes > 0).MinBy(r => r.diskBytes).diskBytes;
string best = results.First(r => r.diskBytes == bestDisk).label;
Console.ForegroundColor = ConsoleColor.Yellow;
Console.WriteLine($"\n  Best compression: {best} ({bestDisk / 1024d / 1024:F1} MB)");
Console.WriteLine($"  Best vs baseline: {(double)baselineBytes / bestDisk:F1}x smaller");
Console.ResetColor();
Console.WriteLine($"\n  Output: {outputRoot}");

string csv = Path.Combine(outputRoot, "compress_bench.csv");
using var cw = new StreamWriter(csv);
cw.WriteLine("algorithm,label,disk_bytes,disk_mb,ratio_vs_raw,ratio_vs_baseline,backup_ms,restore_ms,sha256_pass,note");
foreach (var r in results)
{
    double ratio = r.diskBytes > 0 ? (double)r.diskBytes / srcSize : 0;
    double vsBase = r.diskBytes > 0 ? (double)r.diskBytes / baselineBytes : 0;
    cw.WriteLine($"{r.label},{r.label},{r.diskBytes},{r.diskBytes / 1024d / 1024:F2},{ratio:F4},{vsBase:F4},{r.backupMs},{r.restoreMs},{r.shaOk},{r.note}");
}
Console.WriteLine($"  CSV:      {csv}");

return 0;
