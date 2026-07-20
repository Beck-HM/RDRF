using System.Diagnostics;
using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.DSAA;
using RDRF.Core.Encryption;

// Throughput baseline (item 23): write sizes and strategies to stdout; no git, local only.
// Usage: RDRF.BenchBaseline [sizeMb=32]

int sizeMb = args.Length > 0 && int.TryParse(args[0], out int m) ? Math.Clamp(m, 1, 512) : 32;
string root = Path.Combine(Path.GetTempPath(), "rdrf_bench_" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
string src = Path.Combine(root, "payload.bin");
byte[] buf = new byte[1024 * 1024];
new Random(1).NextBytes(buf);
using (var fs = File.Create(src))
{
    for (int i = 0; i < sizeMb; i++)
        fs.Write(buf);
}

string[] strategies = { "FSS1", "FSS3", "FSS6.1" };
Console.WriteLine($"payload_mb={sizeMb} path={src}");
Console.WriteLine("strategy,wall_ms,peak_working_set_mb,store_bytes,ok");

foreach (var strat in strategies)
{
    string store = Path.Combine(root, strat.Replace('.', '_'));
    Directory.CreateDirectory(store);
    byte[] pw = EncryptionLayer.GenerateRcCode(32);
    var proc = Process.GetCurrentProcess();
    long peakBefore = proc.PeakWorkingSet64;
    var sw = Stopwatch.StartNew();
    bool ok = false;
    long storeBytes = 0;
    try
    {
        using var engine = new RDRFEngine(pw, new LocalDSAAAdapter(store));
        string fp = engine.BackupFile(src, strat, compressionMethod: "lz4");
        string outPath = Path.Combine(store, "restored.bin");
        ok = engine.RestoreFile(fp, outPath);
        storeBytes = Directory.GetFiles(store).Sum(f => new FileInfo(f).Length);
        if (ok)
        {
            ok = CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(File.ReadAllBytes(src)),
                SHA256.HashData(File.ReadAllBytes(outPath)));
        }
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"{strat} error: {ex.Message}");
        ok = false;
    }
    sw.Stop();
    proc.Refresh();
    long peakMb = Math.Max(0, (proc.PeakWorkingSet64 - peakBefore) / (1024 * 1024));
    Console.WriteLine($"{strat},{sw.ElapsedMilliseconds},{peakMb},{storeBytes},{ok}");
}

try { Directory.Delete(root, true); } catch { /* best-effort */ }
