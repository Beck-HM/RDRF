using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using ZstdSharp;
using K4os.Compression.LZ4;

var dataDir = Path.Combine(AppContext.BaseDirectory, "zstd_data");

// Parse args
var levelSet = new[] { 1, 3, 5, 10, 19 };
bool fastMode = false;
bool aesBench = false;
bool lz4Bench = false;
for (int i = 0; i < args.Length; i++)
{
    if ((args[i] is "-l" or "--level") && i + 1 < args.Length)
        levelSet = args[++i].Split(',').Select(int.Parse).Distinct().Order().ToArray();
    if (args[i] is "--fast") fastMode = true;
    if (args[i] is "--aes") aesBench = true;
    if (args[i] is "--lz4") lz4Bench = true;
}

if (aesBench)
{
    try { RunAesBenchmark(); }
    finally { CleanupDataDir(dataDir); }
    return 0;
}

if (lz4Bench)
{
    try { RunLz4Benchmark(args); }
    finally { CleanupDataDir(Path.Combine(AppContext.BaseDirectory, "lz4_data")); }
    return 0;
}

// Generate test data
var files = new List<(string name, long size, byte[] data)>();
try
{
files.AddRange(GenerateTextData(dataDir, fastMode ? 3 : 3));
files.AddRange(GenerateBinaryData(dataDir, fastMode ? 3 : 10));
files.AddRange(GeneratePrecompData(dataDir, fastMode ? 3 : 10));
if (!fastMode)
    files.Add(GenerateLargeMix(dataDir));

Console.WriteLine($"Generated {files.Count} test file(s) in {dataDir}");
Console.WriteLine();

// Run tests
var results = new List<TestResult>();

foreach (var (name, size, original) in files)
{
    var shaOriginal = SHA256.HashData(original);
    Console.Write($"  {name,-30} {size,8:N0} bytes");

    foreach (int level in levelSet)
    {
        var (ratio, compMbps, decompGbps, compBytes, shaOk) = RunSingleTest(original, shaOriginal, level);
        results.Add(new TestResult(name, size, level, ratio, compMbps, decompGbps, compBytes, shaOk));
    }

    Console.WriteLine();
}

PrintTable(results, levelSet);
PrintCsv(results);
PrintSummary(results);
}
finally
{
    CleanupDataDir(dataDir);
}
return 0;

// -- Generate --

static List<(string, long, byte[])> GenerateTextData(string dir, int sizeMb)
{
    var results = new List<(string, long, byte[])>();
    foreach (int mb in new[] { 3, 10, 100 }.Where(s => s <= sizeMb || s <= 3))
    {
        if (mb > sizeMb && mb > 3) continue;
        var path = Path.Combine(dir, $"text_{mb}mb.bin");
        var data = Encoding.UTF8.GetBytes(GenerateLoremIpsum(mb * 1024 * 1024));
        Directory.CreateDirectory(dir);
        File.WriteAllBytes(path, data);
        results.Add(($"text_{mb}mb", data.Length, data));
    }
    return results;
}

static string GenerateLoremIpsum(int minBytes)
{
    var words = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua ut enim ad minim veniam quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur excepteur sint occaecat cupidatat non proident sunt in culpa qui officia deserunt mollit anim id est laborum".Split(' ');
    var sb = new StringBuilder(minBytes + 1024);
    var rng = new Random(42);
    while (sb.Length < minBytes)
    {
        int count = rng.Next(5, 20);
        for (int i = 0; i < count; i++)
        {
            sb.Append(words[rng.Next(words.Length)]);
            sb.Append(' ');
        }
        sb.AppendLine();
        // Occasionally inject non-repeating tokens
        if (rng.Next(10) == 0)
            sb.AppendLine($"<!-- uuid-{Guid.NewGuid():N} -->");
    }
    return sb.ToString();
}

static List<(string, long, byte[])> GenerateBinaryData(string dir, int sizeMb)
{
    var results = new List<(string, long, byte[])>();
    foreach (int mb in new[] { 3, 10 }.Where(s => s <= sizeMb))
    {
        var path = Path.Combine(dir, $"binary_{mb}mb.bin");
        var data = GenerateBinaryBlob(mb * 1024 * 1024);
        Directory.CreateDirectory(dir);
        File.WriteAllBytes(path, data);
        results.Add(($"binary_{mb}mb", data.Length, data));
    }
    return results;
}

static byte[] GenerateBinaryBlob(int size)
{
    var rng = new Random(42);
    var buf = new byte[size];
    int off = 0;
    while (off < size)
    {
        // Repeating 256-byte pattern (moderately compressible)
        int chunkLen = Math.Min(256, size - off);
        var pattern = new byte[chunkLen];
        rng.NextBytes(pattern);
        // Repeat same pattern a few times
        int repeat = Math.Min(rng.Next(1, 8), (size - off) / chunkLen);
        for (int r = 0; r < repeat && off < size; r++)
        {
            Buffer.BlockCopy(pattern, 0, buf, off, Math.Min(chunkLen, size - off));
            off += chunkLen;
        }
    }
    return buf;
}

static List<(string, long, byte[])> GeneratePrecompData(string dir, int sizeMb)
{
    var results = new List<(string, long, byte[])>();
    foreach (int mb in new[] { 3, 10 }.Where(s => s <= sizeMb))
    {
        var path = Path.Combine(dir, $"precomp_{mb}mb.bin");
        var data = new byte[mb * 1024 * 1024];
        Random.Shared.NextBytes(data);
        Directory.CreateDirectory(dir);
        File.WriteAllBytes(path, data);
        results.Add(($"precomp_{mb}mb", data.Length, data));
    }
    return results;
}

static (string, long, byte[]) GenerateLargeMix(string dir)
{
    var path = Path.Combine(dir, "large_300mb.bin");
    using var ms = new MemoryStream();
    var rng = new Random(42);
    for (int i = 0; i < 30; i++) // 10 MB each
    {
        var chunk = i switch
        {
            < 10 => Encoding.UTF8.GetBytes(GenerateLoremIpsum(10 * 1024 * 1024)),
            < 20 => GenerateBinaryBlob(10 * 1024 * 1024),
            _ => GenerateRandomChunk(rng, 10 * 1024 * 1024)
        };
        ms.Write(chunk, 0, chunk.Length);
    }
    var data = ms.ToArray();
    Directory.CreateDirectory(dir);
    File.WriteAllBytes(path, data);
    return ("large_300mb", data.Length, data);
}

static byte[] GenerateRandomChunk(Random rng, int size)
{
    var buf = new byte[size];
    rng.NextBytes(buf);
    return buf;
}

// -- Run single test --

static (double ratio, double compMbps, double decompGbps, long compBytes, bool shaOk) RunSingleTest(
    byte[] original, byte[] shaOriginal, int level)
{
    var times = new List<(long compTicks, long decompTicks, byte[] compressed)>();
    for (int trial = 0; trial < 3; trial++)
    {
        var sw = Stopwatch.StartNew();
        var compressed = Compress(original, level);
        sw.Stop();
        long compTicks = sw.ElapsedTicks;

        sw.Restart();
        var decompressed = Decompress(compressed, original.Length);
        sw.Stop();
        long decompTicks = sw.ElapsedTicks;

        times.Add((compTicks, decompTicks, compressed));
    }

    var sorted = times.OrderBy(t => t.compTicks + t.decompTicks).ToList();
    var best = sorted[1];

    double ratio = (double)original.Length / best.compressed.Length;
    double compMs = best.compTicks * 1000.0 / Stopwatch.Frequency;
    double decompMs = best.decompTicks * 1000.0 / Stopwatch.Frequency;
    double compMbps = original.Length / 1024.0 / 1024.0 / (compMs / 1000.0);
    double decompGbps = original.Length / 1024.0 / 1024.0 / 1024.0 / (decompMs / 1000.0);

    var check = Decompress(best.compressed, original.Length);
    bool shaOk = CryptographicOperations.FixedTimeEquals(shaOriginal, SHA256.HashData(check));

    double pct = (double)best.compressed.Length / original.Length * 100;
    Console.Write($" | L{level} {ratio,5:F2}x {compMbps,6:F0}MB/s {decompGbps,4:F2}GB/s {best.compressed.Length,8:N0}B({pct,4:F1}%) {(shaOk ? "[OK]" : "[FAIL]")}");
    return (ratio, compMbps, decompGbps, best.compressed.Length, shaOk);
}

static byte[] Compress(byte[] data, int level)
{
    return Zstd.Compress(data, level);
}

static byte[] Decompress(byte[] compressed, int originalSize)
{
    return Zstd.Decompress(compressed, originalSize);
}

// -- Output --

static void PrintTable(List<TestResult> results, int[] levels)
{
    Console.WriteLine();
    Console.WriteLine("=== Compression Test Report ===");
    Console.WriteLine();

    foreach (var grp in results.GroupBy(r => r.Name))
    {
        Console.WriteLine($"  {grp.Key,-30} {grp.First().Size,10:N0} bytes");
        Console.WriteLine($"  {'-',30} {'-',10} {'-',8} {'-',12} {'-',8} {'-',8} {'-',8}");
        Console.WriteLine($"  {"Level",30} {"Ratio",10} {"Stored",8} {"Overhead",12} {"Comp",8} {"Decomp",8} {"SHA",8}");
        Console.WriteLine($"  {"",30} {"",10} {"Bytes",8} {"%",12} {"MB/s",8} {"GB/s",8} {"",8}");
        Console.WriteLine($"  {'-',30} {'-',10} {'-',8} {'-',12} {'-',8} {'-',8} {'-',8}");
        foreach (var r in grp.OrderBy(r => r.Level))
        {
            double pct = (double)r.CompressedBytes / r.Size * 100;
            string overhead = r.CompressedBytes < r.Size
                ? $"-{(1 - (double)r.CompressedBytes / r.Size) * 100,5:F1}%"
                : $"+{pct - 100,5:F1}%";
            Console.WriteLine($"  {r.Level,30} {r.Ratio,10:F2}x {r.CompressedBytes,8:N0} {overhead,12} {r.CompMbps,8:F0} {r.DecompGbps,8:F2} {(r.ShaOk ? "[OK]" : "[FAIL]"),8}");
        }
        Console.WriteLine();
    }
}

static void PrintCsv(List<TestResult> results)
{
    Console.WriteLine("=== CSV ===");
    Console.WriteLine("name,size_bytes,level,ratio,compressed_bytes,overhead_pct,compress_mbps,decompress_gbps,sha256_ok");
    foreach (var r in results.OrderBy(r => r.Name).ThenBy(r => r.Level))
    {
        double pct = (double)r.CompressedBytes / r.Size * 100;
        Console.WriteLine($"{r.Name},{r.Size},{r.Level},{r.Ratio:F4},{r.CompressedBytes},{pct:F2},{r.CompMbps:F2},{r.DecompGbps:F4},{r.ShaOk}");
    }
    Console.WriteLine();
}

static void PrintSummary(List<TestResult> results)
{
    var bestRatio = results.MaxBy(r => r.Ratio)!;
    var bestComp = results.MaxBy(r => r.CompMbps)!;
    var bestDecomp = results.MaxBy(r => r.DecompGbps)!;
    var bestOverhead = results.Where(r => r.CompressedBytes < r.Size)
        .MaxBy(r => (double)r.Size / r.CompressedBytes)!;

    Console.WriteLine("================================================================");
    Console.WriteLine("Summary:");
    Console.WriteLine($"  Best ratio:           {bestRatio.Name} @ L{bestRatio.Level} = {bestRatio.Ratio:F2}x  ({bestRatio.CompressedBytes:N0} -> {bestRatio.Size:N0} bytes)");
    Console.WriteLine($"  Best compress speed:   {bestComp.Name} @ L{bestComp.Level} = {bestComp.CompMbps:F0} MB/s");
    Console.WriteLine($"  Best decompress speed:  {bestDecomp.Name} @ L{bestDecomp.Level} = {bestDecomp.DecompGbps:F2} GB/s");
    if (bestOverhead != null)
        Console.WriteLine($"  Best space saving:     {bestOverhead.Name} @ L{bestOverhead.Level} = {(1 - (double)bestOverhead.CompressedBytes / bestOverhead.Size) * 100:F1}%");
    Console.WriteLine("================================================================");
}

static void CleanupDataDir(string dir)
{
    try { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
    catch { }
}

// -- AES Benchmark --

static void RunAesBenchmark()
{
    Console.WriteLine("=== AES-CTR Benchmark ===");
    Console.WriteLine($"  Hardware AES-NI: {RDRF.Core.Encryption.AesNiCtr.IsSupported}");
    Console.WriteLine();

    // Test sizes: 1 MB, 10 MB, 100 MB
    int[] sizes = [1 * 1024 * 1024, 10 * 1024 * 1024, 100 * 1024 * 1024];
    byte[] key = RandomNumberGenerator.GetBytes(32);
    byte[] nonce = RandomNumberGenerator.GetBytes(12);

    foreach (int size in sizes)
    {
        byte[] data = RandomNumberGenerator.GetBytes(size);
        var shaBefore = SHA256.HashData(data);

        // Warmup
        RDRF.Core.Encryption.AesNiCtr.CtrCrypt(data, key, nonce);

        // Benchmark: 5 trials
        var times = new List<long>();
        for (int t = 0; t < 5; t++)
        {
            var sw = Stopwatch.StartNew();
            byte[] encrypted = RDRF.Core.Encryption.AesNiCtr.CtrCrypt(data, key, nonce);
            sw.Stop();
            times.Add(sw.ElapsedTicks);

            // Decrypt and verify
            byte[] decrypted = RDRF.Core.Encryption.AesNiCtr.CtrCrypt(encrypted, key, nonce);
            bool ok = CryptographicOperations.FixedTimeEquals(shaBefore, SHA256.HashData(decrypted));
            if (!ok) Console.WriteLine("  SHA256 MISMATCH!");
        }

        double medianMs = times.OrderBy(t => t).Skip(1).First() * 1000.0 / Stopwatch.Frequency;
        double throughput = size / 1024.0 / 1024.0 / (medianMs / 1000.0);

        Console.WriteLine($"  {size / 1024 / 1024,4} MB  encrypt: {throughput,7:F0} MB/s  ({medianMs,6:F1} ms)");
    }

    Console.WriteLine();
    Console.WriteLine($"  AES-NI path: {(RDRF.Core.Encryption.AesNiCtr.IsSupported ? "AES-NI intrinsics (~5 GB/s)" : "Batch TransformBlock (~2 GB/s)")}");
}

// -- LZ4 Benchmark --

static void RunLz4Benchmark(string[] args)
{
    var lz4Levels = new[] { 0, 1, 3, 5, 7, 9 };
    var dataDir = Path.Combine(AppContext.BaseDirectory, "lz4_data");
    bool fastMode = false;

    for (int i = 0; i < args.Length; i++)
    {
        if (args[i] is "--fast") fastMode = true;
        if ((args[i] is "-l" or "--level") && i + 1 < args.Length)
            lz4Levels = args[++i].Split(',').Select(int.Parse).Distinct().Order().ToArray();
    }

    var files = new List<(string name, long size, byte[] data)>();
    files.AddRange(GenerateTextData(dataDir, fastMode ? 3 : 3));
    files.AddRange(GenerateBinaryData(dataDir, fastMode ? 3 : 10));
    files.AddRange(GeneratePrecompData(dataDir, fastMode ? 3 : 10));
    if (!fastMode)
        files.Add(GenerateLargeMix(dataDir));

    Console.WriteLine($"Generated {files.Count} test file(s) in {dataDir}");
    Console.WriteLine();

    var results = new List<TestResult>();

    foreach (var (name, size, original) in files)
    {
        var shaOriginal = SHA256.HashData(original);
        Console.Write($"  {name,-30} {size,8:N0} bytes");

        foreach (int level in lz4Levels)
        {
            var times = new List<(long compTicks, long decompTicks, byte[] compressed)>();
            for (int trial = 0; trial < 3; trial++)
            {
                var sw = Stopwatch.StartNew();
                byte[] compressed = LZ4Pickler.Pickle(original, (LZ4Level)level);
                sw.Stop();
                long compTicks = sw.ElapsedTicks;

                sw.Restart();
                byte[] decompressed = LZ4Pickler.Unpickle(compressed);
                sw.Stop();
                long decompTicks = sw.ElapsedTicks;

                times.Add((compTicks, decompTicks, compressed));
            }

            var sorted = times.OrderBy(t => t.compTicks + t.decompTicks).ToList();
            var best = sorted[1];

            double ratio = (double)original.Length / best.compressed.Length;
            double compMs = best.compTicks * 1000.0 / Stopwatch.Frequency;
            double decompMs = best.decompTicks * 1000.0 / Stopwatch.Frequency;
            double compMbps = original.Length / 1024.0 / 1024.0 / (compMs / 1000.0);
            double decompGbps = original.Length / 1024.0 / 1024.0 / 1024.0 / (decompMs / 1000.0);

            var check = LZ4Pickler.Unpickle(best.compressed);
            bool shaOk = CryptographicOperations.FixedTimeEquals(shaOriginal, SHA256.HashData(check));

            double pct = (double)best.compressed.Length / original.Length * 100;
            Console.Write($" | L{level} {ratio,5:F2}x {compMbps,6:F0}MB/s {decompGbps,4:F2}GB/s {best.compressed.Length,8:N0}B({pct,4:F1}%) {(shaOk ? "[OK]" : "[FAIL]")}");
            results.Add(new TestResult(name, size, level, ratio, compMbps, decompGbps, best.compressed.Length, shaOk));
        }
        Console.WriteLine();
    }

    PrintTable(results, lz4Levels);
    PrintCsv(results);
    PrintSummary(results);

    CleanupDataDir(dataDir);
}

// -- Models --

record TestResult(string Name, long Size, int Level, double Ratio, double CompMbps, double DecompGbps, long CompressedBytes, bool ShaOk);
