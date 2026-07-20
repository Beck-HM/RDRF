using System.Globalization;

// FragSizeSim - Adaptive fragment size simulation
// Estimated overhead model based on RDRF embedded-index + fragment-header cost.
// Outputs CSV + formatted tables to stdout.

var fileSizes = new[] { 1_024L, 10_240L, 102_400L, 1_048_576L, 5_242_880L, 10_485_760L,
    26_214_400L, 52_428_800L, 104_857_600L, 262_144_000L, 524_288_000L,
    1_073_741_824L, 2_684_354_560L, 5_368_709_120L, 10_737_418_240L,
    26_843_545_600L, 53_687_091_200L, 107_374_182_400L };

var targetCounts = new[] { 25, 50, 75, 100, 150, 200, 500 };

const long minFrag = 256 * 1024;
const long maxFrag = 64 * 1024 * 1024;

string testsDir = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,
    "..", "..", "..", "..", "..", "tests", "RDRF_TestOutput"));
string outDir = Path.Combine(testsDir, $"frag_sim_{Guid.NewGuid():N}");
Directory.CreateDirectory(outDir);

try
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("+---------------------------------------------------------------------------+");
    Console.WriteLine("|      Fragment Size Adaptive Simulation - Overhead Model                   |");
    Console.WriteLine("+---------------------------------------------------------------------------+");
    Console.ResetColor();
    Console.WriteLine($"  minFrag = {Fmt(minFrag)},  maxFrag = {Fmt(maxFrag)}");
    Console.WriteLine($"  Files: {fileSizes.Length} sizes ({Fmt(fileSizes[0])} .. {Fmt(fileSizes[^1])})");
    Console.WriteLine($"  Target counts: {string.Join(", ", targetCounts)}");
    Console.WriteLine();

    var csv = new List<string>
    {
        "FileSize,FileSizeStr,TargetCount,FragSize,FragCount,EmbedIdxEach,TotalEmbedOH,HeaderOH,StandaloneIdx,TotalStorage,OHPct"
    };

    Console.WriteLine("  TABLE 1 - Storage overhead per file-size x target-count");
    Console.WriteLine("  " + new string('-', 78));

    foreach (var fs in fileSizes)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("  {0,8} file:", Fmt(fs));
        Console.ResetColor();

        foreach (var tc in targetCounts)
        {
            long fragSize = Math.Max(minFrag, Math.Min(maxFrag, fs / tc));
            int fragCount = (int)((fs + fragSize - 1) / fragSize);

            int each = 200 + 40 * fragCount;
            long embed = (long)fragCount * each;
            long header = fragCount * 6L;
            int stand = 500 + 80 * fragCount;
            long total = fs + embed + header + stand;
            double pct = (double)(total - fs) / fs * 100;

            csv.Add(string.Format(CultureInfo.InvariantCulture,
                "{0},\"{1}\",{2},{3},{4},{5},{6},{7},{8},{9},{10:F3}",
                fs, Fmt(fs), tc, fragSize, fragCount, each, embed, header, stand, total, pct));

            string sc = Fmt(fragSize) + " x" + fragCount.ToString().PadLeft(4);
            string oc = pct < 0.5 ? string.Format("{0:F2}%", pct) : string.Format("{0:F1}%", pct);
            Console.WriteLine("    target={0,3}  |  {1,-16} |  embedIdx={2}B x{3}  |  OH={4}",
                tc, sc, each, fragCount, oc);
        }
        Console.WriteLine();
    }

    Console.WriteLine("  TABLE 2 - Recommended targetCount per file-size range");
    Console.WriteLine("  " + new string('-', 78));

    var ranges = new (long min, long max, string label)[]
    {
        (0L,              1_048_575L,         "< 1 MB"),
        (1_048_576L,      104_857_600L,       "1 MB - 100 MB"),
        (104_857_601L,    3_221_225_472L,     "100 MB - 3 GB"),
        (3_221_225_473L,  long.MaxValue,      "> 3 GB"),
    };

    int bestTc = 50;
    Console.WriteLine(string.Format("  {0,-16} {1,8} {2,10} {3,8} {4,8}  Note",
        "Range", "BestTc", "FragSize", "FragCnt", "OH%"));
    Console.WriteLine("  " + new string('-', 78));

    foreach (var (min, max, label) in ranges)
    {
        long mid = Math.Max(min, (min + Math.Min(max, fileSizes[^1])) / 2);
        long fs = Math.Max(1024, mid);
        long fragSize = Math.Max(minFrag, Math.Min(maxFrag, fs / bestTc));
        int fragCount = (int)((fs + fragSize - 1) / fragSize);
        int each = 200 + 40 * fragCount;
        long embed = (long)fragCount * each;
        long header = fragCount * 6L;
        int stand = 500 + 80 * fragCount;
        long total = fs + embed + header + stand;
        double pct = (double)(total - fs) / fs * 100;

        string note = fragCount <= 4 ? "minFrag clamps" :
                      fragSize == maxFrag ? "maxFrag reached" : "balanced";

        Console.WriteLine(string.Format("  {0,-16} {1,8} {2,10} {3,8} {4,7:F2}%  {5}",
            label, bestTc, Fmt(fragSize), fragCount, pct, note));
    }

    Console.WriteLine();
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine("  Recommendation: targetCount = 50, minFrag = 256 KB, maxFrag = 64 MB");
    Console.WriteLine("  CLI override: -size <MB> always wins.");
    Console.ResetColor();

    string csvPath = Path.Combine(outDir, "frag_sim_results.csv");
    File.WriteAllLines(csvPath, csv);
    Console.WriteLine($"\n  CSV: {csvPath}");
}
finally
{
    if (Directory.Exists(outDir))
    {
        Directory.Delete(outDir, true);
        Console.WriteLine($"  Cleaned: {outDir}");
    }
}

static string Fmt(long bytes)
{
    if (bytes >= 1024L * 1024 * 1024 * 1024) return string.Format("{0:F1} TB", bytes / (1024.0 * 1024 * 1024 * 1024));
    if (bytes >= 1024L * 1024 * 1024)       return string.Format("{0:F1} GB", bytes / (1024.0 * 1024 * 1024));
    if (bytes >= 1024 * 1024)                return string.Format("{0:F1} MB", bytes / (1024.0 * 1024));
    if (bytes >= 1024)                        return string.Format("{0:F0} KB", bytes / 1024.0);
    return string.Format("{0} B", bytes);
}
