using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.DSAA;
using RDRF.Core.Encryption;
using RDRF.Core.FSS;
using Xunit;

namespace RDRF.Core.Tests;

/// <summary>
/// Regression: FSS5 IsValidFss5Fragment used a 1 MiB part-size cap, so adaptive fragments
/// above 1 MiB (common for multi‑tens‑of‑MB files) failed StripSingle and corrupted restore.
/// </summary>
public class Fss5LargeRestoreTests
{
    [Fact]
    public void Fss5_Strip_AcceptsPartsAbove1MiB()
    {
        // Two ~1.5 MiB raw fragments → FSS5 combined own/n1/n2 each > 1 MiB
        int part = (int)(1.5 * 1024 * 1024);
        var raw = new List<byte[]>
        {
            Make(part, 1),
            Make(part, 2),
            Make(part, 3),
            Make(part / 2, 4),
        };
        var engine = new FSSEngine();
        var encoded = engine.Encode(raw, "FSS5");
        var sizes = raw.Select(r => r.Length).ToList();
        var dict = Enumerable.Range(0, encoded.Count).ToDictionary(i => i, i => encoded[i]);
        var stripped = engine.Strip(dict, "FSS5", raw.Count, sizes);
        Assert.Equal(raw.Count, stripped.Count);
        for (int i = 0; i < raw.Count; i++)
            Assert.Equal(raw[i], stripped[i]);
    }

    [Fact]
    public void Fss5_BackupRestore_MultiMeg_Lz4_RoundTrip()
    {
        // ~6 MiB forces adaptive frag size often > 1 MiB with default target count
        const int size = 6 * 1024 * 1024;
        string dir = Path.Combine(Path.GetTempPath(), "fss5_large_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        string src = Path.Combine(dir, "src.bin");
        string outPath = Path.Combine(dir, "out.bin");
        try
        {
            File.WriteAllBytes(src, Make(size, 9));
            string want = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(src))).ToLowerInvariant();
            byte[] pw = EncryptionLayer.GenerateRcCode(32);
            using var eng = new RDRFEngine(pw, new LocalDSAAAdapter(dir));
            string fp = eng.BackupFile(src, "FSS5", compressionMethod: "lz4");
            Assert.False(string.IsNullOrEmpty(fp));
            Assert.True(eng.RestoreFile(fp, outPath));
            string got = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(outPath))).ToLowerInvariant();
            Assert.Equal(want, got);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* best-effort */ }
        }
    }

    private static byte[] Make(int n, int seed)
    {
        var b = new byte[n];
        new Random(seed).NextBytes(b);
        for (int i = 0; i < b.Length; i += 4) b[i] = 0;
        return b;
    }
}
