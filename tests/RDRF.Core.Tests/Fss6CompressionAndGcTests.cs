using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.DSAA;
using RDRF.Core.Encryption;
using RDRF.Core.FSS;
using RDRF.Core.Index;
using RDRF.Core.Versioning;
using Xunit;

namespace RDRF.Core.Tests;

/// <summary>
/// FSS6/6.1 compression E2E, verify-after-backup regression, versioned restore, gcMode.
/// No legacy-compat requirements.
/// </summary>
[Collection("EtnSerial")]
public class Fss6CompressionAndGcTests
{
    private static string Sha(string path)
    {
        using var fs = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
    }

    private static byte[] MakePayload(int size)
    {
        var b = new byte[size];
        new Random(42).NextBytes(b);
        for (int i = 0; i < b.Length; i += 4) b[i] = 0;
        return b;
    }

    [Theory]
    [InlineData("FSS6", "lz4")]
    [InlineData("FSS6.1", "lz4")]
    [InlineData("FSS6.2", "lz4")]
    public void BackupRestore_WithCompression_RoundTrip(string strategy, string compression)
    {
        string dir = EtnTestHelpers.CreateStorageDir();
        string src = Path.Combine(dir, "src.bin");
        string outPath = Path.Combine(dir, "out.bin");
        File.WriteAllBytes(src, MakePayload(48 * 1024));
        string want = Sha(src);
        try
        {
            byte[] pw = EncryptionLayer.GenerateRcCode(32);
            using var engine = new RDRFEngine(pw, new LocalDSAAAdapter(dir));
            string fp = engine.BackupFile(src, strategy, compressionMethod: compression);
            Assert.False(string.IsNullOrEmpty(fp));

            byte[] encIdx = new LocalDSAAAdapter(dir).ReadIndex(fp);
            (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encIdx, pw);
            var index = IndexManager.DeserializeIndex(cbor);
            Assert.Equal(compression, index.Compression, ignoreCase: true);

            Assert.True(engine.RestoreFile(fp, outPath));
            Assert.Equal(want, Sha(outPath));
        }
        finally { EtnTestHelpers.Cleanup(dir); }
    }

    [Fact]
    public void Fss61_VerifyAfterBackup_IsValid()
    {
        string dir = EtnTestHelpers.CreateStorageDir();
        string src = Path.Combine(dir, "src.bin");
        File.WriteAllBytes(src, MakePayload(16 * 1024));
        try
        {
            byte[] pw = EncryptionLayer.GenerateRcCode(32);
            var storage = new LocalDSAAAdapter(dir);
            string fp;
            using (var engine = new RDRFEngine(pw, storage))
                fp = engine.BackupFile(src, "FSS6.1", compressionMethod: "lz4");

            byte[] encIdx = storage.ReadIndex(fp);
            (byte[] key, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encIdx, pw);
            var index = IndexManager.DeserializeIndex(cbor);
            Assert.NotNull(index.Fss6FragmentBlockMapsFlat);
            Assert.NotNull(index.Fss6RcBlockMapFlat);

            byte[] rcEnc = storage.ReadRc(fp);
            byte[] rc = EncryptionLayer.DecryptFragmentWithKey(rcEnc, key);
            var frags = new List<byte[]>();
            for (int i = 0; i < index.FragmentCount; i++)
            {
                byte[] file = storage.ReadFragment($"{fp}_{i}.rdrf");
                var (_, body, _) = FragmentFileHeader.DecryptWithEmbeddedIndex(file, key);
                frags.Add(body);
            }
            var cv = Fss6Etn.CrossValidate(cbor, frags, rc);
            Assert.True(cv.IsValid, $"IndexBad={cv.IndexCorrupted} RcBad={cv.RcCorrupted} Frags={cv.CorruptedFragments.Count}");
        }
        finally { EtnTestHelpers.Cleanup(dir); }
    }

    [Fact]
    public async Task VersionedBackup_TwoVersions_HistoryAndLatestRestore()
    {
        string dir = EtnTestHelpers.CreateStorageDir();
        string f1 = Path.Combine(dir, "a.bin");
        string f2 = Path.Combine(dir, "b.bin");
        File.WriteAllBytes(f1, MakePayload(8192));
        var b2 = MakePayload(8192);
        b2[^1] ^= 0xFF;
        File.WriteAllBytes(f2, b2);
        string h1 = Sha(f1);
        string h2 = Sha(f2);
        try
        {
            byte[] pw = EncryptionLayer.GenerateRcCode(32);
            var storage = new LocalDSAAAdapter(dir);
            // Real-incremental (default): each distinct content gets its own fingerprint index.
            string fp1 = await VersionedBackup.BackupAsync(f1, storage, pw, "v1", "FSS1",
                compressionMethod: "lz4");
            string fp2 = await VersionedBackup.BackupAsync(f2, storage, pw, "v2", "FSS1",
                compressionMethod: "lz4");
            Assert.NotEqual(fp1, fp2);
            Assert.True(storage.IndexExists(fp1));
            Assert.True(storage.IndexExists(fp2));

            string idx1 = Path.Combine(dir, fp1 + Constants.IndexFileSuffix);
            string idx2 = Path.Combine(dir, fp2 + Constants.IndexFileSuffix);

            string o1 = Path.Combine(dir, "v1.bin");
            string o2 = Path.Combine(dir, "v2.bin");
            Assert.True(VersionedRestore.Restore(o1, idx1, pw));
            Assert.True(VersionedRestore.Restore(o2, idx2, pw));
            Assert.Equal(h1, Sha(o1));
            Assert.Equal(h2, Sha(o2));

            // Latest index history should include both version records (synced on v2).
            var hist = VersionedRestore.GetVersionHistory(idx2, pw);
            Assert.True(hist.Count >= 2, $"expected >=2 history entries, got {hist.Count}");
            Assert.Contains(hist, v => v.Version == 1 || v.UserMessage == "v1");
            Assert.Contains(hist, v => v.Version == 2 || v.UserMessage == "v2");
        }
        finally { EtnTestHelpers.Cleanup(dir); }
    }

    [Fact]
    public async Task GcMode_Incremental_DoesNotThrow_AndRestoresLatest()
    {
        string dir = EtnTestHelpers.CreateStorageDir();
        string f1 = Path.Combine(dir, "a.bin");
        string f2 = Path.Combine(dir, "b.bin");
        File.WriteAllBytes(f1, MakePayload(4096));
        var b2 = MakePayload(4096);
        b2[0] ^= 0xAA;
        File.WriteAllBytes(f2, b2);
        string h2 = Sha(f2);
        try
        {
            byte[] pw = EncryptionLayer.GenerateRcCode(32);
            var storage = new LocalDSAAAdapter(dir);
            await VersionedBackup.BackupAsync(f1, storage, pw, "v1", "FSS1",
                compressionMethod: "lz4", gcMode: true);
            string p = await VersionedBackup.BackupAsync(f2, storage, pw, "v2", "FSS1",
                compressionMethod: "lz4", gcMode: true);
            string outPath = Path.Combine(dir, "out.bin");
            string idxPath = Path.Combine(dir, p + Constants.IndexFileSuffix);
            Assert.True(VersionedRestore.Restore(outPath, idxPath, pw));
            Assert.Equal(h2, Sha(outPath));
        }
        finally { EtnTestHelpers.Cleanup(dir); }
    }

    [Fact]
    public void DeleteIndexAndRc_Api_Works()
    {
        string dir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var storage = new LocalDSAAAdapter(dir);
            storage.WriteIndex("abc", new byte[] { 1, 2, 3 });
            storage.WriteRc("abc", new byte[] { 4, 5 });
            Assert.True(storage.IndexExists("abc"));
            Assert.True(storage.RcExists("abc"));
            storage.DeleteIndex("abc");
            storage.DeleteRc("abc");
            Assert.False(storage.IndexExists("abc"));
            Assert.False(storage.RcExists("abc"));
        }
        finally { EtnTestHelpers.Cleanup(dir); }
    }
}
