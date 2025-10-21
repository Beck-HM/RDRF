using System.Security.Cryptography;
using RDRF.Core.Diff;
using RDRF.Core.Dssa;
using Xunit;

namespace RDRF.Core.Tests;

public class VersioningTests
{
    [Fact]
    public async Task SaltBasedOrchestrator_ProducesReadableIndex()
    {
        string storageDir = Path.Combine(Path.GetTempPath(), $"rdr_sb_{Guid.NewGuid():N}");
        string testFile = Path.Combine(Path.GetTempPath(), $"rdr_sb_in_{Guid.NewGuid():N}.txt");
        try
        {
            byte[] password = RandomNumberGenerator.GetBytes(32);
            File.WriteAllText(testFile, "Salt based orchestrator test.");

            byte[] salt = RandomNumberGenerator.GetBytes(32);
            var storage = new LocalDssaAdapter(storageDir);

            using var orchestrator = new BackupOrchestrator(password, storage, salt);
            string fingerprint = await orchestrator.BackupFileAsync(testFile, "FSS1");

            byte[] encIdx = storage.ReadIndex(fingerprint);
            var (key, cbor) = Encryption.EncryptionLayer.DecryptIndexWithAutoDetect(encIdx, password);
            var idx = Index.IndexManager.DeserializeIndex(cbor);
            Assert.Equal(fingerprint, idx.FileFingerprint);
        }
        finally
        {
            try { File.Delete(testFile); } catch { }
            try { Directory.Delete(storageDir, true); } catch { }
        }
    }

    [Fact]
    public async Task VersionedBackup_Fresh_ShouldCreateVersionRecord()
    {
        string storageDir = Path.Combine(Path.GetTempPath(), $"rdr_vf_{Guid.NewGuid():N}");
        string outputFile = Path.Combine(Path.GetTempPath(), $"rdr_vf_out_{Guid.NewGuid():N}.txt");
        string testFile = Path.Combine(Path.GetTempPath(), $"rdr_vf_in_{Guid.NewGuid():N}.txt");

        try
        {
            byte[] password = RandomNumberGenerator.GetBytes(32);
            string content = "Versioned backup content line one.\nLine two.\nLine three.\n";
            File.WriteAllText(testFile, content);

            string fp = await Versioning.VersionedBackup.BackupAsync(
                testFile, new LocalDssaAdapter(storageDir), password, "Initial", "FSS1");

            string indexFile = Path.Combine(storageDir, fp + ".indrdrf");
            Assert.True(File.Exists(indexFile));

            var history = Versioning.VersionedRestore.GetVersionHistory(indexFile, password);
            Assert.Single(history);
            Assert.Equal("Initial", history[0].UserMessage);
            Assert.Equal(1, history[0].Version);
        }
        finally
        {
            try { File.Delete(testFile); } catch { }
            try { File.Delete(outputFile); } catch { }
            try { Directory.Delete(storageDir, true); } catch { }
        }
    }

    [Fact]
    public async Task VersionedBackup_Incremental_ShouldAppendVersionAndDiff()
    {
        string storageDir = Path.Combine(Path.GetTempPath(), $"rdr_vi_{Guid.NewGuid():N}");
        string outputFile = Path.Combine(Path.GetTempPath(), $"rdr_vi_out_{Guid.NewGuid():N}.txt");
        string testFile = Path.Combine(Path.GetTempPath(), $"rdr_vi_in_{Guid.NewGuid():N}.txt");

        try
        {
            byte[] password = RandomNumberGenerator.GetBytes(32);
            string v1 = "Line one.\nLine two.\n";
            File.WriteAllText(testFile, v1);

            string fp1 = await Versioning.VersionedBackup.BackupAsync(
                testFile, new LocalDssaAdapter(storageDir), password, "V1", "FSS1");

            string v2 = "Line one.\nLine two modified.\nLine three new.\n";
            File.WriteAllText(testFile, v2);

            string fp2 = await Versioning.VersionedBackup.BackupAsync(
                testFile, new LocalDssaAdapter(storageDir), password, "V2: changes", "FSS1");

            Assert.NotEqual(fp1, fp2);

            // V1 index preserved (dedup may reference its fragments)
            string v1Index = Path.Combine(storageDir, fp1 + ".indrdrf");

            // V2's index is the only one
            string v2Index = Path.Combine(storageDir, fp2 + ".indrdrf");
            Assert.True(File.Exists(v2Index));

            var history = Versioning.VersionedRestore.GetVersionHistory(v2Index, password);
            Assert.Equal(2, history.Count);
            Assert.Equal("V1", history[0].UserMessage);
            Assert.Equal("V2: changes", history[1].UserMessage);
            Assert.True(history[1].SystemDiff.Length > 0);

            bool restored = Versioning.VersionedRestore.Restore(outputFile, v2Index, password);
            Assert.True(restored);
            Assert.Equal(v2, File.ReadAllText(outputFile));
        }
        finally
        {
            try { File.Delete(testFile); } catch { }
            try { File.Delete(outputFile); } catch { }
            try { Directory.Delete(storageDir, true); } catch { }
        }
    }

    [Fact]
    public async Task VersionedBackup_Dedup_ShouldReuseUnchangedFragments()
    {
        string storageDir = Path.Combine(Path.GetTempPath(), $"rdr_dd_{Guid.NewGuid():N}");
        string testFile = Path.Combine(Path.GetTempPath(), $"rdr_dd_in_{Guid.NewGuid():N}.dat");
        string outputFile = Path.Combine(Path.GetTempPath(), $"rdr_dd_out_{Guid.NewGuid():N}.dat");

        try
        {
            byte[] password = RandomNumberGenerator.GetBytes(32);
            int fragSize = 256;

            // Use JPEG-prefix so Compressor skips LZ4 (fragment-aligned raw data)
            var rng = new Random(42);
            byte[] v1Base = new byte[2048];
            v1Base[0] = 0xff; v1Base[1] = 0xd8; v1Base[2] = 0xff; v1Base[3] = 0xe0;
            rng.NextBytes(new Span<byte>(v1Base, 4, 2044));
            File.WriteAllBytes(testFile, v1Base);

            string fp1 = await Versioning.VersionedBackup.BackupAsync(
                testFile, new LocalDssaAdapter(storageDir), password, "V1", "FSS1",
                fragmentSize: fragSize);

            // V2: change last 512 bytes — DedupMap is still empty, all 8 fragments written
            byte[] v2Data = new byte[2048];
            v2Data[0] = 0xff; v2Data[1] = 0xd8; v2Data[2] = 0xff; v2Data[3] = 0xe0;
            Buffer.BlockCopy(v1Base, 4, v2Data, 4, 1532);
            rng.NextBytes(new Span<byte>(v2Data, 1536, 512));
            File.WriteAllBytes(testFile, v2Data);

            string fp2 = await Versioning.VersionedBackup.BackupAsync(
                testFile, new LocalDssaAdapter(storageDir), password, "V2", "FSS1",
                fragmentSize: fragSize);

            // V3: keep first 1536 bytes (same as V2), replace last 512 AGAIN
            // Now DedupMap has entries from V2 — unchanged fragments should reference V2
            byte[] v3Data = new byte[2048];
            v3Data[0] = 0xff; v3Data[1] = 0xd8; v3Data[2] = 0xff; v3Data[3] = 0xe0;
            Buffer.BlockCopy(v2Data, 4, v3Data, 4, 1532);
            rng.NextBytes(new Span<byte>(v3Data, 1536, 512));
            File.WriteAllBytes(testFile, v3Data);

            string fp3 = await Versioning.VersionedBackup.BackupAsync(
                testFile, new LocalDssaAdapter(storageDir), password, "V3", "FSS1",
                fragmentSize: fragSize);

            // Verify V2's DedupMap has entries
            byte[] encIdx2 = new LocalDssaAdapter(storageDir).ReadIndex(fp2);
            (_, byte[] cbor2) = Encryption.EncryptionLayer.DecryptIndexWithAutoDetect(encIdx2, password);
            var idx2 = Index.IndexManager.DeserializeIndex(cbor2);
            Assert.NotNull(idx2.DedupMap);
            Assert.True(idx2.DedupMap.Count > 0, $"V2 DedupMap empty, should have {idx2.Fragments?.Count ?? 0} entries");

            // Check how many V3 fragment hashes exist in V2's DedupMap
            byte[] v3Raw = File.ReadAllBytes(testFile);
            byte[] v3Comp = RDRF.Core.Compression.Compressor.Compress(v3Raw, Constants.CompressionLz4);
            var v3Frags = new List<byte[]>();
            for (int off = 0; off < v3Comp.Length; off += 256)
                v3Frags.Add(v3Comp.AsSpan(off, Math.Min(256, v3Comp.Length - off)).ToArray());
            var v3Keys = v3Frags.Select(f => Convert.ToHexString(System.IO.Hashing.XxHash128.Hash(f.AsSpan())).ToLowerInvariant()).ToArray();
            int matchCount = v3Keys.Count(k => idx2.DedupMap!.ContainsKey(k));

            // Check V2's fragments vs V3's: compare raw hashes counted in V2's DedupMap
            int v3HitsInV2Map = 0;
            for (int i = 0; i < v3Frags.Count; i++)
            {
                string k3 = Convert.ToHexString(System.IO.Hashing.XxHash128.Hash(v3Frags[i].AsSpan())).ToLowerInvariant();
                if (idx2.DedupMap!.ContainsKey(k3))
                    v3HitsInV2Map++;
            }

            // Check V3's actual index Fragments for SourceVersion
            byte[] encIdx3 = new LocalDssaAdapter(storageDir).ReadIndex(fp3);
            (_, byte[] cb3) = Encryption.EncryptionLayer.DecryptIndexWithAutoDetect(encIdx3, password);
            var ix3 = Index.IndexManager.DeserializeIndex(cb3);
            int svCount = ix3.Fragments?.Count(f => f.SourceVersion != null) ?? 0;

            // Also check V2's index right after AppendVersionRecord
            byte[] encIdx2b = new LocalDssaAdapter(storageDir).ReadIndex(fp2);
            (_, byte[] cb2b) = Encryption.EncryptionLayer.DecryptIndexWithAutoDetect(encIdx2b, password);
            var idx2b = Index.IndexManager.DeserializeIndex(cb2b);
            int v2mapCount = idx2b.DedupMap?.Count ?? 0;

            Assert.True(v2mapCount > 0, $"V2 DedupMap has {v2mapCount} entries after AppendVersionRecord");
            Assert.True(v3HitsInV2Map > 0, $"V3 hashes hit V2 map: {v3HitsInV2Map}/{v3Frags.Count}");
            Assert.True(svCount > 0, $"V3 index has {svCount} fragments with SourceVersion");

            // V3 index should have DedupMap
            byte[] encIdx = new LocalDssaAdapter(storageDir).ReadIndex(fp3);
            (_, byte[] cbor) = Encryption.EncryptionLayer.DecryptIndexWithAutoDetect(encIdx, password);
            var idx3 = Index.IndexManager.DeserializeIndex(cbor);

            // Fragments 0-5 should reference V2 (unchanged from V2)
            Assert.NotNull(idx3.Fragments);
            bool hasRef = idx3.Fragments.Any(f => f.SourceVersion != null);
            Assert.True(hasRef, "Unchanged fragments should reference a prior version");

            // Each reference must include SourceIndex
            foreach (var f in idx3.Fragments.Where(f => f.SourceVersion != null))
                Assert.True(f.SourceIndex.HasValue,
                    $"Fragment {f.Index} has SourceVersion but missing SourceIndex");

            // V2 index preserved (fragments still referenced by V3)
            string v2Idx = Path.Combine(storageDir, fp2 + ".indrdrf");
            Assert.True(File.Exists(v2Idx), "V2 index must be preserved for dedup");

            // Verify V2 restore (full ownership, no dedup refs)
            string v2Out = Path.Combine(Path.GetTempPath(), $"rdr_dd_v2_{Guid.NewGuid():N}.dat");
            try
            {
                Assert.True(Versioning.VersionedRestore.Restore(
                    v2Out, Path.Combine(storageDir, fp2 + ".indrdrf"), password),
                    $"V2 restore should work");
            }
            finally { try { File.Delete(v2Out); } catch { } }

            // Verify V3 restore (has dedup refs)
            Assert.True(Versioning.VersionedRestore.Restore(
                outputFile, Path.Combine(storageDir, fp3 + ".indrdrf"), password),
                $"V3 restore should work");
            Assert.Equal(v3Data.Length, new FileInfo(outputFile).Length);
            Assert.Equal(v3Data, File.ReadAllBytes(outputFile));
        }
        finally
        {
            try { File.Delete(testFile); } catch { }
            try { File.Delete(outputFile); } catch { }
            try { Directory.Delete(storageDir, true); } catch { }
        }
    }

    [Fact]
    public void DiffEngine_TextContent_ShouldProduceUnifiedDiff()
    {
        string oldText = "line1\nline2\nline3\n";
        string newText = "line1\nline2_modified\nline3\nline4\n";

        byte[] oldBytes = System.Text.Encoding.UTF8.GetBytes(oldText);
        byte[] newBytes = System.Text.Encoding.UTF8.GetBytes(newText);

        var result = new DiffEngine().ComputeDiff(oldBytes, newBytes);

        Assert.True(result.HumanDiff.Length > 0, "Diff should not be empty");
        Assert.True(result.AddedBytes > 0, $"Added bytes should be > 0, got: {result.AddedBytes}");
        Assert.True(result.HumanDiff.Contains("line2_modified"), $"Diff should mention changed line, got: {result.HumanDiff}");
        Assert.True(result.HumanDiff.Contains("line4"), $"Diff should mention new line, got: {result.HumanDiff}");
    }

    [Fact]
    public void DiffEngine_IdenticalContent_ShouldBeMinimal()
    {
        byte[] data = System.Text.Encoding.UTF8.GetBytes("same content");
        var result = new DiffEngine().ComputeDiff(data, data);

        Assert.Equal(0, result.AddedBytes);
        Assert.Equal(0, result.RemovedBytes);
    }

    [Fact]
    public void DiffEngine_BinaryContent_ShouldNoteSizeChange()
    {
        byte[] oldBytes = new byte[] { 0x00, 0x01, 0x02, 0x03 };
        byte[] newBytes = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 };

        var result = new DiffEngine().ComputeDiff(oldBytes, newBytes);

        Assert.True(result.HumanDiff.Contains("binary"), "Should mark as binary");
        Assert.True(result.HumanDiff.Contains("Old size"), "Should mention old size");
        Assert.True(result.HumanDiff.Contains("New size"), "Should mention new size");
        Assert.Equal(1, result.AddedBytes);
        Assert.Equal(0, result.RemovedBytes);
    }
}

