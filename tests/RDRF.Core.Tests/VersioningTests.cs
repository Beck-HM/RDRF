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

            // V1's files should have been cleaned up
            string v1Index = Path.Combine(storageDir, fp1 + ".indrdrf");
            Assert.False(File.Exists(v1Index), "V1 index should be cleaned up");

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

