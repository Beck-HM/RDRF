using System.Security.Cryptography;
using Xunit;

namespace RDRF.Core.Tests;

public class VersioningTests
{
    [Fact]
    public void VersionChain_InitAndLoad_ShouldPersistConfig()
    {
        string dir = Path.Combine(Path.GetTempPath(), $"rdr_vc_{Guid.NewGuid():N}");
        try
        {
            var chain = Versioning.VersionChain.Init(dir);
            Assert.Equal(32, chain.Config.Salt.Length);
            Assert.Equal(600_000, chain.Config.KdfIterations);
            Assert.True(Versioning.VersionChain.Exists(dir));

            var loaded = Versioning.VersionChain.Load(dir);
            Assert.Equal(chain.Config.Salt, loaded.Config.Salt);
            Assert.Equal(chain.Config.KdfIterations, loaded.Config.KdfIterations);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    [Fact]
    public void VersionChain_WriteHead_ShouldTrackVersion()
    {
        string dir = Path.Combine(Path.GetTempPath(), $"rdr_vc_{Guid.NewGuid():N}");
        try
        {
            var chain = Versioning.VersionChain.Init(dir);
            Assert.Equal(0, chain.ReadHeadVersion());

            chain.WriteHead(1, "abc123");
            Assert.Equal(1, chain.ReadHeadVersion());
            Assert.Equal("abc123", chain.ReadHeadFingerprint());

            chain.WriteHead(2, "def456");
            Assert.Equal(2, chain.ReadHeadVersion());
            Assert.Equal("def456", chain.ReadHeadFingerprint());
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }

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
            var storage = new Storage.LocalFileAdapter(storageDir);

            using var orchestrator = new BackupOrchestrator(password, salt, storage);
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
    public async Task VersionedBackup_Fresh_ShouldCreateChainAndRestore()
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
                testFile, storageDir, password, "Initial", "FSS1");

            Assert.NotNull(fp);
            Assert.True(Directory.Exists(Path.Combine(storageDir, ".rdr_version")));

            var chain = Versioning.VersionChain.Load(Path.Combine(storageDir, ".rdr_version"));
            Assert.Equal(1, chain.ReadHeadVersion());
            string headFp = chain.ReadHeadFingerprint();
            Assert.Equal(fp, headFp);

        var history = Versioning.VersionedRestore.GetVersionHistory(storageDir, password);
            Assert.Single(history);
            Assert.Equal("Initial", history[0].UserMessage);
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
                testFile, storageDir, password, "V1", "FSS1");

            string v2 = "Line one.\nLine two modified.\nLine three new.\n";
            File.WriteAllText(testFile, v2);

            string fp2 = await Versioning.VersionedBackup.BackupAsync(
                testFile, storageDir, password, "V2: changes", "FSS1");

            Assert.NotEqual(fp1, fp2);

            var history = Versioning.VersionedRestore.GetVersionHistory(storageDir, password);
            Assert.Equal(2, history.Count);
            Assert.Equal("V1", history[0].UserMessage);
            Assert.Equal("V2: changes", history[1].UserMessage);
            Assert.True(history[1].SystemDiff.Length > 0);

            bool restored = await Versioning.VersionedRestore.RestoreAsync(outputFile, storageDir, password);
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

        var (diff, added, removed) = Versioning.DiffEngine.ComputeDiff(oldBytes, newBytes);

        Assert.True(diff.Length > 0, "Diff should not be empty");
        Assert.True(added > 0, $"Added bytes should be > 0, got: {added}");
        Assert.True(diff.Contains("line2_modified"), $"Diff should mention changed line, got: {diff}");
        Assert.True(diff.Contains("line4"), $"Diff should mention new line, got: {diff}");
    }

    [Fact]
    public void DiffEngine_IdenticalContent_ShouldBeMinimal()
    {
        byte[] data = System.Text.Encoding.UTF8.GetBytes("same content");
        var (diff, added, removed) = Versioning.DiffEngine.ComputeDiff(data, data);

        Assert.Equal(0, added);
        Assert.Equal(0, removed);
    }

    [Fact]
    public void DiffEngine_BinaryContent_ShouldNoteSizeChange()
    {
        byte[] oldBytes = new byte[] { 0x00, 0x01, 0x02, 0x03 };
        byte[] newBytes = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 };

        var (diff, added, removed) = Versioning.DiffEngine.ComputeDiff(oldBytes, newBytes);

        Assert.True(diff.Contains("binary"), "Should mark as binary");
        Assert.True(diff.Contains("Old size"), "Should mention old size");
        Assert.True(diff.Contains("New size"), "Should mention new size");
        Assert.Equal(1, added);
        Assert.Equal(0, removed);
    }
}
