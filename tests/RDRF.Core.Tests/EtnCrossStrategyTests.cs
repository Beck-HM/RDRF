using System.Security.Cryptography;
using RDRF.Core.Encryption;
using RDRF.Core.FSS;
using RDRF.Core.Index;
using RDRF.Core.Storage;
using Xunit;
using Xunit.Abstractions;

namespace RDRF.Core.Tests;

[Collection("EtnSerial")]
/// <summary>
/// Phase 5  - Cross>FSS strategy compatibility with ETN.
/// Verifies that ETN works with FSS1/3/5 without breaking core backup/restore.
/// </summary>
public class EtnCrossStrategyTests
{
    private readonly ITestOutputHelper _output;

    public EtnCrossStrategyTests(ITestOutputHelper output)
    {
        _output = output;
    }

    public static IEnumerable<object[]> FssStrategies()
    {
        yield return new object[] { "FSS1" };
        yield return new object[] { "FSS2" };
        yield return new object[] { "FSS3" };
        yield return new object[] { "FSS5" };
    }

    public static IEnumerable<object[]> FssRecoveryStrategies()
    {
        // Strategies that can recover from missing fragments
        yield return new object[] { "FSS3", 1 };
        yield return new object[] { "FSS5", 1 };
        yield return new object[] { "FSS1", 1 };
    }

    [Theory]
    [MemberData(nameof(FssStrategies))]
    public void BackupAndRestoreWithFssPlusEtn(string strategy)
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            byte[] rcCode = EncryptionLayer.GenerateRcCode(32);
            byte[] rcCodeClone = (byte[])rcCode.Clone();
            var storage = new LocalFileAdapter(storageDir);

            string fingerprint;
            using (var engine = new RDRFEngine(rcCode, storage))
            {
                fingerprint = engine.BackupFile(
                    EtnTestHelpers.TestFile, strategy,
                    auxiliaryStrategies: new List<string> { "FSS6" });
            }
            _output.WriteLine($"  Backup ({strategy}+FSS6): {fingerprint}");

            Assert.True(storage.RcExists(fingerprint), "RC file must exist after FSS6 backup");

            string restorePath = Path.Combine(EtnTestHelpers.TestOutputDir, $"recov_{Guid.NewGuid():N}.mp4");
            using (var engine = new RDRFEngine(rcCodeClone, storage))
            {
                bool success = engine.RestoreFile(fingerprint, restorePath);
                Assert.True(success, $"Restore {strategy}+FSS6 should succeed");
            }

            byte[] originalHash = SHA256.HashData(File.ReadAllBytes(EtnTestHelpers.TestFile));
            byte[] restoredHash = SHA256.HashData(File.ReadAllBytes(restorePath));
            Assert.Equal(Convert.ToHexString(originalHash), Convert.ToHexString(restoredHash));

            try { File.Delete(restorePath); } catch { }

            _output.WriteLine($"PASS: {strategy}+FSS6 backup/restore");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void Fss6Alone_BackupAndRestore()
    {
        // FSS6 without any other FSS strategy
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            byte[] rcCode = EncryptionLayer.GenerateRcCode(32);
            byte[] rcCodeClone = (byte[])rcCode.Clone();
            var storage = new LocalFileAdapter(storageDir);

            string fingerprint;
            using (var engine = new RDRFEngine(rcCode, storage))
            {
                fingerprint = engine.BackupFile(EtnTestHelpers.TestFile, "FSS6");
            }
            _output.WriteLine($"  Backup (FSS6 only): {fingerprint}");

            Assert.True(storage.RcExists(fingerprint));

            string restorePath = Path.Combine(EtnTestHelpers.TestOutputDir, $"recov_{Guid.NewGuid():N}.mp4");
            using (var engine = new RDRFEngine(rcCodeClone, storage))
            {
                bool success = engine.RestoreFile(fingerprint, restorePath);
                Assert.True(success, "FSS6 restore should succeed");
            }

            byte[] originalHash = SHA256.HashData(File.ReadAllBytes(EtnTestHelpers.TestFile));
            byte[] restoredHash = SHA256.HashData(File.ReadAllBytes(restorePath));
            Assert.Equal(Convert.ToHexString(originalHash), Convert.ToHexString(restoredHash));

            try { File.Delete(restorePath); } catch { }
            _output.WriteLine("PASS: FSS6 alone backup/restore");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void Fss6CrossValidation_AfterFragmentRecovery()
    {
        // FSS3+FSS6: drop a fragment, FSS3 recovers it, then verify ETN validates
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            byte[] rcCode = EncryptionLayer.GenerateRcCode(32);
            byte[] rcCodeClone = (byte[])rcCode.Clone();
            var storage = new LocalFileAdapter(storageDir);

            string fingerprint;
            using (var engine = new RDRFEngine((byte[])rcCode.Clone(), storage))
            {
                fingerprint = engine.BackupFile(
                    EtnTestHelpers.TestFile, "FSS3",
                    auxiliaryStrategies: new List<string> { "FSS6" });
            }
            _output.WriteLine($"  Backup (FSS3+FSS6): {fingerprint}");

            // Delete a fragment to simulate loss
            (_, byte[] idxCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(
                storage.ReadIndex(fingerprint), rcCodeClone);
            var index = IndexManager.DeserializeIndex(idxCbor);
            string prefix = index.CustomName ?? fingerprint;
            string fragToDelete = $"{prefix}_0.rdrf";
            string fragPath = Path.Combine(storageDir, fragToDelete);
            File.Delete(fragPath);
            _output.WriteLine($"  Deleted {fragToDelete}");

            // Restore with recovery  - FSS3 should reconstruct the missing fragment
            string restorePath = Path.Combine(EtnTestHelpers.TestOutputDir, $"recov_{Guid.NewGuid():N}.mp4");
            using (var engine = new RDRFEngine(rcCodeClone, storage))
            {
                bool success = engine.RestoreFile(fingerprint, restorePath);
                Assert.True(success, "FSS3+FSS6 restore with missing fragment should succeed");
            }

            byte[] originalHash = SHA256.HashData(File.ReadAllBytes(EtnTestHelpers.TestFile));
            byte[] restoredHash = SHA256.HashData(File.ReadAllBytes(restorePath));
            Assert.Equal(Convert.ToHexString(originalHash), Convert.ToHexString(restoredHash));

            try { File.Delete(restorePath); } catch { }
            _output.WriteLine("PASS: FSS3+FSS6: fragment recovered and verified");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }
}
