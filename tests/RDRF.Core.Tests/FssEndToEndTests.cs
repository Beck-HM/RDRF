using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.Storage;
using RDRF.Core.FSS;
using RDRF.Core.Index;
using RDRF.Core.FragmentEngine;
using Xunit;
using Xunit.Abstractions;

namespace RDRF.Core.Tests;

/// <summary>
/// End>to>end tests: full Backup >> Restore cycle for every FSS strategy.
/// Uses tests/1.mp4 as test data.
/// All generated files go to tests/ directory and are cleaned up after.
/// </summary>
public class FssEndToEndTests
{
    private readonly ITestOutputHelper _output;

    public FssEndToEndTests(ITestOutputHelper output)
    {
        _output = output;
    }

    /// <summary>
    /// Test file is at tests/1.mp4 relative to solution root.
    /// </summary>
    private static string TestFile
    {
        get
        {
            // Assembly is at: tests/RDRF.Core.Tests/bin/Debug/net8.0/RDRF.Core.Tests.dll
            var dir = AppContext.BaseDirectory;
            // Go up to tests/ directory
            dir = Path.GetDirectoryName(dir)!; // net8.0
            dir = Path.GetDirectoryName(dir)!; // Debug
            dir = Path.GetDirectoryName(dir)!; // bin
            dir = Path.GetDirectoryName(dir)!; // RDRF.Core.Tests
            dir = Path.GetDirectoryName(dir)!; // tests
            return Path.Combine(dir, "1.mp4");
        }
    }

    private static string TestOutputDir => Path.Combine(Path.GetDirectoryName(TestFile)!, "RDRF_TestOutput");

    public static IEnumerable<object[]> AllStrategies => new[]
    {
        new object[] { "FSS1" },
        new object[] { "FSS2" },
        new object[] { "FSS2R" },
        new object[] { "FSS3" },
        new object[] { "FSS5" },
        new object[] { "FSS5+" },
        new object[] { "FSS6" },
    };

    public static IEnumerable<object[]> RecoverableStrategies => new[]
    {
        new object[] { "FSS1" },
        new object[] { "FSS2" },
        new object[] { "FSS2R" },
        new object[] { "FSS3" },
        new object[] { "FSS5" },
        new object[] { "FSS5+" },
    };

    private static string ComputeSha256(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        byte[] hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string CreateTestStorageDir(string strategy)
    {
        string dir = Path.Combine(TestOutputDir, $"{strategy}_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void Cleanup(string storageDir, string? outputFile = null)
    {
        try
        {
            if (Directory.Exists(storageDir))
                Directory.Delete(storageDir, recursive: true);
            if (outputFile != null && File.Exists(outputFile))
                File.Delete(outputFile);
        }
        catch
        {
            // Best>effort cleanup
        }
    }

    [Theory]
    [MemberData(nameof(AllStrategies))]
    public void BackupAndRestore_ShouldReturnIdenticalFile(string strategy)
    {
        // Assert test file exists
        Assert.True(File.Exists(TestFile), $"Test file not found: {TestFile}");

        string storageDir = CreateTestStorageDir(strategy);
        string outputFile = Path.Combine(TestOutputDir, $"restored_{strategy}_{Guid.NewGuid():N}.mp4");
        string originalHash = ComputeSha256(TestFile);

        try
        {
            // Create engine
            byte[] rcCode = EncryptionLayer.GenerateRcCode(32);
            var storage = new LocalFileAdapter(storageDir);
            using var engine = new RDRFEngine(rcCode, storage);

            // Backup
            _output.WriteLine($"[{strategy}] Backing up {TestFile}...");
            string fingerprint = engine.BackupFile(TestFile, strategy);
            Assert.False(string.IsNullOrEmpty(fingerprint));
            _output.WriteLine($"[{strategy}] Backup complete, fingerprint{fingerprint}");

            // Restore
            _output.WriteLine($"[{strategy}] Restoring to {outputFile}...");
            bool restored = engine.RestoreFile(fingerprint, outputFile);
            Assert.True(restored, $"[{strategy}] Restore returned false!");

            // Compare
            string restoredHash = ComputeSha256(outputFile);
            Assert.Equal(originalHash, restoredHash);
            _output.WriteLine($"[{strategy}] Files match: {originalHash}");
        }
        finally
        {
            Cleanup(storageDir, outputFile);
        }
    }

    [Theory]
    [MemberData(nameof(AllStrategies))]
    public void BackupAndRestoreAsync_ShouldReturnIdenticalFile(string strategy)
    {
        Assert.True(File.Exists(TestFile), $"Test file not found: {TestFile}");

        string storageDir = CreateTestStorageDir(strategy);
        string outputFile = Path.Combine(TestOutputDir, $"restored_async_{strategy}_{Guid.NewGuid():N}.mp4");
        string originalHash = ComputeSha256(TestFile);

        try
        {
            byte[] rcCode = EncryptionLayer.GenerateRcCode(32);
            var storage = new LocalFileAdapter(storageDir);
            using var engine = new RDRFEngine(rcCode, storage);

            // Async backup
            var task = engine.BackupFileAsync(TestFile, strategy);
            task.Wait();
            string fingerprint = task.Result;
            Assert.False(string.IsNullOrEmpty(fingerprint));

            // Async restore
            var restoreTask = engine.RestoreFileAsync(fingerprint, outputFile);
            restoreTask.Wait();
            bool restored = restoreTask.Result;
            Assert.True(restored, $"[{strategy}] Async restore returned false!");

            string restoredHash = ComputeSha256(outputFile);
            Assert.Equal(originalHash, restoredHash);
            _output.WriteLine($"[{strategy}] Async test passed: {originalHash}");
        }
        finally
        {
            Cleanup(storageDir, outputFile);
        }
    }

    [Theory]
    [MemberData(nameof(RecoverableStrategies))]
    public void BackupAndRestore_WithOneMissingFragment_ShouldRecover(string strategy)
    {
        Assert.True(File.Exists(TestFile), $"Test file not found: {TestFile}");

        string storageDir = CreateTestStorageDir(strategy);
        string outputFile = Path.Combine(TestOutputDir, $"recovered_{strategy}_{Guid.NewGuid():N}.mp4");
        string originalHash = ComputeSha256(TestFile);

        try
        {
            byte[] rcCode = EncryptionLayer.GenerateRcCode(32);
            var storage = new LocalFileAdapter(storageDir);
            using var engine = new RDRFEngine(rcCode, storage);

            // Backup
            string fingerprint = engine.BackupFile(TestFile, strategy);
            _output.WriteLine($"[{strategy}] Backup complete, fingerprint{fingerprint}");

            // Delete one fragment from storage (to test recovery)
            var backupDir = storageDir;
            var fragmentFiles = Directory.GetFiles(backupDir, "*.rdrf");
            Assert.True(fragmentFiles.Length > 1,
                $"Need at least 2 fragments for recovery test, got {fragmentFiles.Length}");

            // Delete the first fragment (index 0)
            string? frag0 = fragmentFiles.FirstOrDefault(f =>
                f.EndsWith("_0.rdrf", StringComparison.OrdinalIgnoreCase));
            if (frag0 != null)
            {
                File.Delete(frag0);
                _output.WriteLine($"[{strategy}] Deleted fragment: {Path.GetFileName(frag0)}");
            }

            // Restore with recovery
            _output.WriteLine($"[{strategy}] Calling engine.RestoreFile...");
            // Simulate in>test download to check
            _output.WriteLine($"  Remaining fragment count: {Directory.GetFiles(storageDir, "*.rdrf").Length}");
            
            // Read index and check needsCtr
            var idxEnc = storage.ReadIndex(fingerprint);
            (byte[] testKey, byte[] idxCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(idxEnc, rcCode);
            var idxData = IndexManager.DeserializeIndex(idxCbor);
            _output.WriteLine($"  Index: strategy{idxData.FssStrategy}, frags{idxData.FragentCount}");
            if (idxData.FssParams?.TryGetValue("plan", out var pObj) == true)
            {
                _output.WriteLine($"  plan type{pObj?.GetType().FullName}");
                // Check manual Decrypt
                var remainingFiles = Directory.GetFiles(storageDir, "*.rdrf").OrderBy(f => f).ToArray();
                int okCount = 0;
                int failCount = 0;
                foreach (var f in remainingFiles)
                {
                    try
                    {
                        var enc = File.ReadAllBytes(f);
                        var dec = EncryptionLayer.DecryptFragmentCtrWithKey(enc, testKey);
                        okCount++;
                    }
                    catch { failCount++; }
                }
                _output.WriteLine($"  Manual decrypt Ctr: {okCount} ok, {failCount} fail");
            }
            
            bool restored = engine.RestoreFile(fingerprint, outputFile, allowFssRecovery: true);
            _output.WriteLine($"[{strategy}] RestoreFile returned: {restored}");
            Assert.True(restored, $"[{strategy}] Recovery restore returned false!");

            // Compare
            string restoredHash = ComputeSha256(outputFile);
            Assert.Equal(originalHash, restoredHash);
            _output.WriteLine($"[{strategy}] Recovery test passed (1 fragment removed)");
        }
        finally
        {
            Cleanup(storageDir, outputFile);
        }
    }

    [Fact]
    public void WrongKey_ShouldFailDecrypt()
    {
        string storageDir = CreateTestStorageDir("WRONG_KEY");
        string outputFile = Path.Combine(TestOutputDir, "wrongkey_test.mp4");
        string originalHash = ComputeSha256(TestFile);

        try
        {
            byte[] rcCode = EncryptionLayer.GenerateRcCode(32);
            byte[] wrongRcCode = EncryptionLayer.GenerateRcCode(32);

            var storage = new LocalFileAdapter(storageDir);

            // Backup with correct key
            using (var engine = new RDRFEngine(rcCode, storage))
            {
                string fingerprint = engine.BackupFile(TestFile, "FSS1");
                _output.WriteLine($"Backup with correct key, fingerprint{fingerprint}");
            }

            // Try to restore with wrong key
            using (var engine2 = new RDRFEngine(wrongRcCode, storage))
            {
                string fingerprint2 = "?";
                var indexFiles = Directory.GetFiles(storageDir, "*.indrdrf");
                if (indexFiles.Length > 0)
                {
                    // Extract fingerprint from filename
                    fingerprint2 = Path.GetFileNameWithoutExtension(indexFiles[0]);
                }
                _output.WriteLine($"Attempting restore with wrong key...");

                // Should throw CryptographicException on index decryption
                var ex = Assert.ThrowsAny<CryptographicException>(() =>
                {
                    engine2.RestoreFile(fingerprint2, outputFile);
                });
                _output.WriteLine($"OK - Correctly threw: {ex.GetType().Name}");
            }
        }
        finally
        {
            Cleanup(storageDir, outputFile);
        }
    }
}
