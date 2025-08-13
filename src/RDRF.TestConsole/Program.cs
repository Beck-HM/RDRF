using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.Storage;

namespace RDRF.TestConsole;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("=== RDRF.Core Test Suite ===\n");

        string testDir = Path.Combine(Path.GetTempPath(), "rdrf_test_" + Guid.NewGuid().ToString("N").Substring(0, 8));
        string backupDir = Path.Combine(testDir, "backup");
        string restoreDir = Path.Combine(testDir, "restore");
        string testFile = Path.Combine(testDir, "testfile.txt");

        Directory.CreateDirectory(testDir);
        Directory.CreateDirectory(backupDir);
        Directory.CreateDirectory(restoreDir);

        string testContent = "Hello, RDRF! This is a test file for encryption and recovery testing. " +
                             "It contains multiple lines of text to make sure the fragmentation works correctly.\n" +
                             "Line 2: The quick brown fox jumps over the lazy dog.\n" +
                             "Line 3: RDRF - Redundant Data Recovery Format\n" +
                             "Line 4: Testing FSS strategies...\n" +
                             "Line 5: End of test file.";
        File.WriteAllText(testFile, testContent);
        byte[] originalHash = SHA256.HashData(File.ReadAllBytes(testFile));
        string originalHashHex = BitConverter.ToString(originalHash).Replace("-", "").ToLower();

        Console.WriteLine($"Test file: {testFile}");
        Console.WriteLine($"Test file size: {new FileInfo(testFile).Length} bytes");
        Console.WriteLine($"Original hash: {originalHashHex.Substring(0, 16)}...\n");

        byte[] key = SHA256.HashData(Encoding.UTF8.GetBytes("testpassword123"));

        string[] strategies = { "FSS1", "FSS2", "FSS2R", "FSS3", "FSS5", "FSS5+" };

        foreach (string strategy in strategies)
        {
            Console.WriteLine($">>> Testing {strategy} >>>");
            try
            {
                foreach (var f in Directory.GetFiles(backupDir))
                    File.Delete(f);

                var storage = new LocalFileAdapter(backupDir);
                var engine = new RDRFEngine(key, storage);

                Console.WriteLine("  Backing up...");
                string fingerprint = engine.BackupFile(testFile, strategy);
                Console.WriteLine($"  Fingerprint: {fingerprint}");

                var fragments = storage.ListFragments();
                Console.WriteLine($"  Fragments generated: {fragments.Count}");
                foreach (var f in fragments)
                {
                    Console.WriteLine($"    > {f}");
                }

                if (storage.IndexExists(fingerprint))
                    Console.WriteLine("  Index file: OK");
                else
                    Console.WriteLine("  Index file: MISSING!");

                Console.WriteLine("  Restoring...");
                string restorePath = Path.Combine(restoreDir, $"restored_{strategy}.txt");
                bool success = engine.RestoreFile(fingerprint, restorePath);

                if (success)
                {
                    Console.WriteLine("  Restore: SUCCESS");

                    if (File.Exists(restorePath))
                    {
                        byte[] restoredHash = SHA256.HashData(File.ReadAllBytes(restorePath));
                        string restoredHashHex = BitConverter.ToString(restoredHash).Replace("-", "").ToLower();
                        bool hashMatch = originalHashHex == restoredHashHex;
                        Console.WriteLine($"  Hash match: {hashMatch}");

                        if (!hashMatch)
                        {
                            Console.WriteLine($"  Original hash: {originalHashHex}");
                            Console.WriteLine($"  Restored hash: {restoredHashHex}");
                            Console.WriteLine("  Restored content:");
                            Console.WriteLine("  " + File.ReadAllText(restorePath).Replace("\n", "\n  "));
                        }
                    }
                }
                else
                {
                    Console.WriteLine("  Restore: FAILED");
                }

                Console.WriteLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  ERROR: {ex.Message}");
                Console.WriteLine($"  Stack trace: {ex.StackTrace?.Substring(0, Math.Min(300, ex.StackTrace.Length))}");
                Console.WriteLine();
            }
        }

        Console.WriteLine("=== Test Complete ===");
        Console.WriteLine($"Test directory: {testDir}");
    }
}
