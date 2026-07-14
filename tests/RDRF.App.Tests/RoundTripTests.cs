using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.DSAA;
using Xunit;

namespace RDRF.App.Tests;

public class RoundTripTests
{
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

    [Theory]
    [MemberData(nameof(AllStrategies))]
    public void RoundTrip_SmallFile_ContentMatches(string strategy)
    {
        using var dir = new Fixtures.TempDir();
        byte[] password = RandomNumberGenerator.GetBytes(32);
        string input = dir.CreateTextFile("test.txt", $"Round-trip test for {strategy}.");
        string fp = Fixtures.BackupHelpers.Backup(password, input, dir.Path, strategy);
        string output = dir["restored.bin"];

        bool ok = Fixtures.BackupHelpers.Restore(password, dir.Path, fp, output);
        Assert.True(ok);
        Assert.Equal(
            File.ReadAllBytes(input),
            File.ReadAllBytes(output));
    }

    [Theory]
    [InlineData("FSS1", 2_000_000)]
    [InlineData("FSS3", 2_500_000)]  // triggers variable-size fragments
    [InlineData("FSS5", 3_000_000)]
    public void RoundTrip_LargeFile_ContentMatches(string strategy, int fileSize)
    {
        using var dir = new Fixtures.TempDir();
        byte[] password = RandomNumberGenerator.GetBytes(32);
        string input = dir.CreateFile("large.bin", fileSize);
        string fp = Fixtures.BackupHelpers.Backup(password, input, dir.Path, strategy, fragmentSize: 1_000_000);
        string output = dir["restored.bin"];

        bool ok = Fixtures.BackupHelpers.Restore(password, dir.Path, fp, output);
        Assert.True(ok);
        byte[] original = File.ReadAllBytes(input);
        byte[] restored = File.ReadAllBytes(output);
        Assert.Equal(original.Length, restored.Length);
        Assert.Equal(original, restored);
    }

    [Fact]
    public void SaltBasedOrchestrator_RoundTrip_ContentMatches()
    {
        using var dir = new Fixtures.TempDir();
        byte[] password = RandomNumberGenerator.GetBytes(32);
        byte[] salt = RandomNumberGenerator.GetBytes(32);
        string input = dir.CreateTextFile("test.txt", "Salt-based round-trip test.");
        string fp = Fixtures.BackupHelpers.BackupWithSalt(password, salt, input, dir.Path, "FSS1");
        string output = dir["restored.bin"];

        bool ok = Fixtures.BackupHelpers.Restore(password, dir.Path, fp, output);
        Assert.True(ok);
        Assert.Equal(File.ReadAllBytes(input), File.ReadAllBytes(output));
    }

    [Fact]
    public void PreDerivedEngine_RoundTrip_ContentMatches()
    {
        using var dir = new Fixtures.TempDir();
        byte[] password = RandomNumberGenerator.GetBytes(32);
        byte[] aesKey = EncryptionLayer.DeriveKeyLegacy(password);
        var storage = new LocalDSAAAdapter(dir.Path);

        using var engine = new RDRFEngine(aesKey, password, storage);
        string input = dir.CreateTextFile("test.txt", "Pre-derived round-trip test.");
        string fp = engine.BackupFile(input, "FSS1");

        using var restoreEngine = new RDRFEngine(aesKey, password, storage);
        string output = dir["restored.bin"];
        bool ok = restoreEngine.RestoreFile(fp, output);
        Assert.True(ok);
        Assert.Equal(File.ReadAllBytes(input), File.ReadAllBytes(output));
    }
}
