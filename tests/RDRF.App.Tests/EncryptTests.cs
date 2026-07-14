using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.DSAA;
using Xunit;

namespace RDRF.App.Tests;

public class EncryptTests
{
    [Theory]
    [InlineData("FSS1")]
    [InlineData("FSS2")]
    [InlineData("FSS2R")]
    [InlineData("FSS3")]
    [InlineData("FSS5")]
    [InlineData("FSS5+")]
    [InlineData("FSS6")]
    public void AllStrategies_BackupSucceeds(string strategy)
    {
        using var dir = new Fixtures.TempDir();
        byte[] password = RandomNumberGenerator.GetBytes(32);
        string input = dir.CreateTextFile("test.txt", $"{strategy} backup test.");
        string fp = Fixtures.BackupHelpers.Backup(password, input, dir.Path, strategy);
        Assert.False(string.IsNullOrEmpty(fp));
    }

    [Fact]
    public void FSS3_WithVariableFragments_Succeeds()
    {
        using var dir = new Fixtures.TempDir();
        byte[] password = RandomNumberGenerator.GetBytes(32);
        string input = dir.CreateFile("large.bin", 2_500_000); // 2.5MB -> 3 frags (last smaller)
        string fp = Fixtures.BackupHelpers.Backup(password, input, dir.Path, "FSS3", fragmentSize: 1_000_000);
        Assert.False(string.IsNullOrEmpty(fp));
    }

    [Theory]
    [InlineData(512 * 1024)]
    [InlineData(1_000_000)]
    [InlineData(2_000_000)]
    public void DifferentFragmentSizes_BackupSucceeds(int fragSize)
    {
        using var dir = new Fixtures.TempDir();
        byte[] password = RandomNumberGenerator.GetBytes(32);
        string input = dir.CreateFile("test.bin", 5_000_000);
        string fp = Fixtures.BackupHelpers.Backup(password, input, dir.Path, "FSS1", fragSize);
        Assert.False(string.IsNullOrEmpty(fp));

        var result = Fixtures.BackupHelpers.LoadIndex(password, dir.Path, fp);
        Assert.True(result.FragmentCount > 0);
    }

    [Fact]
    public void CustomName_BackupSucceeds()
    {
        using var dir = new Fixtures.TempDir();
        byte[] password = RandomNumberGenerator.GetBytes(32);
        string input = dir.CreateTextFile("test.txt", "Custom name test.");
        var storage = new LocalDSAAAdapter(dir.Path);
        using var engine = new RDRFEngine(password, storage);
        string fp = engine.BackupFile(input, "FSS1", customName: "my_custom_name");

        Assert.False(string.IsNullOrEmpty(fp));
        // When custom name is set, index is stored as custom_name.indrdrf, not fingerprint.indrdrf
        Assert.True(storage.IndexExists("my_custom_name"), "Index should exist under custom name");
        var result = Fixtures.BackupHelpers.LoadIndex(password, dir.Path, "my_custom_name");
    }

    [Fact]
    public void FsaMode_FSS3PlusFSS6_BackupSucceeds()
    {
        using var dir = new Fixtures.TempDir();
        byte[] password = RandomNumberGenerator.GetBytes(32);
        string input = dir.CreateFile("test.bin", 1_000_000);
        var storage = new LocalDSAAAdapter(dir.Path);
        using var engine = new RDRFEngine(password, storage);
        string fp = engine.BackupFile(input, "FSS3",
            auxiliaryStrategies: new List<string> { "FSS6" });

        Assert.False(string.IsNullOrEmpty(fp));
        var result = Fixtures.BackupHelpers.LoadIndex(password, dir.Path, fp);
        Assert.Contains("FSS3", result.StrategyDisplay);
    }

    [Fact]
    public void PureFSS3_NoAux_StrategyShowsFSS3Only()
    {
        using var dir = new Fixtures.TempDir();
        byte[] password = RandomNumberGenerator.GetBytes(32);
        string input = dir.CreateFile("test.bin", 500_000);
        string fp = Fixtures.BackupHelpers.Backup(password, input, dir.Path, "FSS3");
        var result = Fixtures.BackupHelpers.LoadIndex(password, dir.Path, fp);
        Assert.Equal("FSS3", result.StrategyDisplay);
        Assert.DoesNotContain("+", result.StrategyDisplay);
    }
}
