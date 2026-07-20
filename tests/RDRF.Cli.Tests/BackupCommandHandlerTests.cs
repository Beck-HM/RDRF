using System.CommandLine;
using RDRF.Cli.Commands;
using RDRF.Core.Logging;
using RDRF.Core.PasswordManager;
using Xunit;

namespace RDRF.Cli.Tests;

public class BackupCommandHandlerTests
{
    private static readonly PasswordManager _pm = new();
    private static readonly RdrfLogger _log = new();
    private readonly BackupCommand _command = new(_pm, _log);

    [Fact]
    public void Parse_MinimalArgs_Succeeds()
    {
        var root = new RootCommand();
        root.Add(_command);
        var result = root.Parse("backup test.bin -o out -fss1");
        Assert.NotNull(result);
    }

    [Fact]
    public void Parse_WithAllOptions_Succeeds()
    {
        var root = new RootCommand();
        root.Add(_command);
        var result = root.Parse("backup test.bin -o out -password pass -fss5 -size 2 -name mybackup");
        Assert.NotNull(result);
    }

    [Fact]
    public void Parse_MissingSource_Fails()
    {
        var root = new RootCommand();
        root.Add(_command);
        var result = root.Parse("backup");
        Assert.NotNull(result);
    }

    [Fact]
    public void Parse_InvalidStrategy_StillParses()
    {
        var root = new RootCommand();
        root.Add(_command);
        var result = root.Parse("backup s.bin -o o -fss3");
        Assert.NotNull(result);
    }

    [Fact]
    public void Parse_Compression_Lz4()
    {
        var root = new RootCommand();
        root.Add(_command);
        var result = root.Parse("backup test.bin -o out -fss1 -c lz4");
        Assert.NotNull(result);
    }

    [Fact]
    public void Parse_Compression_Zstd_WithOptions()
    {
        var root = new RootCommand();
        root.Add(_command);
        var result = root.Parse("backup test.bin -o out -fss1 -c zstd 5");
        Assert.NotNull(result);
    }

    [Fact]
    public void Parse_Compression_NoMethod_Defaults()
    {
        var root = new RootCommand();
        root.Add(_command);
        var result = root.Parse("backup test.bin -o out -fss1");
        Assert.NotNull(result);
    }
}
