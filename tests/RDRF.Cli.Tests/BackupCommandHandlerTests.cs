using System.CommandLine;
using RDRF.Cli.Commands;
using Xunit;

namespace RDRF.Cli.Tests;

public class BackupCommandHandlerTests
{
    private readonly BackupCommand _command = new();

    [Fact]
    public void Parse_MinimalArgs_Succeeds()
    {
        var root = new RootCommand();
        root.AddCommand(_command);
        var result = root.Parse("backup /tmp/test.bin /tmp/out");
        Assert.Equal(0, result.Errors.Count);
    }

    [Fact]
    public void Parse_WithAllOptions_Succeeds()
    {
        var root = new RootCommand();
        root.AddCommand(_command);
        var result = root.Parse("backup /tmp/test.bin /tmp/out -password pass -strategy FSS5 -fragment-size 2 -name mybackup -progress");
        Assert.Equal(0, result.Errors.Count);
    }

    [Fact]
    public void Parse_MissingSource_Fails()
    {
        var root = new RootCommand();
        root.AddCommand(_command);
        var result = root.Parse("backup");
        Assert.NotEqual(0, result.Errors.Count);
    }

    [Fact]
    public void Parse_InvalidStrategy_StillParses()
    {
        var root = new RootCommand();
        root.AddCommand(_command);
        var result = root.Parse("backup /tmp/s.bin /tmp/o -strategy INVALID");
        Assert.Equal(0, result.Errors.Count);
    }
}
