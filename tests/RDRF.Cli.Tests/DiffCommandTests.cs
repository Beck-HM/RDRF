using System.CommandLine;
using RDRF.Cli.Commands;
using RDRF.Core.Logging;
using Xunit;

namespace RDRF.Cli.Tests;

public class DiffCommandTests
{
    private static readonly RdrfLogger _log = new();
    private readonly DiffCommand _command = new(_log);

    [Fact]
    public void Command_Name_IsDiff()
    {
        Assert.Equal("diff", _command.Name);
    }

    [Fact]
    public void Command_HasIndexFileArgument()
    {
        var arg = _command.Arguments.FirstOrDefault(a => a.Name == "indexFile");
        Assert.NotNull(arg);
    }

    [Fact]
    public void Command_HasV1AndV2Arguments()
    {
        Assert.NotNull(_command.Arguments.FirstOrDefault(a => a.Name == "v1"));
        Assert.NotNull(_command.Arguments.FirstOrDefault(a => a.Name == "v2"));
    }

    [Fact]
    public void Command_HasPasswordOption()
    {
        Assert.NotNull(_command.Options.FirstOrDefault(o => o.Name == "-password"));
    }

    [Fact]
    public void Command_HasOutputOption()
    {
        Assert.NotNull(_command.Options.FirstOrDefault(o => o.Name == "-o"));
    }

    [Fact]
    public void Parse_MinimalArgs_Succeeds()
    {
        var root = new RootCommand();
        root.Add(_command);
        var result = root.Parse("diff somefile.indrdrf 1 2");
        Assert.Equal(0, result.Errors.Count);
    }

    [Fact]
    public void Parse_WithPassword_Succeeds()
    {
        var root = new RootCommand();
        root.Add(_command);
        var result = root.Parse("diff f.indrdrf 1 2 -password mypass");
        Assert.Equal(0, result.Errors.Count);
    }

    [Fact]
    public void Parse_MissingArgs_Fails()
    {
        var root = new RootCommand();
        root.Add(_command);
        var result = root.Parse("diff f.indrdrf");
        Assert.NotEqual(0, result.Errors.Count);
    }
}
