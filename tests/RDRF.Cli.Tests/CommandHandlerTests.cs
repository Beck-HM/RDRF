using System.CommandLine;
using RDRF.Cli.Commands;
using Xunit;

namespace RDRF.Cli.Tests;

public class RestoreCommandHandlerTests
{
    private readonly RestoreCommand _command = new();

    [Fact]
    public void Parse_MinimalArgs_Succeeds()
    {
        var root = new RootCommand();
        root.AddCommand(_command);
        var result = root.Parse("restore f.indrdrf /tmp/out");
        Assert.Equal(0, result.Errors.Count);
    }

    [Fact]
    public void Parse_WithPassword_Succeeds()
    {
        var root = new RootCommand();
        root.AddCommand(_command);
        var result = root.Parse("restore f.indrdrf /tmp/out -password pwd");
        Assert.Equal(0, result.Errors.Count);
    }

    [Fact]
    public void Parse_MissingArgs_Fails()
    {
        var root = new RootCommand();
        root.AddCommand(_command);
        var result = root.Parse("restore");
        Assert.NotEqual(0, result.Errors.Count);
    }
}

public class OtherCommandTests
{
    [Fact]
    public void InfoCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new InfoCommand();
        root.AddCommand(cmd);
        Assert.Equal(0, root.Parse("info f.indrdrf -password p").Errors.Count);
    }

    [Fact]
    public void VerifyCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new VerifyCommand();
        root.AddCommand(cmd);
        Assert.Equal(0, root.Parse("verify f.indrdrf -password p").Errors.Count);
    }

    [Fact]
    public void StatusCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new StatusCommand();
        root.AddCommand(cmd);
        Assert.Equal(0, root.Parse("status d -password p").Errors.Count);
    }

    [Fact]
    public void NextCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new NextCommand();
        root.AddCommand(cmd);
        Assert.Equal(0, root.Parse("next f.indrdrf -password p -msg test").Errors.Count);
    }

    [Fact]
    public void CheckCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new CheckCommand();
        root.AddCommand(cmd);
        Assert.Equal(0, root.Parse("check f.indrdrf -password p").Errors.Count);
    }

    [Fact]
    public void InitCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new InitCommand();
        root.AddCommand(cmd);
        Assert.Equal(0, root.Parse("init /tmp/storage").Errors.Count);
    }

    [Fact]
    public void ListCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new ListCommand();
        root.AddCommand(cmd);
        Assert.Equal(0, root.Parse("list /tmp/dir").Errors.Count);
    }

    [Fact]
    public void RemoveBackendCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new RemoveBackendCommand();
        root.AddCommand(cmd);
        Assert.Equal(0, root.Parse("remove-backend /tmp/dir -name test").Errors.Count);
    }

    [Fact]
    public void ResetCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new ResetCommand();
        root.AddCommand(cmd);
        Assert.Equal(0, root.Parse("reset /tmp/dir -name fp").Errors.Count);
    }

    [Fact]
    public void RemoteCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new RemoteCommand();
        root.AddCommand(cmd);
        Assert.Equal(0, root.Parse("remote list /tmp/dir").Errors.Count);
    }

    [Fact]
    public void PushCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new PushCommand();
        root.AddCommand(cmd);
        Assert.Equal(0, root.Parse("push /tmp/f -remote r -password p").Errors.Count);
    }

    [Fact]
    public void PullCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new PullCommand();
        root.AddCommand(cmd);
        Assert.Equal(0, root.Parse("pull /tmp -remote r -password p").Errors.Count);
    }
}
