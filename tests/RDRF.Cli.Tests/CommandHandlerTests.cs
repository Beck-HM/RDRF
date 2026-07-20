using System.CommandLine;
using RDRF.Cli.Commands;
using RDRF.Core.Logging;
using RDRF.Core.PasswordManager;
using Xunit;

namespace RDRF.Cli.Tests;

public class RestoreCommandHandlerTests
{
    private static readonly PasswordManager _pm = new();
    private static readonly RdrfLogger _log = new();
    private readonly RestoreCommand _command = new(_pm, _log);

    [Fact]
    public void Command_CanBeInstantiated()
    {
        Assert.Equal("res", _command.Name);
        Assert.Single(_command.Arguments);
    }

    [Fact]
    public void Parse_MissingArgs_Fails()
    {
        var root = new RootCommand();
        root.Add(_command);
        var result = root.Parse("restore");
        Assert.NotEmpty(result.Errors);
    }
}

public class OtherCommandTests
{
    [Fact]
    public void InfoCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new InfoCommand();
        root.Add(cmd);
        Assert.Equal(0, root.Parse("info f.indrdrf -password p").Errors.Count);
    }

    [Fact]
    public void VerifyCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new VerifyCommand();
        root.Add(cmd);
        Assert.Equal(0, root.Parse("verify f.indrdrf -password p").Errors.Count);
    }

    [Fact]
    public void StatusCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new StatusCommand();
        root.Add(cmd);
        Assert.Equal(0, root.Parse("status d -password p").Errors.Count);
    }

    [Fact]
    public void NextCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new NextCommand();
        root.Add(cmd);
        Assert.Equal(0, root.Parse("next f -m test -password p").Errors.Count);
    }

    [Fact]
    public void CheckCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new CheckCommand();
        root.Add(cmd);
        Assert.Equal(0, root.Parse("check f.indrdrf -password p").Errors.Count);
    }

    [Fact]
    public void InitCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new InitCommand();
        root.Add(cmd);
        Assert.Equal(0, root.Parse("init -path \"name:nas & base_path:/tmp/storage\"").Errors.Count);
    }

    [Fact]
    public void ListCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new ListCommand();
        root.Add(cmd);
        Assert.Equal(0, root.Parse("list -node").Errors.Count);
    }

    [Fact]
    public void RemoveBackendCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new RemoveBackendCommand();
        root.Add(cmd);
        Assert.Equal(0, root.Parse("remove /tmp/dir -node -name test").Errors.Count);
    }

    [Fact]
    public void ResetCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new ResetCommand();
        root.Add(cmd);
        Assert.Equal(0, root.Parse("reset /tmp/dir -name fp").Errors.Count);
    }

    [Fact]
    public void RemoteCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new RemoteCommand();
        root.Add(cmd);
        Assert.Equal(0, root.Parse("remote /tmp/f -add backend1").Errors.Count);
    }

    [Fact]
    public void PushCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new PushCommand();
        root.Add(cmd);
        Assert.Equal(0, root.Parse("push /tmp/f -password p").Errors.Count);
    }

    [Fact]
    public void PullCommand_Parse_Succeeds()
    {
        var root = new RootCommand(); var cmd = new PullCommand();
        root.Add(cmd);
        Assert.Equal(0, root.Parse("pull /tmp/f -password p").Errors.Count);
    }
}
