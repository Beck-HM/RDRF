using RDRF.Core.Logging;
using RDRF.Core.PasswordManager;
using Xunit;

namespace RDRF.Cli.Tests;

public class CommandsTest
{
    private static readonly PasswordManager _pm = new();
    private static readonly RdrfLogger _log = new();

    private static System.CommandLine.Command CreateCommand(Type commandType)
    {
        if (commandType == typeof(Commands.BackupCommand))
            return new Commands.BackupCommand(_pm, _log);
        if (commandType == typeof(Commands.RestoreCommand))
            return new Commands.RestoreCommand(_pm, _log);
        if (commandType == typeof(Commands.DiffCommand))
            return new Commands.DiffCommand(_log);
        if (commandType == typeof(Commands.ListCommand))
            return new Commands.ListCommand(_pm);
        return (System.CommandLine.Command)Activator.CreateInstance(commandType)!;
    }

    [Theory]
    [InlineData("backup", typeof(Commands.BackupCommand))]
    [InlineData("res", typeof(Commands.RestoreCommand))]
    [InlineData("info", typeof(Commands.InfoCommand))]
    [InlineData("verify", typeof(Commands.VerifyCommand))]
    [InlineData("status", typeof(Commands.StatusCommand))]
    [InlineData("next", typeof(Commands.NextCommand))]
    [InlineData("check", typeof(Commands.CheckCommand))]
    [InlineData("diff", typeof(Commands.DiffCommand))]
    [InlineData("init", typeof(Commands.InitCommand))]
    [InlineData("list", typeof(Commands.ListCommand))]
    [InlineData("remove", typeof(Commands.RemoveBackendCommand))]
    [InlineData("reset", typeof(Commands.ResetCommand))]
    [InlineData("remote", typeof(Commands.RemoteCommand))]
    [InlineData("push", typeof(Commands.PushCommand))]
    [InlineData("pull", typeof(Commands.PullCommand))]
    public void Command_CanBeInstantiated(string expectedName, Type commandType)
    {
        var cmd = CreateCommand(commandType);
        Assert.NotNull(cmd);
        Assert.Equal(expectedName, cmd.Name);
    }

    [Theory]
    [InlineData(typeof(Commands.BackupCommand), "source")]
    [InlineData(typeof(Commands.RestoreCommand), "indexFile")]
    [InlineData(typeof(Commands.InfoCommand), "indexFile")]
    [InlineData(typeof(Commands.VerifyCommand), "indexFile")]
    [InlineData(typeof(Commands.StatusCommand), "indexFile")]
    [InlineData(typeof(Commands.DiffCommand), "indexFile")]
    [InlineData(typeof(Commands.CheckCommand), "indexFile")]
    [InlineData(typeof(Commands.RemoteCommand), "indexFile")]
    [InlineData(typeof(Commands.PushCommand), "indexFile")]
    [InlineData(typeof(Commands.PullCommand), "indexFile")]
    public void Command_HasRequiredArguments(Type commandType, string argName)
    {
        var cmd = CreateCommand(commandType);
        Assert.Contains(cmd.Arguments, a => a.Name == argName);
    }

    [Theory]
    [InlineData(typeof(Commands.BackupCommand), "backup file.txt -fss6.1", true)]
    [InlineData(typeof(Commands.BackupCommand), "backup -fss6.1", false)]
    [InlineData(typeof(Commands.BackupCommand), "backup", false)]
    [InlineData(typeof(Commands.RestoreCommand), "res index.indrdrf -o out.rdrf", true)]
    [InlineData(typeof(Commands.RestoreCommand), "res -o out.rdrf", false)]
    [InlineData(typeof(Commands.InfoCommand), "info index.indrdrf", true)]
    [InlineData(typeof(Commands.InfoCommand), "info", false)]
    [InlineData(typeof(Commands.VerifyCommand), "verify index.indrdrf", true)]
    [InlineData(typeof(Commands.VerifyCommand), "verify", false)]
    [InlineData(typeof(Commands.StatusCommand), "status index.indrdrf", true)]
    [InlineData(typeof(Commands.StatusCommand), "status", false)]
    [InlineData(typeof(Commands.NextCommand), "next", false)]
    [InlineData(typeof(Commands.CheckCommand), "check index.indrdrf", true)]
    [InlineData(typeof(Commands.CheckCommand), "check", false)]
    [InlineData(typeof(Commands.DiffCommand), "diff index.indrdrf 1 2", true)]
    [InlineData(typeof(Commands.DiffCommand), "diff", false)]
    [InlineData(typeof(Commands.DiffCommand), "diff index.indrdrf 1", false)]
    [InlineData(typeof(Commands.ListCommand), "list -node", true)]
    [InlineData(typeof(Commands.RemoteCommand), "remote index.indrdrf -add backend1", true)]
    [InlineData(typeof(Commands.RemoteCommand), "remote", false)]
    [InlineData(typeof(Commands.PushCommand), "push index.indrdrf", true)]
    [InlineData(typeof(Commands.PushCommand), "push", false)]
    [InlineData(typeof(Commands.PullCommand), "pull index.indrdrf", true)]
    [InlineData(typeof(Commands.PullCommand), "pull", false)]
    public void Parse_Command(Type commandType, string args, bool expectSuccess)
    {
        var cmd = CreateCommand(commandType);
        var root = new System.CommandLine.RootCommand();
        root.Add(cmd);
        var result = root.Parse(args);
        if (expectSuccess)
            Assert.Empty(result.Errors);
        else
            Assert.NotEmpty(result.Errors);
    }
}
