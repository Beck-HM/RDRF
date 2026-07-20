using RDRF.Cli.Commands;
using RDRF.Core.Logging;
using RDRF.Core.PasswordManager;
using Xunit;

namespace RDRF.Cli.Tests;

public class BackupCommandTests
{
    private static readonly PasswordManager _pm = new();
    private static readonly RdrfLogger _log = new();

    [Fact]
    public void Command_CanBeInstantiated()
    {
        var cmd = new BackupCommand(_pm, _log);
        Assert.NotNull(cmd);
        Assert.Equal("backup", cmd.Name);
    }

    [Fact]
    public void Command_HasRequiredArguments()
    {
        var cmd = new BackupCommand(_pm, _log);
        Assert.Contains(cmd.Arguments, a => a.Name == "source");
    }

    [Fact]
    public void Parse_BasicArgs_Succeeds()
    {
        var cmd = new BackupCommand(_pm, _log);
        var root = new System.CommandLine.RootCommand();
        root.Add(cmd);
        var result = root.Parse("backup myfile.txt -fss6.1");
        Assert.NotNull(result);
    }

    [Fact]
    public void Parse_WithPassword_Succeeds()
    {
        var cmd = new BackupCommand(_pm, _log);
        var root = new System.CommandLine.RootCommand();
        root.Add(cmd);
        var result = root.Parse("backup test.txt -fss6.1 -password mypass");
        Assert.NotNull(result);
    }
}
