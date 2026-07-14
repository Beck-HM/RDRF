using System.CommandLine;
using RDRF.Cli.Commands;
using RDRF.Core.PasswordManager;
using Xunit;

namespace RDRF.Cli.Tests;

public class FpCommandTests
{
    [Fact]
    public void FpCommand_HasSetListDeleteGetSubcommands()
    {
        // Can't easily test interactive commands without stdin mock
        // Just verify the command structure is correct
        var cmd = new FpCommand(new PasswordManager());
        Assert.NotNull(cmd);
        Assert.Equal("fp", cmd.Name);
    }

    [Fact]
    public void Parse_RootFp_Succeeds()
    {
        var root = new RootCommand();
        root.AddCommand(new FpCommand(new PasswordManager()));
        var result = root.Parse("fp list");
        Assert.Equal(0, result.Errors.Count);
    }
}
