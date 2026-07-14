using System.CommandLine;
using RDRF.Cli.Commands;
using RDRF.Core.Logging;
using Xunit;

namespace RDRF.Cli.Tests;

public class ReachCommandTests
{
    private readonly ReachCommand _command = new(new RdrfLogger());

    [Fact]
    public void Command_Name_IsReach()
    {
        Assert.Equal("reach", _command.Name);
    }

    [Fact]
    public void Command_HasPathArgument()
    {
        Assert.NotNull(_command.Arguments.FirstOrDefault(a => a.Name == "path"));
    }

    [Fact]
    public void Command_HasOutputOption()
    {
        Assert.NotNull(_command.Options.FirstOrDefault(o => o.Name == "o"));
    }
}
