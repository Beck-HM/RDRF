using RDRF.Cli.Commands;
using System.CommandLine;
using System.Globalization;

/// <summary>
/// Entry point. Parses args with System.CommandLine and dispatches to subcommands.
/// </summary>
class Program
{
    static async Task<int> Main(string[] args)
    {
        // Force English for all built-in System.CommandLine text
        CultureInfo.DefaultThreadCurrentUICulture = new CultureInfo("en-US");

        var root = new RootCommand("RDRF - Redundant Distributed Recovery File");
        root.Subcommands.Add(new BackupCommand());
        root.Subcommands.Add(new RestoreCommand());
        root.Subcommands.Add(new InfoCommand());
        root.Subcommands.Add(new VerifyCommand());
        root.Subcommands.Add(new StatusCommand());
        root.Subcommands.Add(new NextCommand());
        root.Subcommands.Add(new CheckCommand());
        root.Subcommands.Add(new DiffCommand());
        root.Subcommands.Add(new InitCommand());
        root.Subcommands.Add(new ListCommand());
        root.Subcommands.Add(new RemoveBackendCommand());
        root.Subcommands.Add(new ResetCommand());
        root.Subcommands.Add(new RemoteCommand());
        root.Subcommands.Add(new PushCommand());
        root.Subcommands.Add(new PullCommand());
        var parseResult = root.Parse(args);
        return await parseResult.InvokeAsync();
    }
}






