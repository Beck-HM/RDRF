using RDRF.Cli.Commands;
using System.CommandLine;
using System.Globalization;

class Program
{
    static async Task<int> Main(string[] args)
    {
        // Force English for all built-in System.CommandLine text
        CultureInfo.DefaultThreadCurrentUICulture = new CultureInfo("en-US");

        var root = new RootCommand("RDRF - Resilient Distributed Replication Format");
        root.Subcommands.Add(new BackupCommand());
        root.Subcommands.Add(new RestoreCommand());
        root.Subcommands.Add(new InfoCommand());
        root.Subcommands.Add(new VerifyCommand());
        root.Subcommands.Add(new StatusCommand());
        root.Subcommands.Add(new NextCommand());
        root.Subcommands.Add(new CheckCommand());
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
