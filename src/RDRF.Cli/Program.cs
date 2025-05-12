using RDRF.Cli.Commands;
using System.CommandLine;

class Program
{
    static async Task<int> Main(string[] args)
    {
        var root = new RootCommand("RDRF - Resilient Distributed Replication Format");
        root.Subcommands.Add(new BackupCommand());
        root.Subcommands.Add(new RestoreCommand());
        root.Subcommands.Add(new InfoCommand());
        root.Subcommands.Add(new VerifyCommand());
        var parseResult = root.Parse(args);
        return await parseResult.InvokeAsync();
    }
}
