using RDRF.Cli.Commands;
using System.CommandLine;

class Program
{
    static async Task<int> Main(string[] args)
    {
        var root = new RootCommand("RDRF - Resilient Distributed Replication Format");
        root.Subcommands.Add(new BackupCommand());
        root.Subcommands.Add(new RestoreCommand());
        var parseResult = root.Parse(args);
        return await parseResult.InvokeAsync();
    }
}
