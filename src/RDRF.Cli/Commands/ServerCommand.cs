using RDRF.Server;
using Spectre.Console;
using System.CommandLine;

namespace RDRF.Cli.Commands;

public class ServerCommand : Command
{
    public ServerCommand() : base("server", "Start RDRF native TCP storage server")
    {
        var portOpt = new Option<int>("--port") { Description = "Listening port (required)" };
        var pathOpt = new Option<DirectoryInfo>("--path") { Description = "Fragment storage directory (required)" };
        var limitOpt = new Option<int>("--limit") { Description = "Max concurrent connections (default: 1000)" };
        var partTimeoutOpt = new Option<int>("--part-timeout") { Description = "Part file cleanup timeout in hours (default: 24)" };
        var daemonOpt = new Option<bool>("--daemon") { Description = "Run in background" };

        Options.Add(portOpt);
        Options.Add(pathOpt);
        Options.Add(limitOpt);
        Options.Add(partTimeoutOpt);
        Options.Add(daemonOpt);

        this.SetAction(async (ParseResult parseResult) =>
        {
            int port = parseResult.GetValue(portOpt);
            var path = parseResult.GetValue(pathOpt);
            int limit = Math.Max(1, parseResult.GetValue(limitOpt));
            int partTimeout = Math.Max(1, parseResult.GetValue(partTimeoutOpt));
            bool daemon = parseResult.GetValue(daemonOpt);

            if (port == 0) { AnsiConsole.MarkupLine("[red]Error: --port is required[/]"); return 1; }
            if (path == null || !path.Exists) { AnsiConsole.MarkupLine("[red]Error: --path directory must exist[/]"); return 1; }

            string storagePath = path.FullName;

            if (daemon)
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = Environment.ProcessPath!,
                    Arguments = $"server --port {port} --path \"{storagePath}\" --limit {limit} --part-timeout {partTimeout}",
                    UseShellExecute = false, CreateNoWindow = true
                };
                System.Diagnostics.Process.Start(psi);
                AnsiConsole.MarkupLine($"[green]Server started as daemon on port {port}.[/]");
                return 0;
            }

            var serverArgs = new[] { "--port", port.ToString(), "--path", storagePath, "--limit", limit.ToString(), "--part-timeout", partTimeout.ToString() };
            return await RDRF.Server.Program.Main(serverArgs);
        });
    }
}
