using System.Net;
using System.Net.Sockets;

namespace RDRF.Server;

public static class ProgramCompatibility
{
    public static Task<int> StartAsync(string[] args) => Program.Main(args);
}

public class Program
{
    public static async Task<int> Main(string[] args)
    {
        int port = 0;
        string path = "";
        int limit = 1000;
        double partTimeout = 24;
        bool daemon = false;

        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            string? Next() => i + 1 < args.Length ? args[++i] : null;
            switch (a)
            {
                case "--port": int.TryParse(Next(), out port); break;
                case "--path": path = Next() ?? ""; break;
                case "--limit": int.TryParse(Next(), out limit); break;
                case "--part-timeout": double.TryParse(Next(), out partTimeout); break;
                case "--daemon": daemon = true; break;
                case "-h": case "--help": ShowHelp(); return 0;
            }
        }

        if (port == 0) { Console.Error.WriteLine("Error: --port required."); return 1; }
        if (string.IsNullOrEmpty(path)) { Console.Error.WriteLine("Error: --path required."); return 1; }

        path = Path.GetFullPath(path);
        Directory.CreateDirectory(path);
        FragmentStore.StoragePath = path;

        if (daemon) Console.WriteLine($"Daemon mode — storage: {path}");

        using var cts = new CancellationTokenSource();
        var listener = new TcpListener(IPAddress.Any, port);
        listener.Start(limit);

        Console.WriteLine($"RDRF server listening on 0.0.0.0:{port}");
        Console.WriteLine($"Storage: {path}  Limit: {limit}  PartTimeout: {partTimeout}h");

        _ = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromHours(1), cts.Token);
                FragmentStore.CleanupParts(partTimeout);
            }
        });

        try
        {
            while (!cts.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(cts.Token).ConfigureAwait(false);
                _ = Task.Run(async () =>
                {
                    try
                    {
                        using (client)
                        using (var stream = client.GetStream())
                            await ProtocolHandler.HandleAsync(stream, cts.Token).ConfigureAwait(false);
                    }
                    catch (Exception ex) { Console.Error.WriteLine($"Connection error: {ex.Message}"); }
                });
            }
        }
        catch (OperationCanceledException) { }
        finally { listener.Stop(); }

        return 0;
    }

    static void ShowHelp()
    {
        Console.WriteLine("""
            rdrf server — RDRF native TCP storage server

            Options:
              --port <n>            Listening port (required)
              --path <dir>          Fragment storage directory (required)
              --limit <n>           Max concurrent connections (default: 1000)
              --part-timeout <h>    Part file cleanup timeout in hours (default: 24)
              --daemon              Run in background
            """);
    }
}
