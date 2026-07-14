using RDRF.Core.DSAA;
using RDRF.Core.PasswordManager;
using Spectre.Console;
using System.CommandLine;

namespace RDRF.Cli.Commands;

public class ListCommand : Command
{
    public ListCommand(PasswordManager? passwordManager = null) : base("list", "List configured backends or registered projects")
    {
        var nodeOpt = new Option<bool>("-node") { Description = "List all configured storage backends" };
        var fpOpt = new Option<bool>("-fp") { Description = "List all stored FastPasswords" };
        Add(nodeOpt);
        Add(fpOpt);

        SetAction((ParseResult parseResult) =>
        {
            bool node = parseResult.GetValue(nodeOpt);
            bool fp = parseResult.GetValue(fpOpt);

            if (fp)
            {
                var mgr = passwordManager ?? new PasswordManager();
                mgr.Initialize();
                var keys = mgr.ListKeys();
                if (keys.Length == 0)
                {
                    AnsiConsole.MarkupLine("[yellow]No FastPasswords stored. Use 'rdrf fp set <key>' to add one.[/]");
                    return 0;
                }
                var table = new Table();
                table.Border(TableBorder.Rounded);
                table.AddColumn("Key");
                table.AddColumn("Backups");
                table.AddColumn("Created");
                foreach (var k in keys)
                {
                    var detail = mgr.GetKeyDetail(k);
                    string created = detail.Length > 0
                        ? DateTimeOffset.FromUnixTimeSeconds(detail[0].CreatedAt).LocalDateTime.ToString("yyyy-MM-dd HH:mm")
                        : "-";
                    table.AddRow(k, detail.Length.ToString(), created);
                }
                AnsiConsole.Write(new Panel(table).Header($"FastPasswords ({keys.Length})").BorderColor(Color.Grey));
                return 0;
            }

            if (!node)
            {
                AnsiConsole.MarkupLine("[red]Error: -node or -fp is required[/]");
                return 1;
            }

            var backends = ConfigManager.Load();
            if (backends.Count == 0)
            {
                AnsiConsole.MarkupLine("[yellow]No backends configured. Use 'rdrf init -rest/-key/-path' to add one.[/]");
                return 0;
            }

            var table2 = new Table();
            table2.Border(TableBorder.Rounded);
            table2.AddColumn("Name");
            table2.AddColumn("Type");
            table2.AddColumn("Info");

            foreach (var b in backends)
            {
                string info = b.Type switch
                {
                    "rest" => $"api_url: {b.Parameters.GetValueOrDefault("api_url", "-")}",
                    "key" => $"endpoint: {b.Parameters.GetValueOrDefault("endpoint", "-")}, bucket: {b.Parameters.GetValueOrDefault("bucket", "-")}",
                    "path" => $"base_path: {b.Parameters.GetValueOrDefault("base_path", "-")}",
                    _ => b.Type,
                };
                table2.AddRow(b.Name, b.Type, info);
            }

            AnsiConsole.Write(new Panel(table2).Header($"Configured backends ({backends.Count})").BorderColor(Color.Grey));
            return 0;
        });
    }
}







