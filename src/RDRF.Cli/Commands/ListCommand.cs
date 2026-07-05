using RDRF.Core.Dssa;
using Spectre.Console;
using System.CommandLine;

namespace RDRF.Cli.Commands;

/// <summary>
/// List configured backends or registered projects. CLI: rdrf list.
/// </summary>

public class ListCommand : Command
{
    public ListCommand() : base("list", "List configured backends or registered projects")
    {
        var nodeOpt = new Option<bool>("-node") { Description = "List all configured storage backends" };
        Add(nodeOpt);

        SetAction((ParseResult parseResult) =>
        {
            bool node = parseResult.GetValue(nodeOpt);
            if (!node)
            {
                AnsiConsole.MarkupLine("[red]Error: -node is required[/]");
                return 1;
            }

            var backends = ConfigManager.Load();
            if (backends.Count == 0)
            {
                AnsiConsole.MarkupLine("[yellow]No backends configured. Use 'rdrf init -rest/-key/-path' to add one.[/]");
                return 0;
            }

            var table = new Table();
            table.Border(TableBorder.Rounded);
            table.AddColumn("Name");
            table.AddColumn("Type");
            table.AddColumn("Info");

            foreach (var b in backends)
            {
                string info = b.Type switch
                {
                    "rest" => $"api_url: {b.Parameters.GetValueOrDefault("api_url", "-")}",
                    "key" => $"endpoint: {b.Parameters.GetValueOrDefault("endpoint", "-")}, bucket: {b.Parameters.GetValueOrDefault("bucket", "-")}",
                    "path" => $"base_path: {b.Parameters.GetValueOrDefault("base_path", "-")}",
                    _ => b.Type,
                };
                table.AddRow(b.Name, b.Type, info);
            }

            AnsiConsole.Write(new Panel(table).Header($"Configured backends ({backends.Count})").BorderColor(Color.Grey));
            return 0;
        });
    }
}







