using RDRF.Core.Configuration;
using Spectre.Console;
using System.CommandLine;

namespace RDRF.Cli.Commands;

public class ConfigCommand : Command
{
    public ConfigCommand() : base("config", "Manage RDRF configuration")
    {
        var moveCmd = new Command("move", "Move .rdrf directory to a new location")
        {
            new Argument<string>("path") { Description = "New path for .rdrf directory" },
        };
        moveCmd.SetAction((ParseResult parseResult) =>
        {
            string path = parseResult.GetValue<string>("path");
            string fullPath = Path.GetFullPath(path);
            RdrfConfig.MoveTo(fullPath);
            AnsiConsole.MarkupLine($"[green].rdrf directory moved to:[/] {fullPath}");
            AnsiConsole.MarkupLine("[green]All future logs and passwords will use the new location.[/]");
            return 0;
        });

        var showCmd = new Command("show", "Show current configuration");
        showCmd.SetAction((ParseResult parseResult) =>
        {
            var table = new Table();
            table.Border(TableBorder.Rounded);
            table.AddColumn("Key");
            table.AddColumn("Value");
            table.AddRow(".rdrf directory", RdrfConfig.RootDir);
            table.AddRow("Log directory", RdrfConfig.LogDir);
            table.AddRow("Log level", GlobalConfig.LogLevel);
            table.AddRow("Auto FP", GlobalConfig.AutoFp.ToString());
            table.AddRow("Default storage", string.IsNullOrEmpty(GlobalConfig.DefaultStorage) ? "(not set)" : GlobalConfig.DefaultStorage);
            AnsiConsole.Write(table);
            return 0;
        });

        var setCmd = new Command("set", "Set a global configuration value")
        {
            new Argument<string>("key") { Description = "Configuration key (log-level, auto-fp, default-storage)" },
            new Argument<string>("value") { Description = "Configuration value" },
        };
        setCmd.SetAction((ParseResult parseResult) =>
        {
            string key = parseResult.GetValue<string>("key");
            string value = parseResult.GetValue<string>("value");
            switch (key.ToLowerInvariant())
            {
                case "log-level":
                    GlobalConfig.LogLevel = value;
                    break;
                case "auto-fp":
                    if (!bool.TryParse(value, out bool autoFp))
                    { AnsiConsole.MarkupLine("[red]Invalid boolean value. Use 'true' or 'false'.[/]"); return 1; }
                    GlobalConfig.AutoFp = autoFp;
                    break;
                case "default-storage":
                    GlobalConfig.DefaultStorage = value;
                    break;
                default:
                    AnsiConsole.MarkupLine($"[red]Unknown key: {key}. Valid keys: log-level, auto-fp, default-storage[/]");
                    return 1;
            }
            GlobalConfig.Save();
            AnsiConsole.MarkupLine($"[green]'{key}' set to '{value}'[/]");
            return 0;
        });

        Add(moveCmd);
        Add(showCmd);
        Add(setCmd);
    }
}
