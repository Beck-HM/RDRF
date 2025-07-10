using RDRF.Core.Versioning;
using RDRF.Cli.Services;
using Spectre.Console;
using System.CommandLine;
using System.Text;

namespace RDRF.Cli.Commands;

public class CheckCommand : Command
{
    public CheckCommand() : base("check", "Show version history with file tree and diffs")
    {
        var indexArg = new Argument<FileInfo>("indexFile") { Description = "Path to the .indrdrf index file" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password as plain text (INSECURE: visible in process list; omit for secure prompt)" };

        Arguments.Add(indexArg);
        Options.Add(passwordOpt);

        SetAction((ParseResult parseResult) =>
        {
            var indexFile = parseResult.GetValue(indexArg);
            var pwd = parseResult.GetValue(passwordOpt);

            if (!indexFile.Exists)
            {
                Console.Error.WriteLine($"Error: index file not found: {indexFile.FullName}");
                return 1;
            }

            byte[] password = pwd != null ? Encoding.UTF8.GetBytes(pwd) : PasswordProvider.ReadInteractive();
            if (password.Length == 0)
            {
                Console.Error.WriteLine("Error: password cannot be empty");
                return 1;
            }

            var records = VersionedRestore.GetVersionHistory(indexFile.FullName, password);
            if (records.Count == 0)
            {
                Console.Error.WriteLine("Error: no version history found (wrong password or non-versioned backup)");
                return 1;
            }

            bool interactive = !Console.IsInputRedirected;
            RenderTable(records);
            if (!interactive) return 0;

            while (true)
            {
                int maxV = records.Max(r => r.Version);
                string? input = AnsiConsole.Prompt(
                    new TextPrompt<string>($"[grey]Enter version ([/]1[grey]-[/]{maxV}[grey], q to exit)[/]:")
                        .PromptStyle("cyan")
                        .ValidationErrorMessage("Invalid input")
                        .Validate(val =>
                        {
                            if (val.Equals("q", StringComparison.OrdinalIgnoreCase)) return ValidationResult.Success();
                            if (int.TryParse(val, out int n) && n >= 1 && n <= maxV) return ValidationResult.Success();
                            return ValidationResult.Error($"Enter 1-{maxV} or q");
                        }));

                if (input.Equals("q", StringComparison.OrdinalIgnoreCase)) break;

                int choice = int.Parse(input);
                var selected = records.FirstOrDefault(r => r.Version == choice);
                if (selected == null)
                {
                    AnsiConsole.MarkupLine("[yellow]Invalid version.[/]");
                    continue;
                }

                ShowVersionFiles(selected);
            }

            return 0;
        });
    }

    private static void RenderTable(List<VersionRecord> records)
    {
        AnsiConsole.Write(new Rule("[bold yellow]RDRF Version History[/]") { Style = Style.Parse("dim") });
        Console.WriteLine();

        var table = new Table();
        table.Border(TableBorder.Rounded);
        table.AddColumn(new TableColumn("#").RightAligned());
        table.AddColumn("Date");
        table.AddColumn("Message");
        table.AddColumn("Changes");
        table.AddColumn("Files");

        foreach (var r in records)
        {
            string date = DateTimeOffset.FromUnixTimeSeconds(r.CreatedAt).LocalDateTime.ToString("yyyy-MM-dd HH:mm");
            string changes = string.IsNullOrEmpty(r.SystemDiff) ? "(initial)" : "+/- lines";
            int fileCount = r.Files?.Count ?? 0;
            string fileStr = fileCount > 0 ? fileCount.ToString() : "";
            table.AddRow($"v{r.Version}", date, r.UserMessage, changes, fileStr);
        }
        AnsiConsole.Write(table);
        Console.WriteLine();
    }

    private static void ShowVersionFiles(VersionRecord version)
    {
        AnsiConsole.Write(new Rule($"[bold]v{version.Version}: {version.UserMessage}[/]") { Style = Style.Parse("dim") });
        Console.WriteLine();

        var files = version.Files;

        if (files == null || files.Count == 0)
        {
            ShowDiffText(version.SystemDiff);
            Console.WriteLine();
            AnsiConsole.Markup("[dim]Press Enter to return...[/]");
            Console.ReadLine();
            return;
        }

        var fileGrid = new Grid();
        fileGrid.AddColumn();
        foreach (var f in files)
        {
            string color = f.ChangeType switch
            {
                "added" => "green",
                "deleted" => "red",
                _ => "yellow",
            };
            string glyph = f.ChangeType switch
            {
                "added" => "[+]",
                "deleted" => "[-]",
                _ => "[*]",
            };
            fileGrid.AddRow(new Markup($"  [{color}]{glyph.EscapeMarkup()}[/] [white]{f.Path.EscapeMarkup()}[/]"));
        }
        AnsiConsole.Write(new Panel(fileGrid).Header("Changed files").BorderColor(Color.Grey));
        Console.WriteLine();
        Console.WriteLine();

        if (files.Count == 1)
        {
            ShowDiffText(files[0].Diff);
            Console.WriteLine();
            AnsiConsole.Markup("[dim]Press Enter to return...[/]");
            Console.ReadLine();
            return;
        }

        string? fileInput = AnsiConsole.Prompt(
            new TextPrompt<string>($"[grey]Enter file ([/]1[grey]-[/]{files.Count}[grey], q to go back)[/]:")
                .PromptStyle("cyan")
                .ValidationErrorMessage("Invalid input")
                .Validate(val =>
                {
                    if (val.Equals("q", StringComparison.OrdinalIgnoreCase)) return ValidationResult.Success();
                    if (int.TryParse(val, out int n) && n >= 1 && n <= files.Count) return ValidationResult.Success();
                    return ValidationResult.Error($"Enter 1-{files.Count} or q");
                }));

        if (fileInput.Equals("q", StringComparison.OrdinalIgnoreCase)) return;

        int fileChoice = int.Parse(fileInput);
        var fe = files[fileChoice - 1];
        ShowDiffText(fe.Diff);
        Console.WriteLine();
        AnsiConsole.Markup("[dim]Press Enter to return...[/]");
        Console.ReadLine();
    }

    private static void ShowDiffText(string diff)
    {
        if (string.IsNullOrEmpty(diff))
        {
            AnsiConsole.MarkupLine("[yellow]No diff content for this version.[/]");
            return;
        }

        foreach (string rawLine in diff.Split('\n'))
        {
            if (string.IsNullOrEmpty(rawLine)) continue;

            if (rawLine.StartsWith("@@"))
                AnsiConsole.MarkupLine($"[purple]{rawLine.EscapeMarkup()}[/]");
            else if (rawLine.StartsWith('-') && !rawLine.StartsWith("---"))
                AnsiConsole.MarkupLine($"[red]{rawLine.EscapeMarkup()}[/]");
            else if (rawLine.StartsWith('+') && !rawLine.StartsWith("+++"))
                AnsiConsole.MarkupLine($"[green]{rawLine.EscapeMarkup()}[/]");
            else if (!rawLine.StartsWith("---") && !rawLine.StartsWith("+++"))
                AnsiConsole.MarkupLine($"[white]{rawLine.EscapeMarkup()}[/]");
        }
    }
}
