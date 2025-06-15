using RDRF.Core.Versioning;
using RDRF.Cli.Services;
using Spectre.Console;
using System.CommandLine;
using System.Text;

namespace RDRF.Cli.Commands;

public class CheckCommand : Command
{
    public CheckCommand() : base("check", "View version history and diffs")
    {
        var indexArg = new Argument<FileInfo>("indexFile") { Description = "Path to the .indrdrf index file" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password as plain text (omit for interactive prompt)" };

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

            while (true)
            {
                AnsiConsole.Write(new Rule("[bold yellow]RDRF Version History[/]") { Style = Style.Parse("dim") });
                Console.WriteLine();

                var table = new Table();
                table.Border(TableBorder.Rounded);
                table.AddColumn(new TableColumn("#").RightAligned());
                table.AddColumn("Date");
                table.AddColumn("Message");
                table.AddColumn("Changes");

                foreach (var r in records)
                {
                    string date = DateTimeOffset.FromUnixTimeSeconds(r.CreatedAt).LocalDateTime.ToString("yyyy-MM-dd HH:mm");
                    string changes = string.IsNullOrEmpty(r.SystemDiff) ? "(initial)" : $"+/- lines";
                    table.AddRow($"v{r.Version}", date, r.UserMessage, changes);
                }
                AnsiConsole.Write(table);
                Console.WriteLine();

                int? choice = AnsiConsole.Prompt(
                    new TextPrompt<int>("Enter version [grey](1-[/]" + records.Max(r => r.Version) + "[grey], 0 to exit)[/]:")
                        .PromptStyle("cyan")
                        .ValidationErrorMessage("Invalid version number")
                        .Validate(input => input >= 0 && input <= records.Max(r => r.Version)
                            ? ValidationResult.Success()
                            : ValidationResult.Error($"Enter 0-{records.Max(r => r.Version)}")));

                if (choice == 0) break;

                var selected = records.FirstOrDefault(r => r.Version == choice);
                if (selected == null || string.IsNullOrEmpty(selected.SystemDiff))
                {
                    AnsiConsole.MarkupLine("[yellow]No diff content for this version.[/]");
                }
                else
                {
                    AnsiConsole.Write(new Rule($"[bold]v{selected.Version}: {selected.UserMessage}[/]") { Style = Style.Parse("dim") });
                    Console.WriteLine();

                    foreach (string rawLine in selected.SystemDiff.Split('\n'))
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

                    Console.WriteLine();
                    AnsiConsole.Markup("[dim]Press Enter to return...[/]");
                    Console.ReadLine();
                }
            }

            return 0;
        });
    }
}
