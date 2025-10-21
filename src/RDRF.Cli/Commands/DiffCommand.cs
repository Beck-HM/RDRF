using RDRF.Core.Versioning;
using RDRF.Cli.Services;
using Spectre.Console;
using System.CommandLine;
using System.Security.Cryptography;
using System.Text;

namespace RDRF.Cli.Commands;

public class DiffCommand : Command
{
    public DiffCommand() : base("diff", "Show diff between two versions of a backup")
    {
        var indexArg = new Argument<FileInfo>("indexFile") { Description = "Path to the .indrdrf index file" };
        var v1Arg = new Argument<int>("v1") { Description = "Version number (0 for initial)" };
        var v2Arg = new Argument<int>("v2") { Description = "Version number (use 0 for initial)" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password as plain text (INSECURE)" };
        var outputOpt = new Option<FileInfo?>("-o") { Description = "Write diff to file instead of stdout" };
        var formatOpt = new Option<string>("--format") { Description = "Output format: unified or stat" };

        Arguments.Add(indexArg);
        Arguments.Add(v1Arg);
        Arguments.Add(v2Arg);
        Options.Add(passwordOpt);
        Options.Add(outputOpt);
        Options.Add(formatOpt);

        SetAction((ParseResult parseResult) =>
        {
            var indexFile = parseResult.GetValue(indexArg);
            var v1 = parseResult.GetValue(v1Arg);
            var v2 = parseResult.GetValue(v2Arg);
            var pwd = parseResult.GetValue(passwordOpt);
            var outputFile = parseResult.GetValue(outputOpt);
            var format = parseResult.GetValue(formatOpt) ?? "unified";

                if (!indexFile.Exists)
            {
                AnsiConsole.MarkupLine($"[red]Error: index file not found: {indexFile.FullName.EscapeMarkup()}[/]");
                return 1;
            }

            byte[] password = pwd != null ? Encoding.UTF8.GetBytes(pwd) : PasswordProvider.ReadInteractive();
            try
            {
                if (password.Length == 0)
                {
                    AnsiConsole.MarkupLine("[red]Error: password cannot be empty[/]");
                    return 1;
                }

                var records = VersionedRestore.GetVersionHistory(indexFile.FullName, password);
                if (records.Count == 0)
                {
                    AnsiConsole.MarkupLine("[red]Error: no version history found[/]");
                    return 1;
                }

                int maxV = records.Max(r => r.Version);
                if (v1 < 0 || v1 > maxV || v2 < 0 || v2 > maxV)
                {
                    AnsiConsole.MarkupLine($"[red]Error: versions must be 0-{maxV}[/]");
                    return 1;
                }

                if (v1 == v2)
                {
                    string msg = "No differences (same version).";
                    if (outputFile != null)
                    {
                        File.WriteAllText(outputFile.FullName, msg);
                        AnsiConsole.MarkupLine($"[green]Written to[/] {outputFile.FullName.EscapeMarkup()}");
                    }
                    else
                    {
                        AnsiConsole.MarkupLine("[yellow]No differences (same version).[/]");
                    }
                    return 0;
                }

                if (v1 > v2)
                {
                    (v1, v2) = (v2, v1);
                }

                // Quick mode: adjacent versions with stored diff
                if (v2 == v1 + 1)
                {
                    var later = records.FirstOrDefault(r => r.Version == v2);
                    if (later != null && !string.IsNullOrEmpty(later.SystemDiff))
                    {
                        string diffText = later.SystemDiff;
                        OutputDiff(diffText, outputFile, format);
                        return 0;
                    }
                }

                // Full reconstruct mode
                AnsiConsole.MarkupLine("[yellow]Full reconstruct mode not yet implemented. Use adjacent versions for stored diffs.[/]");
                return 1;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(password);
            }
        });
    }

    private static void OutputDiff(string diffText, FileInfo? outputFile, string format)
    {
        if (outputFile != null)
        {
            if (format == "stat")
            {
                int add = diffText.Count(c => c == '+' && !diffText.SkipWhile(l => l != '\n').Any());
                int del = diffText.Count(c => c == '-');
                File.WriteAllText(outputFile.FullName, $"+{add} -{del} lines");
            }
            else
            {
                File.WriteAllText(outputFile.FullName, diffText);
            }
            AnsiConsole.MarkupLine($"[green]Written to[/] {outputFile.FullName.EscapeMarkup()}");
        }
        else
        {
            if (format == "stat")
            {
                int add = 0, del = 0;
                foreach (string line in diffText.Split('\n'))
                {
                    if (line.StartsWith('+') && !line.StartsWith("+++")) add++;
                    if (line.StartsWith('-') && !line.StartsWith("---")) del++;
                }
                AnsiConsole.MarkupLine($"[green]+{add}[/] [red]-{del}[/] lines");
            }
            else
            {
                ShowDiffText(diffText);
            }
        }
    }

    private static void ShowDiffText(string diff)
    {
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
