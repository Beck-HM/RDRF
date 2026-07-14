using RDRF.Core;
using RDRF.Core.Diff;
using RDRF.Core.DSAA;
using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Core.Logging;
using RDRF.Core.Versioning;
using RDRF.Cli.Services;
using Spectre.Console;
using System.CommandLine;
using System.Security.Cryptography;
using System.Text;

namespace RDRF.Cli.Commands;

/// <summary>
/// Show diff between two versions. CLI: rdrf diff.
/// </summary>

public class DiffCommand : Command
{
    private readonly RdrfLogger _logger;

    public DiffCommand(RdrfLogger logger) : base("diff", "Show diff between two versions of a backup")
    {
        _logger = logger;
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

                // Full reconstruct mode: restore both versions to temp files in the .rdrf directory.
                // Each version's fragments have the embedded index, so use RestoreFileFromFragments.
                string storageDir = Path.GetDirectoryName(indexFile.FullName) ?? ".";
                byte[] encryptedIndex = File.ReadAllBytes(indexFile.FullName);
                (byte[] aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
                var index = IndexManager.DeserializeIndex(cbor);

                var v1Record = records.FirstOrDefault(r => r.Version == v1);
                var v2Record = records.FirstOrDefault(r => r.Version == v2);
                if (v1Record == null || v2Record == null)
                {
                    AnsiConsole.MarkupLine("[red]Error: version records not found.[/]");
                    return 1;
                }

                string v1Fp = v1Record.FileFingerprint;
                string v2Fp = v2Record.FileFingerprint;
                string tmpV1 = Path.Combine(storageDir, $".diff_v{v1}_{Guid.NewGuid():N}.tmp");
                string tmpV2 = Path.Combine(storageDir, $".diff_v{v2}_{Guid.NewGuid():N}.tmp");
                var storage = new LocalDSAAAdapter(storageDir);

                try
                {
                    using var ro = new RestoreOrchestrator(aesKey, password, storage, logger: _logger);
                    bool ok1 = ro.RestoreFileFromFragments(v1Fp, tmpV1);
                    if (!ok1)
                    {
                        AnsiConsole.MarkupLine($"[red]Error: failed to restore version {v1} (fragments missing for {v1Fp.Substring(0, 16)}...).[/]");
                        return 1;
                    }
                    bool ok2 = ro.RestoreFileFromFragments(v2Fp, tmpV2);
                    if (!ok2)
                    {
                        AnsiConsole.MarkupLine($"[red]Error: failed to restore version {v2} (fragments missing for {v2Fp.Substring(0, 16)}...).[/]");
                        return 1;
                    }

                    byte[] oldBytes = File.ReadAllBytes(tmpV1);
                    byte[] newBytes = File.ReadAllBytes(tmpV2);
                    var diffResult = new DiffEngine().ComputeDiff(oldBytes, newBytes, index.OriginalName);
                    OutputDiff(diffResult.HumanDiff, outputFile, format);
                    return 0;
                }
                finally
                {
                    try { if (File.Exists(tmpV1)) File.Delete(tmpV1); } catch { }
                    try { if (File.Exists(tmpV2)) File.Delete(tmpV2); } catch { }
                }
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
                int add = 0, del = 0;
                foreach (string line in diffText.Split('\n'))
                {
                    if (line.StartsWith('+') && !line.StartsWith("+++")) add++;
                    if (line.StartsWith('-') && !line.StartsWith("---")) del++;
                }
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







