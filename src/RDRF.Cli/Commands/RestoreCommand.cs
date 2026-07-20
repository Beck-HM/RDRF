using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Core.DSAA;
using RDRF.Core.Logging;
using RDRF.Core.PasswordManager;
using RDRF.Cli.Services;
using Spectre.Console;
using System.CommandLine;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace RDRF.Cli.Commands;

/// <summary>
/// Restore a backup from its index file. CLI: rdrf res.
/// </summary>

public class RestoreCommand : Command
{
    private readonly PasswordManager _passwordManager;
    private readonly RdrfLogger _logger;

    public RestoreCommand(PasswordManager passwordManager, RdrfLogger logger) : base("res", "Restore a backup from its index file")
    {
        _passwordManager = passwordManager;
        _logger = logger;

        var indexArg = new Argument<FileInfo>("indexFile") { Description = "Path to the .indrdrf index file" };
        var outputOpt = new Option<FileInfo>("-o") { Description = "Output file path for the restored data (required)" };
        var versionOpt = new Option<int>("--ver") { Description = "Version number to restore (default: latest)" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password as plain text (INSECURE: visible in process list; omit for secure prompt)" };
        var fpOpt = new Option<string?>("-fp") { Description = "FastPassword key (bypass auto-lookup)" };

        Arguments.Add(indexArg);
        Options.Add(outputOpt);
        Options.Add(versionOpt);
        Options.Add(passwordOpt);
        Options.Add(fpOpt);

        SetAction(async (ParseResult parseResult) =>
        {
            var indexFile = parseResult.GetValue(indexArg);
            var output = parseResult.GetValue(outputOpt);
            int targetVersion = parseResult.GetValue(versionOpt);
            var pwd = parseResult.GetValue(passwordOpt);
            var fpKey = parseResult.GetValue(fpOpt);

            if (!indexFile.Exists)
            {
                AnsiConsole.MarkupLine($"[red]Error: index file not found: {indexFile.FullName.EscapeMarkup()}[/]");
                return 1;
            }
            if (output == null)
            {
                string? latest = null;
                string? storageParent = indexFile.DirectoryName;
                if (storageParent != null)
                {
                    try
                    {
                        var dir = new DirectoryInfo(storageParent);
                        var recent = dir.GetFiles("*.indrdrf")
                            .OrderByDescending(f => f.LastWriteTime)
                            .FirstOrDefault();
                        if (recent != null)
                            latest = recent.FullName;
                    }
                    catch (Exception ex) { Debug.WriteLine($"[RestoreCommand] Listing backups failed: {ex.Message}"); }
                }
                string hint = latest != null
                    ? $" (use with: rdrf res \"{latest}\" -o <path>)"
                    : "";
                AnsiConsole.MarkupLine("[red]Error: -o <outputPath> is required[/]" + hint.EscapeMarkup());
                return 1;
            }

            if (fpKey != null && pwd != null)
            {
                AnsiConsole.MarkupLine("[red]Error: -fp and -password cannot be used together[/]");
                return 1;
            }

            byte[] password;
            string storageDir = indexFile.DirectoryName!;

            if (fpKey != null)
            {
                
                string? stored = _passwordManager.GetByKey(fpKey);
                if (stored == null)
                {
                    AnsiConsole.MarkupLine($"[red]Error: FastPassword '{fpKey}' not found.[/]");
                    return 1;
                }
                password = Encoding.UTF8.GetBytes(stored);
            }
            else if (pwd != null)
            {
                password = Encoding.UTF8.GetBytes(pwd);
            }
            else
            {
                // Auto-lookup by index hash
                string indexHash = HashHelper.ComputeSha256Hex(indexFile.FullName);
                
                string? stored = _passwordManager.GetByIndexHash(indexHash);
                if (stored != null)
                {
                    AnsiConsole.MarkupLine("[green]FastPassword match found, auto-unlocking...[/]");
                    password = Encoding.UTF8.GetBytes(stored);
                }
                else
                {
                    password = PasswordProvider.ReadInteractive();
                }
            }

            if (password.Length == 0)
            {
                AnsiConsole.MarkupLine("[red]Error: password cannot be empty[/]");
                return 1;
            }

            try
            {
                byte[] encryptedIndex = File.ReadAllBytes(indexFile.FullName);

                int exitCode;
                using (var engine = new RDRFEngine(password, new LocalDSAAAdapter(storageDir), logger: _logger))
                {
                    exitCode = await RunRestore(engine, password, encryptedIndex, output.FullName, targetVersion);
                }

                return exitCode;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(password);
            }
        });
    }

    private static async Task<int> RunRestore(
        RDRFEngine engine, byte[] password, byte[] encryptedIndex, string outputPath, int targetVersion)
    {
        try
        {
            (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
            var index = IndexManager.DeserializeIndex(cbor);

            bool success;
            if (targetVersion > 0)
            {
                var vr = index.Versions?.FirstOrDefault(v => v.Version == targetVersion)
                    ?? throw new InvalidOperationException($"Version {targetVersion} not found in index history");
                // Real-incremental: each version may have its own index file (content fingerprint).
                // Prefer that index when present so --ver restores the correct payload.
                string vFp = vr.FileFingerprint;
                if (string.IsNullOrEmpty(vFp))
                    throw new InvalidOperationException($"Version {targetVersion} has no FileFingerprint in history");
                if (engine.FileExists(vFp))
                {
                    success = await AnsiConsole.Status()
                        .StartAsync($"Restoring v{targetVersion}...", async _ =>
                            await engine.RestoreFileAsync(vFp, outputPath, filePrefix: vFp));
                }
                else
                {
                    success = await AnsiConsole.Status()
                        .StartAsync($"Restoring v{targetVersion} from fragments...", async _ =>
                            await engine.RestoreFileFromFragmentsAsync(vFp, outputPath));
                }
            }
            else
            {
                // Latest: use the index the user pointed at (CustomName or fingerprint prefix).
                string prefix = index.CustomName ?? index.FileFingerprint;
                if (engine.FileExists(prefix))
                {
                    success = await AnsiConsole.Status()
                        .StartAsync("Restoring...", async _ =>
                            await engine.RestoreFileAsync(prefix, outputPath, filePrefix: prefix));
                }
                else
                {
                    success = await AnsiConsole.Status()
                        .StartAsync("Restoring...", async _ =>
                            await engine.RestoreFileFromFragmentsAsync(prefix, outputPath));
                }
            }

            if (success)
            {
                AnsiConsole.MarkupLine($"[green]Restored to:[/] {outputPath.EscapeMarkup()}");
                return 0;
            }
            AnsiConsole.MarkupLine("[red]Error: restore failed (data may be corrupted)[/]");
            return 1;
        }
        catch (CryptographicException)
        {
            AnsiConsole.MarkupLine("[red]Error: wrong password - the backup could not be decrypted.[/]");
            AnsiConsole.MarkupLine("[yellow]Tip: check Caps Lock or try a similar password (typo near the real one).[/]");
            return 1;
        }
        catch (InvalidOperationException ex)
        {
            AnsiConsole.MarkupLine($"[red]{ex.Message.EscapeMarkup()}[/]");
            return 1;
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Error: {ex.Message.EscapeMarkup()}[/]");
            return 1;
        }
    }
}







