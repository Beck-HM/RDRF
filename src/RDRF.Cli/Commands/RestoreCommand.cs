using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Core.Dssa;
using RDRF.Cli.Services;
using Spectre.Console;
using System.CommandLine;
using System.Security.Cryptography;
using System.Text;

namespace RDRF.Cli.Commands;

public class RestoreCommand : Command
{
    public RestoreCommand() : base("res", "Restore a backup from its index file")
    {
        var indexArg = new Argument<FileInfo>("indexFile") { Description = "Path to the .indrdrf index file" };
        var outputOpt = new Option<FileInfo>("-o") { Description = "Output file path for the restored data (required)" };
        var versionOpt = new Option<int>("-v") { Description = "Version number to restore (default: latest)" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password as plain text (INSECURE: visible in process list; omit for secure prompt)" };

        Arguments.Add(indexArg);
        Options.Add(outputOpt);
        Options.Add(versionOpt);
        Options.Add(passwordOpt);

        SetAction(async (ParseResult parseResult) =>
        {
            var indexFile = parseResult.GetValue(indexArg);
            var output = parseResult.GetValue(outputOpt);
            int targetVersion = parseResult.GetValue(versionOpt);
            var pwd = parseResult.GetValue(passwordOpt);

            if (!indexFile.Exists)
            {
                AnsiConsole.MarkupLine($"[red]Error: index file not found: {indexFile.FullName.EscapeMarkup()}[/]");
                return 1;
            }
            if (output == null)
            {
                AnsiConsole.MarkupLine("[red]Error: -o <outputPath> is required[/]");
                return 1;
            }

            byte[] password = pwd != null ? Encoding.UTF8.GetBytes(pwd) : PasswordProvider.ReadInteractive();
            if (password.Length == 0)
            {
                AnsiConsole.MarkupLine("[red]Error: password cannot be empty[/]");
                return 1;
            }

            try
            {
                string storageDir = indexFile.DirectoryName!;
                byte[] encryptedIndex = File.ReadAllBytes(indexFile.FullName);

                int exitCode;
                using (var engine = new RDRFEngine(password, new LocalDssaAdapter(storageDir)))
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

            string prefix;
            bool success;

            if (targetVersion > 0)
            {
                var vr = index.Versions?.FirstOrDefault(v => v.Version == targetVersion)
                    ?? throw new InvalidOperationException($"Version {targetVersion} not found in index history");
                prefix = index.CustomName ?? vr.FileFingerprint;
                success = await AnsiConsole.Status()
                    .StartAsync($"Restoring v{targetVersion}...", async _ =>
                        await engine.RestoreFileFromFragmentsAsync(prefix, outputPath));
            }
            else
            {
                prefix = index.CustomName ?? index.FileFingerprint;
                success = await AnsiConsole.Status()
                    .StartAsync("Restoring latest version...", async _ =>
                        await engine.RestoreFileAsync(index.FileFingerprint, outputPath, filePrefix: prefix));
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
            AnsiConsole.MarkupLine("[red]Error: wrong password or corrupt index file[/]");
            return 1;
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Error: {ex.Message.EscapeMarkup()}[/]");
            return 1;
        }
    }
}
