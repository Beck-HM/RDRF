using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Cli.Services;
using Spectre.Console;
using System.CommandLine;
using System.Security.Cryptography;
using System.Text;

namespace RDRF.Cli.Commands;

/// <summary>
/// Show backup metadata from an index file. CLI: rdrf info.
/// </summary>

public class InfoCommand : Command
{
    public InfoCommand() : base("info", "Show backup metadata and settings from index file")
    {
        var indexArg = new Argument<FileInfo>("indexFile") { Description = "Path to the .indrdrf index file" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password as plain text (INSECURE: visible in process list; omit for secure prompt)" };

        Arguments.Add(indexArg);
        Options.Add(passwordOpt);

        SetAction(async (ParseResult parseResult) =>
        {
            var indexFile = parseResult.GetValue(indexArg);
            var pwd = parseResult.GetValue(passwordOpt);

            if (!indexFile.Exists)
            {
                AnsiConsole.MarkupLine($"[red]Error: index file not found: {indexFile.FullName.EscapeMarkup()}[/]");
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
                byte[] encryptedIndex = await File.ReadAllBytesAsync(indexFile.FullName);

                RdrfIndex index;
                try
                {
                    (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
                    index = IndexManager.DeserializeIndex(cbor);
                }
                catch
                {
                    AnsiConsole.MarkupLine("[red]Error: wrong password or corrupted index file[/]");
                    return 1;
                }

                string createdAt = DateTimeOffset.FromUnixTimeSeconds(index.CreatedAt)
                    .ToString("yyyy-MM-dd HH:mm:ss UTC");

                var table = new Table();
                table.Border(TableBorder.Rounded);
                table.AddColumn("Property");
                table.AddColumn(new TableColumn("Value").NoWrap());
                string fp = index.FileFingerprint;
                table.AddRow("Fingerprint", fp.Length > 32 ? $"{fp[..12]}...{fp[^8..]}" : fp);
                table.AddRow("File", index.OriginalName);
                table.AddRow("Size", $"{index.FileSize:N0} bytes");
                table.AddRow("Strategy", index.FssStrategy);
                table.AddRow("Fragments", $"{index.FragmentCount} (original: {index.OriginalFragmentCount})");

                string? fss6 = (index.Fss6FragmentBlockMaps != null || index.Fss6RcBlockMap != null)
                    ? "with FSS6/ETN" : null;
                table.AddRow("ETN", fss6 ?? "no");

                table.AddRow("Salt", index.Salt ?? "(none)");
                table.AddRow("Created", createdAt);
                if (index.UpdatedAt.HasValue)
                {
                    string updatedAt = DateTimeOffset.FromUnixTimeSeconds(index.UpdatedAt.Value)
                        .ToString("yyyy-MM-dd HH:mm:ss UTC");
                    table.AddRow("Updated", updatedAt);
                }
                if (index.CustomName != null)
                    table.AddRow("CustomName", index.CustomName);

                AnsiConsole.Write(table);
                return 0;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(password);
            }
        });
    }
}







