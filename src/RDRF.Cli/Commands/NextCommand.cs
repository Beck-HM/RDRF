using RDRF.Core;
using RDRF.Core.Diff;
using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Core.Dssa;
using RDRF.Core.Versioning;
using RDRF.Cli.Services;
using Spectre.Console;
using System.CommandLine;
using System.Text;

namespace RDRF.Cli.Commands;

/// <summary>
/// Create an incremental versioned backup. CLI: rdrf next.
/// </summary>

public class NextCommand : Command
{
    public NextCommand() : base("next", "Create an incremental versioned backup")
    {
        var sourceArg = new Argument<FileInfo>("source") { Description = "New or modified file path" };
        var messageOpt = new Option<string>("-m") { Description = "Commit message describing the change (required)" };
        var storageOpt = new Option<DirectoryInfo?>("-o") { Description = "Storage directory (default: ./backup/)" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password as plain text (INSECURE: visible in process list; omit for secure prompt)" };
        var realOpt = new Option<bool>("-real", "--real") { Description = "Real incremental mode: keep all version files permanently" };

        Arguments.Add(sourceArg);
        Options.Add(messageOpt);
        Options.Add(storageOpt);
        Options.Add(passwordOpt);
        Add(realOpt);

        SetAction(async (ParseResult parseResult) =>
        {
            var source = parseResult.GetValue(sourceArg);
            var msg = parseResult.GetValue(messageOpt);
            var storageDir = parseResult.GetValue(storageOpt);
            var pwd = parseResult.GetValue(passwordOpt);
            bool realMode = parseResult.GetValue(realOpt);

            if (!source.Exists)
            {
                AnsiConsole.MarkupLine($"[red]Error: file not found: {source.FullName.EscapeMarkup()}[/]");
                return 1;
            }
            if (string.IsNullOrEmpty(msg))
            {
                AnsiConsole.MarkupLine("[red]Error: -m <commit message> is required[/]");
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
            string storagePath = storageDir?.FullName ?? Path.Combine(AppContext.BaseDirectory, "backup");
            var storage = new LocalDssaAdapter(storagePath);

            var dir = new DirectoryInfo(storagePath);
            if (!dir.Exists)
            {
                AnsiConsole.MarkupLine($"[red]Error: storage directory not found: {storagePath.EscapeMarkup()}[/]");
                return 1;
            }
            var indexFiles = dir.GetFiles("*.indrdrf");
            if (indexFiles.Length == 0)
            {
                AnsiConsole.MarkupLine("[red]Error: no backup found in storage directory. Use 'backup' command first.[/]");
                return 1;
            }
            var indexFile = indexFiles[0];
            if (indexFiles.Length > 1)
                AnsiConsole.MarkupLine("[yellow]Warning:[/] multiple backups found, using first: " + indexFile.Name);

            byte[] encIdx = File.ReadAllBytes(indexFile.FullName);
            (byte[] aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encIdx, password);
            var oldIndex = IndexManager.DeserializeIndex(cbor);

            AnsiConsole.MarkupLine($"Current: [cyan]v{oldIndex.VersionNumber ?? 0}[/] ([green]{oldIndex.FssStrategy}[/], [blue]{indexFile.Name}[/])");

            if ((oldIndex.VersionNumber ?? 0) == 0)
            {
                AnsiConsole.MarkupLine("[red]Error: backup is not versioned. Use 'backup' for first backup, then 'next' for increments.[/]");
                return 1;
            }

            var oldBytes = ReadDecryptedOriginal(storage, oldIndex, aesKey);
            var newBytes = await File.ReadAllBytesAsync(source.FullName);
            var diffResult = new RDRF.Core.Diff.DiffEngine().ComputeDiff(oldBytes, newBytes, oldIndex.OriginalName);

            if (diffResult.IsBinary)
                AnsiConsole.MarkupLine($"[yellow]Binary file:[/] {oldBytes.Length} -> {newBytes.Length} bytes");
            else
                AnsiConsole.MarkupLine($"[yellow]Changes:[/] +{diffResult.AddedLines} -{diffResult.RemovedLines} lines (+{diffResult.AddedBytes} bytes)");

            string newFp = "";
            await ProgressReporter.Run($"Incrementing {oldIndex.OriginalName}", async progress =>
            {
                newFp = realMode
                    ? await RealVersionedBackup.BackupAsync(
                        source.FullName, new LocalDssaAdapter(storagePath), password, msg,
                        oldIndex.FssStrategy, progress: progress)
                    : await VersionedBackup.BackupAsync(
                        source.FullName, new LocalDssaAdapter(storagePath), password, msg,
                        oldIndex.FssStrategy, progress: progress);
            });

            byte[] newEncIdx = File.ReadAllBytes(Path.Combine(storagePath, newFp + ".indrdrf"));
            (_, byte[] newCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(newEncIdx, password);
            var newIndex = IndexManager.DeserializeIndex(newCbor);

            var table = new Table();
            table.Border(TableBorder.Rounded);
            table.AddColumn("Property");
            table.AddColumn(new TableColumn("Value").NoWrap());
            table.AddRow("Version", $"v{(newIndex.VersionNumber ?? 0)}");
            string fp = newFp;
            table.AddRow("Fingerprint", fp.Length > 32 ? $"{fp[..12]}...{fp[^8..]}" : fp);
            table.AddRow("Message", msg);
            table.AddRow("Strategy", newIndex.FssStrategy);
            AnsiConsole.Write(table);

            return 0;
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(password);
            }
        });
    }

    private static byte[] ReadDecryptedOriginal(DssaAdapter storage, RdrfIndex index, byte[] aesKey)
    {
        string prefix = index.CustomName ?? index.FileFingerprint;
        var rawFragments = new List<byte[]>();
        for (int i = 0; i < index.FragmentCount; i++)
        {
            string fragName = RDRF.Core.FragmentEngine.Frags.FragmentFilename(prefix, i);
            byte[] encrypted = storage.ReadFragment(fragName);
            byte[] raw = EncryptionLayer.DecryptAndStripFragment(encrypted, aesKey);
            rawFragments.Add(raw);
        }

        var decoded = new Dictionary<int, byte[]>();
        for (int i = 0; i < index.OriginalFragmentCount && i < rawFragments.Count; i++)
            decoded[i] = rawFragments[i];

        var fssEngine = new RDRF.Core.FSS.FSSEngine();
        var stripped = fssEngine.Strip(decoded, index.FssStrategy, index.OriginalFragmentCount, index.OriginalFragmentSizes);
        return RDRF.Core.FragmentEngine.Frags.MergeFragments(stripped);
    }
}







