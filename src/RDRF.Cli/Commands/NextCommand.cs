using RDRF.Core;
using RDRF.Core.Diff;
using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Core.Storage;
using RDRF.Core.Versioning;
using RDRF.Cli.Services;
using Spectre.Console;
using System.CommandLine;
using System.Text;

namespace RDRF.Cli.Commands;

public class NextCommand : Command
{
    public NextCommand() : base("next", "Create an incremental versioned backup")
    {
        var sourceArg = new Argument<FileInfo>("source") { Description = "New or modified file path" };
        var messageOpt = new Option<string>("-m") { Description = "Commit message describing the change" };
        var storageOpt = new Option<DirectoryInfo?>("-o") { Description = "Storage directory (default: ./backup/)" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password as plain text (INSECURE: visible in process list; omit for secure prompt)" };

        Arguments.Add(sourceArg);
        Options.Add(messageOpt);
        Options.Add(storageOpt);
        Options.Add(passwordOpt);

        SetAction(async (ParseResult parseResult) =>
        {
            var source = parseResult.GetValue(sourceArg);
            var msg = parseResult.GetValue(messageOpt);
            var storageDir = parseResult.GetValue(storageOpt);
            var pwd = parseResult.GetValue(passwordOpt);

            if (!source.Exists)
            {
                Console.Error.WriteLine($"Error: file not found: {source.FullName}");
                return 1;
            }
            if (string.IsNullOrEmpty(msg))
            {
                Console.Error.WriteLine("Error: -m <commit message> is required");
                return 1;
            }

            byte[] password = pwd != null ? Encoding.UTF8.GetBytes(pwd) : PasswordProvider.ReadInteractive();
            if (password.Length == 0)
            {
                Console.Error.WriteLine("Error: password cannot be empty");
                return 1;
            }

            string storagePath = storageDir?.FullName ?? Path.Combine(AppContext.BaseDirectory, "backup");
            var storage = new LocalFileAdapter(storagePath);

            // Find existing index
            var dir = new DirectoryInfo(storagePath);
            if (!dir.Exists)
            {
                Console.Error.WriteLine($"Error: storage directory not found: {storagePath}");
                return 1;
            }
            var indexFiles = dir.GetFiles("*.indrdrf");
            if (indexFiles.Length == 0)
            {
                Console.Error.WriteLine("Error: no backup found in storage directory. Use 'backup' command first.");
                return 1;
            }
            var indexFile = indexFiles[0];
            if (indexFiles.Length > 1)
                AnsiConsole.MarkupLine("[yellow]Warning:[/] multiple backups found, using first: " + indexFile.Name);

            // Read old index to get current status
            byte[] encIdx = File.ReadAllBytes(indexFile.FullName);
            (byte[] aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encIdx, password);
            var oldIndex = IndexManager.DeserializeIndex(cbor);

            AnsiConsole.MarkupLine($"Current: [cyan]v{oldIndex.VersionNumber ?? 0}[/] ([green]{oldIndex.FssStrategy}[/], [blue]{indexFile.Name}[/])");

            if ((oldIndex.VersionNumber ?? 0) == 0)
            {
                Console.Error.WriteLine("Error: backup is not versioned. Use 'backup' for first backup, then 'next' for increments.");
                return 1;
            }

            // Show diff summary
            var oldBytes = ReadDecryptedOriginal(storage, oldIndex, aesKey);
            var newBytes = await File.ReadAllBytesAsync(source.FullName);
            var diffResult = new RDRF.Core.Diff.DiffEngine().ComputeDiff(oldBytes, newBytes, oldIndex.OriginalName);

            if (diffResult.IsBinary)
                AnsiConsole.MarkupLine($"[yellow]Binary file:[/] {oldBytes.Length} é”?{newBytes.Length} bytes");
            else
                AnsiConsole.MarkupLine($"[yellow]Changes:[/] +{diffResult.AddedLines} -{diffResult.RemovedLines} lines (+{diffResult.AddedBytes} bytes)");

            // Run incremental backup
            string newFp = "";
            await ProgressReporter.Run($"Incrementing {oldIndex.OriginalName}", async progress =>
            {
                newFp = await VersionedBackup.BackupAsync(
                    source.FullName, storagePath, password, msg,
                    oldIndex.FssStrategy, progress: progress);
            });

            // Show result
            byte[] newEncIdx = File.ReadAllBytes(Path.Combine(storagePath, newFp + ".indrdrf"));
            (_, byte[] newCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(newEncIdx, password);
            var newIndex = IndexManager.DeserializeIndex(newCbor);

            var table = new Table();
            table.Border(TableBorder.Rounded);
            table.AddColumn("Property");
            table.AddColumn("Value");
            table.AddRow("Version", $"v{(newIndex.VersionNumber ?? 0)}");
            table.AddRow("Fingerprint", newFp);
            table.AddRow("Message", msg);
            table.AddRow("Strategy", newIndex.FssStrategy);
            AnsiConsole.Write(table);

            return 0;
        });
    }

    private static byte[] ReadDecryptedOriginal(StorageAdapter storage, RdrfIndex index, byte[] aesKey)
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
