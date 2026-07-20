using RDRF.Core;
using RDRF.Core.Diff;
using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Core.DSAA;
using RDRF.Core.Versioning;
using RDRF.Cli.Services;
using Spectre.Console;
using System.CommandLine;
using System.Linq;
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
        var gcOpt = new Option<bool>("-gc", "--gc") { Description = "Legacy GC mode: cleanup orphaned indexes between versions" };
        var compressionOpt = new Option<string[]>("-c")
        {
            Description = "Compression method and options. Values: lz4, lz4hc, zstd, gzip, brotli, lzma2, lzo, xz, ckc. e.g. -c zstd 5",
            Arity = new ArgumentArity(1, 2),
            AllowMultipleArgumentsPerToken = true
        };

        Arguments.Add(sourceArg);
        Options.Add(messageOpt);
        Options.Add(storageOpt);
        Options.Add(passwordOpt);
        Add(gcOpt);
        Add(compressionOpt);

        SetAction(async (ParseResult parseResult) =>
        {
            var source = parseResult.GetValue(sourceArg);
            var msg = parseResult.GetValue(messageOpt);
            var storageDir = parseResult.GetValue(storageOpt);
            var pwd = parseResult.GetValue(passwordOpt);
            bool gcMode = parseResult.GetValue(gcOpt);

            var compArgs = parseResult.GetValue(compressionOpt);
            string? compressionMethod = null;
            string? compressionOptions = null;
            if (compArgs is { Length: > 0 })
            {
                compressionMethod = compArgs[0];
                compressionOptions = compArgs.Length > 1 ? compArgs[1] : null;
            }

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
            var storage = new LocalDSAAAdapter(storagePath);

            var dir = new DirectoryInfo(storagePath);
            if (!dir.Exists)
            {
                AnsiConsole.MarkupLine($"[red]Error: storage directory not found: {storagePath.EscapeMarkup()}[/]");
                return 1;
            }
            var indexFiles = dir.GetFiles("*.indrdrf");
            bool noBackup = indexFiles.Length == 0;
            RdrfIndex? oldIndex = null;
            byte[]? aesKey = null;
            string? tempIndexPath = null;

            if (!noBackup)
            {
                var indexFile = indexFiles.OrderByDescending(f => f.LastWriteTime).First();
                if (indexFiles.Length > 1)
                    AnsiConsole.MarkupLine("[yellow]Warning:[/] multiple backups found, using first: " + indexFile.Name);

                byte[] encIdx = File.ReadAllBytes(indexFile.FullName);
                byte[] cbor;
                (aesKey, cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encIdx, password);
                oldIndex = IndexManager.DeserializeIndex(cbor);

                if ((oldIndex.VersionNumber ?? 0) > 0)
                {
                    // Existing versioned backup — create incremental
                    AnsiConsole.MarkupLine($"Current: [cyan]v{oldIndex.VersionNumber}[/] ([green]{oldIndex.FssStrategy}[/], [blue]{indexFile.Name}[/])");

                    // Preview diff: stream restore to temp + file-based diff (binary = size-only).
                    string tmpOld = Path.Combine(storagePath, $".next_prev_{Guid.NewGuid():N}.tmp");
                    try
                    {
                        string fp = oldIndex.FileFingerprint;
                        string prefix = oldIndex.CustomName ?? fp;
                        using (var ro = new RestoreOrchestrator(aesKey, password, new LocalDSAAAdapter(storagePath)))
                        {
                            bool ok = false;
                            try
                            {
                                ok = await ro.RestoreFileAsync(fp, tmpOld, filePrefix: prefix).ConfigureAwait(false);
                            }
                            catch (FileNotFoundException)
                            {
                                ok = false;
                            }
                            if (!ok)
                            {
                                try { ok = ro.RestoreFileFromFragments(prefix, tmpOld); }
                                catch { ok = false; }
                            }
                            if (!ok)
                                File.WriteAllBytes(tmpOld, ReadDecryptedOriginal(storage, oldIndex, aesKey));
                        }
                        var diffResult = new DiffEngine().ComputeDiffFromFiles(tmpOld, source.FullName, oldIndex.OriginalName);
                        long oldLen = new FileInfo(tmpOld).Length;
                        long newLen = source.Length;
                        if (diffResult.IsBinary)
                            AnsiConsole.MarkupLine($"[yellow]Binary file:[/] {oldLen} -> {newLen} bytes");
                        else
                            AnsiConsole.MarkupLine($"[yellow]Changes:[/] +{diffResult.AddedLines} -{diffResult.RemovedLines} lines (+{diffResult.AddedBytes} bytes)");
                    }
                    finally
                    {
                        try { if (File.Exists(tmpOld)) File.Delete(tmpOld); } catch { /* ignore */ }
                    }

                    string newFp = "";
                    await ProgressReporter.Run($"Incrementing {oldIndex.OriginalName}", async progress =>
                    {
                        newFp = await VersionedBackup.BackupAsync(
                                source.FullName, new LocalDSAAAdapter(storagePath), password, msg,
                                oldIndex.FssStrategy, progress: progress,
                                compressionMethod: compressionMethod, compressionOptions: compressionOptions,
                                gcMode: gcMode);
                    });

                    byte[] newEncIdx = File.ReadAllBytes(Path.Combine(storagePath, newFp + ".indrdrf"));
                    (_, byte[] newCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(newEncIdx, password);
                    var newIndex = IndexManager.DeserializeIndex(newCbor);

                    var resultTable = new Table();
                    resultTable.Border(TableBorder.Rounded);
                    resultTable.AddColumn("Property");
                    resultTable.AddColumn(new TableColumn("Value").NoWrap());
                    resultTable.AddRow("Version", $"v{(newIndex.VersionNumber ?? 0)}");
                    string fpDisplay = newFp;
                    resultTable.AddRow("Fingerprint", fpDisplay.Length > 32 ? $"{fpDisplay[..12]}...{fpDisplay[^8..]}" : fpDisplay);
                    resultTable.AddRow("Message", msg);
                    resultTable.AddRow("Strategy", newIndex.FssStrategy);
                    AnsiConsole.Write(resultTable);

                    return 0;
                }
            }

            // No backup, or non-versioned backup: create first version from scratch
            AnsiConsole.MarkupLine(noBackup
                ? "[yellow]No backup found — creating first version.[/]"
                : "[yellow]Existing backup not versioned — creating first version with existing strategy.[/]");

            int fragmentSize = 0; // auto
            var fssStrategy = oldIndex?.FssStrategy ?? "FSS1";
            var customName = oldIndex?.CustomName;

            string firstFp = "";
            await ProgressReporter.Run($"Backing up {source.Name}", async progress =>
            {
                firstFp = await VersionedBackup.BackupAsync(
                        source.FullName, new LocalDSAAAdapter(storagePath), password, msg,
                        fssStrategy, fragmentSize, customName, null, progress,
                        compressionMethod: compressionMethod, compressionOptions: compressionOptions,
                        gcMode: gcMode);
            });

            {
                var firstTable = new Table();
                firstTable.Border(TableBorder.Rounded);
                firstTable.AddColumn("Property");
                firstTable.AddColumn(new TableColumn("Value").NoWrap());
                firstTable.AddRow("Version", "v1 (initial)");
                string fp2 = firstFp;
                firstTable.AddRow("Fingerprint", fp2.Length > 32 ? $"{fp2[..12]}...{fp2[^8..]}" : fp2);
                firstTable.AddRow("Message", msg);
                firstTable.AddRow("Strategy", fssStrategy.ToString());
                AnsiConsole.Write(firstTable);
            }

            return 0;
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(password);
            }
        });
    }

    private static byte[] ReadDecryptedOriginal(DSAAAdapter storage, RdrfIndex index, byte[] aesKey)
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







