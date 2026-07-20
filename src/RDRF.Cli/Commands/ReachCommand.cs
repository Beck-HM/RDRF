using RDRF.Cli.Services;
using RDRF.Core;
using RDRF.Core.DSAA;
using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Core.Integrity;
using RDRF.Core.Logging;
using RDRF.Core.Versioning;
using Spectre.Console;
using System.CommandLine;
using System.Security.Cryptography;
using System.Text;

namespace RDRF.Cli.Commands;

public class ReachCommand : Command
{
    public ReachCommand(RdrfLogger logger) : base("reach", "Scan and interactively operate on backups")
    {
        var pathArg = new Argument<DirectoryInfo>("path") { Description = "Directory to scan for .indrdrf index files" };
        var outputOpt = new Option<DirectoryInfo?>("-o") { Description = "Output directory (default: {path}/res/)" };
        var recursiveOpt = new Option<bool>("-r", "--recursive") { Description = "Scan subdirectories recursively" };
        var verifyOpt = new Option<bool>("-verify") { Description = "Verify backup integrity" };
        var infoOpt = new Option<bool>("-info") { Description = "Show backup info" };
        var statusOpt = new Option<bool>("-status") { Description = "Show fragment status" };
        var nextOpt = new Option<bool>("-next") { Description = "Create incremental versioned backup" };
        var checkOpt = new Option<bool>("-check") { Description = "Show version history" };
        var diffOpt = new Option<bool>("-diff") { Description = "Compare two backups side by side" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password as plain text (INSECURE)" };

        Arguments.Add(pathArg);
        Options.Add(outputOpt);
        Options.Add(recursiveOpt);
        Options.Add(verifyOpt);
        Options.Add(infoOpt);
        Options.Add(statusOpt);
        Options.Add(nextOpt);
        Options.Add(checkOpt);
        Options.Add(diffOpt);
        Options.Add(passwordOpt);

        SetAction((ParseResult parseResult) =>
        {
            var dir = parseResult.GetValue(pathArg);
            var outputDirOpt = parseResult.GetValue(outputOpt);
            bool recursive = parseResult.GetValue(recursiveOpt);
            bool modeVerify = parseResult.GetValue(verifyOpt);
            bool modeInfo = parseResult.GetValue(infoOpt);
            bool modeStatus = parseResult.GetValue(statusOpt);
            bool modeNext = parseResult.GetValue(nextOpt);
            bool modeCheck = parseResult.GetValue(checkOpt);
            bool modeDiff = parseResult.GetValue(diffOpt);

            if (!dir.Exists)
            {
                AnsiConsole.MarkupLine("[red]Error: directory not found[/]");
                return 1;
            }

            // Phase 1: Scan
            AnsiConsole.MarkupLine("[grey]Scanning for .indrdrf files...[/]");
            var searchOpt = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            var files = dir.GetFiles("*.indrdrf", searchOpt)
                .OrderByDescending(f => f.LastWriteTime)
                .ToArray();
            if (files.Length == 0)
            {
                AnsiConsole.MarkupLine("[yellow]No backup files found.[/]");
                return 0;
            }
            AnsiConsole.MarkupLine($"[green]Found {files.Length} backup(s).[/]\n");

            string FormatFileInfo(FileInfo f)
            {
                string displayName = recursive ? Path.GetRelativePath(dir.FullName, f.FullName) : f.Name;
                if (displayName.Length > 35) displayName = "..." + displayName[^32..];
                string size = f.Length < 1024 ? $"{f.Length} B" :
                    f.Length < 1024 * 1024 ? $"{f.Length / 1024.0:F1} KB" :
                    f.Length < 1024L * 1024 * 1024 ? $"{f.Length / (1024.0 * 1024):F1} MB" :
                    $"{f.Length / (1024.0 * 1024 * 1024):F2} GB";
                return $"{displayName,-50} {f.LastWriteTime:yyyy-MM-dd}  {size,8}";
            }

            // Phase 2: Selection (interactive prompt, or non-TTY auto-pick)
            if (modeDiff)
            {
                if (!AnsiConsole.Profile.Capabilities.Interactive)
                {
                    AnsiConsole.MarkupLine("[red]Error: reach -diff requires an interactive terminal.[/]");
                    return 1;
                }
                return RunDiffMode(files, FormatFileInfo, dir.FullName, recursive);
            }

            FileInfo chosenFile;
            if (!AnsiConsole.Profile.Capabilities.Interactive)
            {
                // Non-interactive (scripts/CI): use newest backup; require an action flag.
                bool hasMode = modeVerify || modeInfo || modeStatus || modeNext || modeCheck;
                if (!hasMode)
                {
                    AnsiConsole.MarkupLine("[red]Error: non-interactive reach requires one of -info/-status/-verify/-check/-next.[/]");
                    AnsiConsole.MarkupLine($"[grey]Found {files.Length} backup(s); newest: {files[0].Name}[/]");
                    return 1;
                }
                chosenFile = files[0];
                AnsiConsole.MarkupLine($"[grey]Non-interactive: using newest {chosenFile.Name}[/]\n");
            }
            else
            {
                var choices = files.Select(FormatFileInfo).ToList();
                choices.Add("--- Exit ---");

                var prompt = new SelectionPrompt<string>()
                    .Title("[cyan]Select a backup:[/]")
                    .PageSize(12)
                    .HighlightStyle(new Style(Color.Cyan1))
                    .AddChoices(choices);

                string selected = AnsiConsole.Prompt(prompt);
                if (selected.Contains("Exit"))
                    return 0;

                int idx = choices.IndexOf(selected);
                chosenFile = files[idx];
            }

            string storageDir = chosenFile.DirectoryName!;
            string fingerprint = Path.GetFileNameWithoutExtension(chosenFile.Name);

            AnsiConsole.MarkupLine($"[green]Selected:[/] {chosenFile.Name}\n");

            // Encrypted index requires password for all modes (including -info).
            byte[]? password = null;
            {
                var pwd = parseResult.GetValue(passwordOpt);
                if (pwd != null)
                    password = Encoding.UTF8.GetBytes(pwd);
                else if (AnsiConsole.Profile.Capabilities.Interactive)
                    password = PasswordProvider.ReadInteractive();
                else
                {
                    AnsiConsole.MarkupLine("[red]Error: -password required in non-interactive mode.[/]");
                    return 1;
                }
                if (password.Length == 0)
                {
                    AnsiConsole.MarkupLine("[red]Password cannot be empty.[/]");
                    return 1;
                }
            }

            try
            {
                return modeVerify ? RunVerify(fingerprint, password!, storageDir)
                     : modeInfo ? RunInfo(chosenFile.FullName, storageDir, password!)
                     : modeStatus ? RunStatus(fingerprint, password!, storageDir)
                     : modeNext ? RunNext(chosenFile, fingerprint, password!, storageDir, logger)
                     : modeCheck ? RunCheck(chosenFile.FullName, password!)
                     : RunRestore(chosenFile, fingerprint, password!, storageDir, outputDirOpt, logger);
            }
            finally
            {
                if (password != null) CryptographicOperations.ZeroMemory(password);
            }
        });
    }

    private static int RunInfo(string indexFile, string storageDir, byte[] password)
    {
        try
        {
            byte[] data = File.ReadAllBytes(indexFile);
            var storage = new LocalDSAAAdapter(storageDir);
            (byte[] aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(data, password);
            var index = IndexManager.DeserializeIndex(cbor);
            string prefix = index.CustomName ?? index.FileFingerprint;
            int fragCount = index.FragmentCount;
            long fragTotal = 0;
            for (int i = 0; i < fragCount; i++)
            {
                string fname = RDRF.Core.FragmentEngine.Frags.FragmentFilename(prefix, i);
                if (storage.FragmentExists(fname))
                    fragTotal += new FileInfo(Path.Combine(storageDir, fname)).Length;
            }
            bool hasRc = storage.RcExists(prefix);
            bool hasEtn = index.HasFss6EtnData;

            var table = new Table();
            table.Border(TableBorder.Rounded);
            table.AddColumn("Property");
            table.AddColumn(new TableColumn("Value").NoWrap());
            table.AddRow("File", index.OriginalName);
            table.AddRow("Size", $"{index.FileSize:N0} bytes");
            table.AddRow("Fingerprint", index.FileFingerprint);
            table.AddRow("Strategy", index.FssStrategy + (hasEtn ? " + FSS6" : ""));
            table.AddRow("Fragments", fragCount.ToString());
            table.AddRow("Fragment data", FileSizeFormatter.FormatBytes(fragTotal));
            table.AddRow("RC file", hasRc ? "Yes" : "No");
            if (index.VersionNumber > 0)
                table.AddRow("Versions", index.VersionNumber.ToString());
            if (index.Compression == "lz4")
                table.AddRow("Compression", "LZ4");
            table.AddRow("Created", DateTimeOffset.FromUnixTimeSeconds(index.CreatedAt).LocalDateTime.ToString("g"));
            AnsiConsole.Write(table);
            return 0;
        }
        catch { AnsiConsole.MarkupLine("[red]Error: could not read index file[/]"); return 1; }
    }

    /// <summary>
    /// fragment_hashes are post-FSS, pre-compress, pre-trailer. Strip trailers then decompress before hashing.
    /// </summary>
    private static byte[] PayloadForFragmentHash(byte[] decryptedBody, RdrfIndex index)
    {
        byte[] body = decryptedBody;
        var (raw62, _, _, _, _) = RDRF.Core.FSS.Fss62RepairTrailer.Parse(body);
        body = raw62;
        var (raw61, _, _, _, _) = RDRF.Core.FSS.Fss61RepairTrailer.Parse(body);
        body = raw61;
        body = RDRF.Core.ETN.EtnTrailer.Parse(body).RawData;

        if (!string.IsNullOrEmpty(index.Compression))
        {
            bool isCkc = string.Equals(index.Compression, "ckc", StringComparison.OrdinalIgnoreCase);
            if (isCkc)
            {
                var ckc = new RDRF.Core.Compression.Ckc.CkcAlgorithm();
                if (ckc.CanHandle(body))
                    body = ckc.Decompress(body);
            }
            else
            {
                body = RDRF.Core.Compression.Compressor.Decompress(body, index.Compression);
            }
        }
        return body;
    }

    private static int RunVerify(string fingerprint, byte[] password, string storageDir)
    {
        try
        {
            (var storage, byte[] aesKey, var index) = OpenAndDecryptIndex(fingerprint, password, storageDir);
            string prefix = index.CustomName ?? fingerprint;
            int ok = 0, bad = 0, missing = 0;

            for (int i = 0; i < index.FragmentCount; i++)
            {
                string fname = RDRF.Core.FragmentEngine.Frags.FragmentFilename(prefix, i);
                if (!storage.FragmentExists(fname)) { missing++; continue; }
                try
                {
                    byte[] encrypted = storage.ReadFragment(fname);
                    byte[] decrypted = EncryptionLayer.DecryptAndStripFragment(encrypted, aesKey);
                    byte[] body = PayloadForFragmentHash(decrypted, index);
                    string actual = IntegrityChecker.HashBytes(body);
                    string expected = index.FragmentHashes.Count > i ? index.FragmentHashes[i] : "";
                    if (IntegrityChecker.VerifyHash(actual, expected)) ok++; else bad++;
                }
                catch { bad++; }
            }

            if (bad == 0 && missing == 0)
                AnsiConsole.MarkupLine($"[green]All {ok}/{index.FragmentCount} fragments verified OK[/]");
            else
                AnsiConsole.MarkupLine($"[green]{ok} OK[/], [red]{bad} CORRUPTED[/], [yellow]{missing} MISSING[/] of {index.FragmentCount}");
            return bad > 0 || missing > 0 ? 1 : 0;
        }
        catch { AnsiConsole.MarkupLine("[red]Wrong password or corrupted index[/]"); return 1; }
    }

    private static int RunStatus(string fingerprint, byte[] password, string storageDir)
    {
        try
        {
            (var storage, byte[] aesKey, var index) = OpenAndDecryptIndex(fingerprint, password, storageDir);
            string prefix = index.CustomName ?? fingerprint;
            bool hasEtn = index.HasFss6EtnData;

            bool indexOk = storage.IndexExists(prefix);
            bool rcOk = storage.RcExists(prefix);

            var infoTable = new Table();
            infoTable.Border(TableBorder.Rounded);
            infoTable.AddColumn("Property");
            infoTable.AddColumn("Value");
            infoTable.AddRow("File", index.OriginalName);
            infoTable.AddRow("Strategy", index.FssStrategy + (hasEtn ? " + FSS6" : ""));
            infoTable.AddRow("Index", indexOk ? "[green]OK[/]" : "[yellow]MISSING[/]");
            infoTable.AddRow("RC", rcOk ? "[green]OK[/]" : "[yellow]MISSING[/]");
            AnsiConsole.Write(infoTable);
            AnsiConsole.WriteLine();

            var fragTable = new Table();
            fragTable.Border(TableBorder.Rounded);
            fragTable.AddColumn(new TableColumn("#").RightAligned());
            fragTable.AddColumn("Status");
            fragTable.AddColumn("Size");

            int ok = 0, bad = 0, missing = 0;
            for (int i = 0; i < index.FragmentCount; i++)
            {
                string fname = RDRF.Core.FragmentEngine.Frags.FragmentFilename(prefix, i);
                if (!storage.FragmentExists(fname))
                {
                    fragTable.AddRow(i.ToString(), "[yellow]MISSING[/]", "-");
                    missing++; continue;
                }
                try
                {
                    byte[] encrypted = storage.ReadFragment(fname);
                    byte[] decrypted = EncryptionLayer.DecryptAndStripFragment(encrypted, aesKey);
                    byte[] body = PayloadForFragmentHash(decrypted, index);
                    string actual = IntegrityChecker.HashBytes(body);
                    string expected = index.FragmentHashes.Count > i ? index.FragmentHashes[i] : "";
                    bool match = IntegrityChecker.VerifyHash(actual, expected);
                    string size = FileSizeFormatter.FormatBytes(body.Length);
                    if (match) { fragTable.AddRow(i.ToString(), "[green]OK[/]", size); ok++; }
                    else { fragTable.AddRow(i.ToString(), "[red]CORRUPTED[/]", size); bad++; }
                }
                catch { fragTable.AddRow(i.ToString(), "[yellow]ERROR[/]", "-"); bad++; }
            }
            AnsiConsole.Write(new Panel(fragTable).Header($"Fragments ({index.FragmentCount})").BorderColor(Color.Grey));
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine($"Summary: [green]{ok} OK[/], [red]{bad} CORRUPTED[/], [yellow]{missing} MISSING[/]");
            return bad > 0 || missing > 0 ? 1 : 0;
        }
        catch { AnsiConsole.MarkupLine("[red]Wrong password or corrupted index[/]"); return 1; }
    }

    private static (LocalDSAAAdapter storage, byte[] aesKey, RdrfIndex index) OpenAndDecryptIndex(
        string fingerprint, byte[] password, string storageDir)
    {
        var storage = new LocalDSAAAdapter(storageDir);
        byte[] encryptedIndex = storage.ReadIndex(fingerprint);
        (byte[] aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
        var index = IndexManager.DeserializeIndex(cbor);
        return (storage, aesKey, index);
    }

    private static int RunNext(FileInfo chosenFile, string fingerprint, byte[] password, string storageDir, RdrfLogger logger)
    {
        string message = AnsiConsole.Prompt(new TextPrompt<string>("Commit message:"));
        try
        {
            var storage = new LocalDSAAAdapter(storageDir);
            string fp = Task.Run(() => VersionedBackup.BackupAsync(chosenFile.FullName, storage, password,
                message, ct: CancellationToken.None)).GetAwaiter().GetResult();
            AnsiConsole.MarkupLine($"[green]Versioned backup created:[/] {fp}");
            return 0;
        }
        catch (CryptographicException)
        {
            AnsiConsole.MarkupLine("[red]Wrong password[/]");
            return 1;
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]{ex.Message.EscapeMarkup()}[/]");
            return 1;
        }
    }

    private static int RunCheck(string indexFile, byte[] password)
    {
        try
        {
            byte[] encryptedIndex = File.ReadAllBytes(indexFile);
            (byte[] aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
            var index = IndexManager.DeserializeIndex(cbor);

            if (index.Versions == null || index.Versions.Count == 0)
            {
                AnsiConsole.MarkupLine("[yellow]No version history found.[/]");
                return 0;
            }

            var table = new Table();
            table.Border(TableBorder.Rounded);
            table.AddColumn(new TableColumn("Ver").RightAligned());
            table.AddColumn("Fingerprint");
            table.AddColumn("Message");
            table.AddColumn("Date");
            foreach (var v in index.Versions.OrderByDescending(v => v.Version))
            {
                string date = DateTimeOffset.FromUnixTimeSeconds(v.CreatedAt).LocalDateTime.ToString("g");
                string fp = v.FileFingerprint;
                string shortFp = fp.Length > 24 ? $"{fp[..12]}...{fp[^8..]}" : fp;
                table.AddRow(v.Version.ToString(), shortFp, v.UserMessage.EscapeMarkup(), date);
            }
            AnsiConsole.Write(new Panel(table).Header("Version History").BorderColor(Color.Grey));
            return 0;
        }
        catch { AnsiConsole.MarkupLine("[red]Wrong password or corrupted index[/]"); return 1; }
    }

    private static int RunDiffMode(FileInfo[] files, Func<FileInfo, string> formatFileInfo,
        string baseDir, bool recursive)
    {
        var choices = files.Select(formatFileInfo).ToList();
        choices.Add("--- Exit ---");

        var prompt1 = new SelectionPrompt<string>()
            .Title("[cyan]Select [green]first[/] backup (A):[/]")
            .PageSize(12)
            .HighlightStyle(new Style(Color.Green))
            .AddChoices(choices);

        string selA = AnsiConsole.Prompt(prompt1);
        if (selA.Contains("Exit")) return 0;
        int idxA = choices.IndexOf(selA);
        var fileA = files[idxA];
        choices.RemoveAt(idxA);

        var prompt2 = new SelectionPrompt<string>()
            .Title("[cyan]Select [red]second[/] backup (B):[/]")
            .PageSize(12)
            .HighlightStyle(new Style(Color.Red))
            .AddChoices(choices);

        string selB = AnsiConsole.Prompt(prompt2);
        if (selB.Contains("Exit")) return 0;
        int idxB = choices.IndexOf(selB);
        var fileB = files[idxB];

        string storageDirA = fileA.DirectoryName!;
        string storageDirB = fileB.DirectoryName!;
        string fpA = Path.GetFileNameWithoutExtension(fileA.Name);
        string fpB = Path.GetFileNameWithoutExtension(fileB.Name);

        // Try same password for both
        byte[] password = PasswordProvider.ReadInteractive("Password (for both backups):");
        if (password.Length == 0) { AnsiConsole.MarkupLine("[red]Password cannot be empty.[/]"); return 1; }

        try
        {
            var storageA = new LocalDSAAAdapter(storageDirA);
            var storageB = new LocalDSAAAdapter(storageDirB);
            byte[] encIdxA = storageA.ReadIndex(fpA);
            byte[] encIdxB = storageB.ReadIndex(fpB);
            (byte[] _, byte[] cborA) = EncryptionLayer.DecryptIndexWithAutoDetect(encIdxA, password);
            (byte[] _, byte[] cborB) = EncryptionLayer.DecryptIndexWithAutoDetect(encIdxB, password);
            var idxAObj = IndexManager.DeserializeIndex(cborA);
            var idxBObj = IndexManager.DeserializeIndex(cborB);

            var table = new Table();
            table.Border(TableBorder.Rounded);
            table.AddColumn(new TableColumn("[green][A][/] " + fileA.Name).NoWrap());
            table.AddColumn("Property");
            table.AddColumn(new TableColumn("[red][B][/] " + fileB.Name).NoWrap());
            string v = idxAObj.FileFingerprint; string shortA = v.Length > 24 ? $"{v[..12]}...{v[^8..]}" : v;
            v = idxBObj.FileFingerprint; string shortB = v.Length > 24 ? $"{v[..12]}...{v[^8..]}" : v;
            table.AddRow(shortA, "Fingerprint", shortB);
            table.AddRow(idxAObj.OriginalName, "File", idxBObj.OriginalName);
            table.AddRow(idxAObj.FssStrategy!, "Strategy", idxBObj.FssStrategy!);
            table.AddRow(idxAObj.FragmentCount.ToString(), "Fragments", idxBObj.FragmentCount.ToString());
            table.AddRow($"{idxAObj.FileSize:N0}", "Size", $"{idxBObj.FileSize:N0}");
            table.AddRow(DateTimeOffset.FromUnixTimeSeconds(idxAObj.CreatedAt).LocalDateTime.ToString("g"), "Created",
                DateTimeOffset.FromUnixTimeSeconds(idxBObj.CreatedAt).LocalDateTime.ToString("g"));
            if (idxAObj.VersionNumber > 0 || idxBObj.VersionNumber > 0)
                table.AddRow((idxAObj.VersionNumber ?? 0).ToString(), "Versions", (idxBObj.VersionNumber ?? 0).ToString());
            AnsiConsole.Write(table);
            return 0;
        }
        catch { AnsiConsole.MarkupLine("[red]Wrong password or corrupted index for one of the backups[/]"); return 1; }
    }

    private static int RunRestore(FileInfo chosenFile, string fingerprint, byte[] password,
        string storageDir, DirectoryInfo? outputDirOpt, RdrfLogger logger)
    {
        string outputPath = outputDirOpt != null
            ? Path.Combine(outputDirOpt.FullName, Path.GetFileNameWithoutExtension(chosenFile.Name))
            : Path.Combine(chosenFile.DirectoryName!, "res", Path.GetFileNameWithoutExtension(chosenFile.Name));
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);

        bool ok = false;
        AnsiConsole.Progress()
            .Columns(new ProgressColumn[]
            {
                new TaskDescriptionColumn(), new ProgressBarColumn(),
                new PercentageColumn(), new RemainingTimeColumn(),
            })
            .Start(ctx =>
            {
                var task = ctx.AddTask("Decrypting index...");
                task.Value = 10;
                try
                {
                    using var engine = new RDRFEngine(password, new LocalDSAAAdapter(storageDir), logger: logger);
                    var progress = new Progress<RdrfProgressReport>(r =>
                    {
                        if (r.TotalBytes > 0) task.Value = (double)r.CurrentBytes / r.TotalBytes * 100;
                        task.Description = r.Stage;
                    });
                    task.Description = "Decrypting index...";
                    task.Value = 30;
                    ok = engine.RestoreFile(fingerprint, outputPath, progress: progress);
                    task.Value = ok ? 100 : 0;
                    task.Description = ok ? "[green]Complete![/]" : "[red]Failed[/]";
                }
                catch (CryptographicException) { task.Description = "[red]Wrong password[/]"; }
                catch (Exception ex) { task.Description = "[red]Error[/]"; AnsiConsole.MarkupLine($"\n[red]{ex.Message.EscapeMarkup()}[/]"); }
            });

        if (ok)
        {
            AnsiConsole.MarkupLine($"\n[green]Restored to:[/] {outputPath}");
            long size = new FileInfo(outputPath).Length;
            AnsiConsole.MarkupLine($"[green]Size:[/] {FileSizeFormatter.FormatBytes(size)}");
        }
        else
            AnsiConsole.MarkupLine("\n[red]Restore failed.[/]");
        return 0;
    }
}
