using RDRF.Core;
using RDRF.Core.DSAA;
using RDRF.Core.Logging;
using RDRF.Core.PasswordManager;
using RDRF.Core.Versioning;
using RDRF.Cli.Services;
using Spectre.Console;
using System.CommandLine;
using System.Security.Cryptography;
using System.Text;

namespace RDRF.Cli.Commands;

/// <summary>
/// Backup a file or directory with FSS strategy selection. CLI: rdrf backup.
/// </summary>

public class BackupCommand : Command
{
    private readonly PasswordManager _passwordManager;
    private readonly RdrfLogger _logger;

    public BackupCommand(PasswordManager passwordManager, RdrfLogger logger) : base("backup", "Backup a file or directory to RDRF storage")
    {
        _passwordManager = passwordManager;
        _logger = logger;

        var sourceArg = new Argument<FileSystemInfo>("source") { Description = "File or directory path to backup" };
        var outputOpt = new Option<DirectoryInfo?>("-o") { Description = "Storage directory (default: ./backup/ when omitted)" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password as plain text (INSECURE: visible in process list; omit for secure prompt)" };
        var fpOpt = new Option<string?>("-fp") { Description = "FastPassword key (use instead of -password)" };
        var sizeOpt = new Option<int?>("-size") { Description = "Fragment size in MB (default: 1)" };
        var nameOpt = new Option<string?>("-name") { Description = "Custom name for the backup (optional)" };
        var nextOpt = new Option<bool>("-next", "--next") { Description = "Enable versioning (creates v1, supports 'rdrf next' for increments)" };
        var nodeOpt = new Option<bool>("-node", "--node") { Description = "Versioned backup with API distribution flag (use with rdrf remote + push)" };
        var gcOpt = new Option<bool>("-gc", "--gc") { Description = "Legacy GC mode: cleanup orphaned indexes between versions" };
        var messageOpt = new Option<string?>("-m") { Description = "Commit message for the initial version (used with -next or -node)" };
        var fss1 = new Option<bool>("-fss1", new[] { "--fss1" }) { Description = "FSS1 strategy" };
        var fss2 = new Option<bool>("-fss2", new[] { "--fss2" }) { Description = "FSS2 strategy" };
        var fss2r = new Option<bool>("-fss2r", new[] { "--fss2r" }) { Description = "FSS2R strategy" };
        var fss3 = new Option<bool>("-fss3", new[] { "--fss3" }) { Description = "FSS3 strategy - Reed-Solomon encoding" };
        var fss5 = new Option<bool>("-fss5", new[] { "--fss5" }) { Description = "FSS5 strategy" };
        var fss5p = new Option<bool>("-fss5+", new[] { "--fss5+" }) { Description = "FSS5+ strategy" };
        // Plain FSS6 (ETN validation only). Avoid "-fss6.1" as primary: SCL can split on '.'.
        // Prefer -fss61 / --fss6.1 (and same for 6.2).
        var fss6 = new Option<bool>("-fss6", new[] { "--fss6" })
            { Description = "FSS6 strategy - ETN cross-validation only" };
        var fss61 = new Option<bool>("-fss61", new[] { "--fss61", "--fss6.1", "-fss6.1" })
            { Description = "FSS6.1 strategy - ETN + LT fountain repair (alias: --fss6.1)" };
        var fss62 = new Option<bool>("-fss62", new[] { "--fss62", "--fss6.2", "-fss6.2" })
            { Description = "FSS6.2 strategy - ETN + Duip fountain repair (alias: --fss6.2)" };
        var compressionOpt = new Option<string[]>("-c")
        {
            Description = "Compression method and options. Values: lz4, lz4hc, zstd, gzip, brotli, lzma2, lzo, xz, ckc. e.g. -c zstd 5",
            Arity = new ArgumentArity(1, 2),
            AllowMultipleArgumentsPerToken = true
        };
        // FSA multi-strategy fusion is temporarily disabled. Single-strategy mode only.
        // var fsaOpt = new Option<bool>("-fsa") { Description = "Enable multi-strategy FSA fusion mode (used with multiple --fss options)" };

        Arguments.Add(sourceArg);
        Options.Add(outputOpt);
        Options.Add(passwordOpt);
        Options.Add(fpOpt);
        Options.Add(sizeOpt);
        Options.Add(nameOpt);
        Options.Add(messageOpt);
        Add(fss1); Add(fss2); Add(fss2r);
        Add(fss3); Add(fss5); Add(fss5p); Add(fss6); Add(fss61); Add(fss62);
        Add(nextOpt); Add(nodeOpt); Add(gcOpt);
        Add(compressionOpt);

        SetAction(async (ParseResult parseResult, CancellationToken ct) =>
        {
            var source = parseResult.GetValue(sourceArg);
            var outputDir = parseResult.GetValue(outputOpt);
            var pwd = parseResult.GetValue(passwordOpt);
            var fpKey = parseResult.GetValue(fpOpt);
            var sizeMb = parseResult.GetValue(sizeOpt);
            var customName = parseResult.GetValue(nameOpt);
            bool enableNext = parseResult.GetValue(nextOpt);
            bool enableNode = parseResult.GetValue(nodeOpt);
            var commitMsg = parseResult.GetValue(messageOpt);
            var flags = new[]
            {
                (parseResult.GetValue(fss1), Constants.FssLevel1),
                (parseResult.GetValue(fss2), Constants.FssLevel2),
                (parseResult.GetValue(fss2r), Constants.FssLevel2R),
                (parseResult.GetValue(fss3), Constants.FssLevel3),
                (parseResult.GetValue(fss5), Constants.FssLevel5),
                (parseResult.GetValue(fss5p), Constants.FssLevel5P),
                (parseResult.GetValue(fss6), Constants.FssLevel6),
                (parseResult.GetValue(fss61), Constants.FssLevel61),
                (parseResult.GetValue(fss62), Constants.FssLevel62),
            };
            var selected = flags.Where(x => x.Item1).Select(x => x.Item2).ToList();

            if (selected.Count < 1)
            {
                AnsiConsole.MarkupLine("[red]Error: at least one -fss<level> option is required[/]");
                return 1;
            }

            string strategy;
            List<string>? auxiliary = null;

            if (selected.Count != 1)
            {
                AnsiConsole.MarkupLine("[red]Error: only one -fss<level> option allowed (single-strategy mode only)[/]");
                return 1;
            }
            strategy = selected[0];

            var compArgs = parseResult.GetValue(compressionOpt);
            string? compressionMethod = null;
            string? compressionOptions = null;
            if (compArgs is { Length: > 0 })
            {
                compressionMethod = compArgs[0];
                compressionOptions = compArgs.Length > 1 ? compArgs[1] : null;
            }

            if (fpKey != null && pwd != null)
            {
                AnsiConsole.MarkupLine("[red]Error: -fp and -password cannot be used together[/]");
                return 1;
            }

            byte[] password;
            string? usedFpKey = null;
            if (fpKey != null)
            {
                
                string? stored = _passwordManager.GetByKey(fpKey);
                if (stored == null)
                {
                    AnsiConsole.MarkupLine($"[red]Error: FastPassword '{fpKey}' not found. Use 'rdrf fp set {fpKey}' first to store it (interactive prompt).[/]");
                    return 1;
                }
                password = Encoding.UTF8.GetBytes(stored);
                usedFpKey = fpKey;
            }
            else
            {
                password = pwd != null ? Encoding.UTF8.GetBytes(pwd) : PasswordProvider.ReadInteractive();
            }
            if (password.Length == 0)
            {
                AnsiConsole.MarkupLine("[red]Error: password cannot be empty[/]");
                return 1;
            }

            try
            {
            string storagePath = outputDir?.FullName ?? (enableNode ? ".rdrf" : Path.Combine(AppContext.BaseDirectory, "backup"));
            int fragmentSize = sizeMb.HasValue ? sizeMb.Value * 1024 * 1024 : 0;

            if (enableNext || enableNode)
            {
                if (source is not FileInfo)
                {
                    AnsiConsole.MarkupLine("[red]Error: -next and -node are only supported for single-file backups[/]");
                    return 1;
                }

                var nf = (FileInfo)source;
                string fp = "";
                string mode = enableNode ? "node" : "versioned";
                await ProgressReporter.Run($"Backing up {nf.Name}", async prog =>
                {
                    fp = await VersionedBackup.BackupAsync(nf.FullName, new LocalDSAAAdapter(storagePath), password,
                            commitMsg ?? "Initial backup", strategy, fragmentSize, customName, auxiliary, prog, ct: ct,
                            compressionMethod: compressionMethod, compressionOptions: compressionOptions,
                            gcMode: parseResult.GetValue(gcOpt));
                });
                var resultTable = new Table();
                resultTable.Border(TableBorder.Rounded);
                resultTable.AddColumn("Property");
                resultTable.AddColumn(new TableColumn("Value").NoWrap());
                resultTable.AddRow("Fingerprint", fp.Length > 32 ? $"{fp[..12]}...{fp[^8..]}" : fp);
                resultTable.AddRow("Strategy", $"{strategy} ({mode})");
                if (enableNode)
                    resultTable.AddRow("Remote", $"rdrf remote {fp}.indrdrf -add <backends>");
                if (fp.Length > 0 && Directory.Exists(storagePath))
                {
                    long fragTotal = 0; int fragCount = 0;
                    foreach (var f in Directory.GetFiles(storagePath, $"{fp}_*.rdrf"))
                    { fragTotal += new FileInfo(f).Length; fragCount++; }
                    string? rcPath = Directory.GetFiles(storagePath, $"{fp}.rdrc").FirstOrDefault();
                    long rcSize = rcPath != null ? new FileInfo(rcPath).Length : 0;
                    resultTable.AddRow("Fragments", $"{fragCount} ({BackupHelpers.FormatSize(fragTotal)})");
                    if (rcSize > 0)
                        resultTable.AddRow("Repair data", BackupHelpers.FormatSize(rcSize));
                }
                AnsiConsole.Write(resultTable);
                return 0;
            }

            var storage = new LocalDSAAAdapter(storagePath);
            using (var engine = new RDRFEngine(password, storage, fssEngine: null, logger: _logger))
            {
                int count = 0;
                string? firstFp = null;

                if (source is FileInfo file)
                {
                    await ProgressReporter.Run($"Backing up {file.Name}", async progress =>
                    {
                        firstFp = await engine.BackupFileAsync(file.FullName, strategy,
                            fragmentSize: fragmentSize, customName: customName, auxiliaryStrategies: auxiliary,
                            progress: progress, cancellationToken: ct,
                            compressionMethod: compressionMethod, compressionOptions: compressionOptions);
                    });
                    count = 1;
                }
                else if (source is DirectoryInfo dir)
                {
                    var files = dir.EnumerateFiles("*", SearchOption.AllDirectories).ToList();
                    await AnsiConsole.Progress()
                        .Columns(new ProgressColumn[]
                        {
                            new TaskDescriptionColumn(),
                            new ProgressBarColumn(),
                            new PercentageColumn(),
                            new ElapsedTimeColumn(),
                        })
                        .StartAsync(async ctx =>
                        {
                            var task = ctx.AddTask($"Backing up {files.Count} files");
                            task.MaxValue = files.Count;
                            foreach (var f in files)
                            {
                                var fp = await engine.BackupFileAsync(f.FullName, strategy,
                                    fragmentSize: fragmentSize, customName: customName, auxiliaryStrategies: auxiliary, cancellationToken: ct,
                                    compressionMethod: compressionMethod, compressionOptions: compressionOptions);
                                firstFp ??= fp;
                                count++;
                                task.Value = count;
                                task.Description = $"{f.Name} ({count}/{files.Count})";
                            }
                        });
                }

                var resultTable = new Table();
                resultTable.Border(TableBorder.Rounded);
                resultTable.AddColumn("Property");
                resultTable.AddColumn(new TableColumn("Value").NoWrap());
                string fp = firstFp ?? "";
                // On-disk prefix is customName when -name is set; fingerprint alone is wrong for lookups.
                string filePrefix = !string.IsNullOrEmpty(customName) ? customName : fp;
                resultTable.AddRow("Fingerprint", fp.Length > 32 ? $"{fp[..12]}...{fp[^8..]}" : fp);
                if (!string.IsNullOrEmpty(customName))
                    resultTable.AddRow("Name", customName);
                resultTable.AddRow("Strategy", strategy);

                // Storage statistics (prefix-aware for -name)
                if (!string.IsNullOrEmpty(filePrefix) && Directory.Exists(storagePath))
                {
                    long fragTotal = 0; int fragCount = 0;
                    foreach (var f in Directory.GetFiles(storagePath, $"{filePrefix}_*.rdrf"))
                    {
                        fragTotal += new FileInfo(f).Length;
                        fragCount++;
                    }
                    string? rcPath = Directory.GetFiles(storagePath, $"{filePrefix}.rdrc")
                        .FirstOrDefault();
                    long rcSize = rcPath != null ? new FileInfo(rcPath).Length : 0;
                    string indexPath = Path.Combine(storagePath, filePrefix + Constants.IndexFileSuffix);
                    if (!File.Exists(indexPath))
                        indexPath = Path.Combine(storagePath, fp + Constants.IndexFileSuffix);
                    long idxSize = File.Exists(indexPath) ? new FileInfo(indexPath).Length : 0;

                    resultTable.AddRow("Fragments", $"{fragCount} ({BackupHelpers.FormatSize(fragTotal)})");
                    if (rcSize > 0)
                        resultTable.AddRow("Repair data", BackupHelpers.FormatSize(rcSize));
                    if (idxSize > 0)
                        resultTable.AddRow("Index", BackupHelpers.FormatSize(idxSize));
                }

                AnsiConsole.Write(resultTable);

                // Attach index hash for FastPassword
                if (usedFpKey != null && !string.IsNullOrEmpty(filePrefix))
                {
                    string indexPath = Path.Combine(storagePath, filePrefix + Constants.IndexFileSuffix);
                    if (!File.Exists(indexPath) && !string.IsNullOrEmpty(fp))
                        indexPath = Path.Combine(storagePath, fp + Constants.IndexFileSuffix);
                    if (File.Exists(indexPath))
                    {
                        string indexHash = HashHelper.ComputeSha256Hex(indexPath);
                        _passwordManager.AttachHash(usedFpKey, indexHash);
                    }
                }
            }

            return 0;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(password);
            }
        });
    }
}

internal static class BackupHelpers
{
    public static string FormatSize(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
        return $"{bytes / (1024.0 * 1024 * 1024):F2} GB";
    }
}







