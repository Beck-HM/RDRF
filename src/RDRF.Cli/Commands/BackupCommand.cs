using RDRF.Core;
using RDRF.Core.Storage;
using RDRF.Cli.Services;
using Spectre.Console;
using System.CommandLine;
using System.Text;

namespace RDRF.Cli.Commands;

public class BackupCommand : Command
{
    public BackupCommand() : base("backup", "Backup a file or directory")
    {
        var sourceArg = new Argument<FileSystemInfo>("source");
        var outputOpt = new Option<DirectoryInfo?>("-o") { Description = "Storage directory (default: ./backup/)" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password (skip interactive prompt)" };
        var sizeOpt = new Option<int?>("-size") { Description = "Fragment size in MB (default: 1)" };
        var nameOpt = new Option<string?>("-name") { Description = "Custom name for the backup" };
        var fss1 = new Option<bool>("--fss1") { Description = "FSS1 strategy" };
        var fss2 = new Option<bool>("--fss2") { Description = "FSS2 strategy" };
        var fss2r = new Option<bool>("--fss2r") { Description = "FSS2R strategy" };
        var fss3 = new Option<bool>("--fss3") { Description = "FSS3 strategy" };
        var fss5 = new Option<bool>("--fss5") { Description = "FSS5 strategy" };
        var fss5p = new Option<bool>("--fss5+") { Description = "FSS5+ strategy" };
        var fsaOpt = new Option<bool>("-fsa") { Description = "Enable multi-strategy FSA fusion mode" };

        Arguments.Add(sourceArg);
        Options.Add(outputOpt);
        Options.Add(passwordOpt);
        Options.Add(sizeOpt);
        Options.Add(nameOpt);
        Add(fss1); Add(fss2); Add(fss2r);
        Add(fss3); Add(fss5); Add(fss5p);
        Add(fsaOpt);

        SetAction(async (ParseResult parseResult) =>
        {
            var source = parseResult.GetValue(sourceArg);
            var outputDir = parseResult.GetValue(outputOpt);
            var pwd = parseResult.GetValue(passwordOpt);
            var sizeMb = parseResult.GetValue(sizeOpt);
            var customName = parseResult.GetValue(nameOpt);
            bool fsaMode = parseResult.GetValue(fsaOpt);

            var flags = new[]
            {
                (parseResult.GetValue(fss1), Constants.FssLevel1),
                (parseResult.GetValue(fss2), Constants.FssLevel2),
                (parseResult.GetValue(fss2r), Constants.FssLevel2R),
                (parseResult.GetValue(fss3), Constants.FssLevel3),
                (parseResult.GetValue(fss5), Constants.FssLevel5),
                (parseResult.GetValue(fss5p), Constants.FssLevel5P),
            };
            var selected = flags.Where(x => x.Item1).Select(x => x.Item2).ToList();

            if (selected.Count < 1)
            {
                Console.Error.WriteLine("Error: at least one -fss<level> option is required");
                return 1;
            }

            string strategy;
            List<string>? auxiliary = null;

            if (fsaMode)
            {
                strategy = selected[0];
                if (selected.Count > 1)
                    auxiliary = selected.Skip(1).ToList();
            }
            else
            {
                if (selected.Count != 1)
                {
                    Console.Error.WriteLine("Error: single-strategy mode requires exactly one -fss<level> (use -fsa for multi-strategy)");
                    return 1;
                }
                strategy = selected[0];
            }
            byte[] password = pwd != null ? Encoding.UTF8.GetBytes(pwd) : PasswordProvider.ReadInteractive();
            if (password.Length == 0)
            {
                Console.Error.WriteLine("Error: password cannot be empty");
                return 1;
            }

            string storagePath = outputDir?.FullName ?? Path.Combine(AppContext.BaseDirectory, "backup");
            var storage = new LocalFileAdapter(storagePath);

            int fragmentSize = sizeMb.HasValue ? sizeMb.Value * 1024 * 1024 : 0;

            using var engine = new RDRFEngine(password, storage);
            int count = 0;
            string? firstFp = null;

            if (source is FileInfo file)
            {
                await ProgressReporter.Run($"Backing up {file.Name}", async progress =>
                {
                    firstFp = await engine.BackupFileAsync(file.FullName, strategy,
                        fragmentSize: fragmentSize, customName: customName, auxiliaryStrategies: auxiliary, progress: progress);
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
                                fragmentSize: fragmentSize, customName: customName, auxiliaryStrategies: auxiliary);
                            firstFp ??= fp;
                            count++;
                            task.Value = count;
                            task.Description = $"{f.Name} ({count}/{files.Count})";
                        }
                    });
            }

            Console.WriteLine($"Fingerprint: {firstFp}");
            Console.WriteLine($"Strategy: {strategy}");
            if (count > 1) Console.WriteLine($"Backed up {count} files");
            return 0;
        });
    }
}
