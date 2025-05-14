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
        var passwordOpt = new Option<string?>("-password", "Password (skip interactive prompt)");
        var fss1 = new Option<bool>("--fss1") { Description = "FSS1 strategy" };
        var fss2 = new Option<bool>("--fss2") { Description = "FSS2 strategy" };
        var fss2r = new Option<bool>("--fss2r") { Description = "FSS2R strategy" };
        var fss3 = new Option<bool>("--fss3") { Description = "FSS3 strategy" };
        var fss5 = new Option<bool>("--fss5") { Description = "FSS5 strategy" };
        var fss5p = new Option<bool>("--fss5+") { Description = "FSS5+ strategy" };

        Arguments.Add(sourceArg);
        Options.Add(outputOpt);
        Options.Add(passwordOpt);
        Add(fss1); Add(fss2); Add(fss2r);
        Add(fss3); Add(fss5); Add(fss5p);

        SetAction(async (ParseResult parseResult) =>
        {
            var source = parseResult.GetValue(sourceArg);
            var outputDir = parseResult.GetValue(outputOpt);
            var pwd = parseResult.GetValue(passwordOpt);

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

            if (selected.Count != 1)
            {
                Console.Error.WriteLine("Error: exactly one -fss<level> option is required (--fss1, --fss2, --fss2r, --fss3, --fss5, --fss5+)");
                return 1;
            }
            string strategy = selected[0];
            byte[] password = pwd != null ? Encoding.UTF8.GetBytes(pwd) : PasswordProvider.ReadInteractive();

            string storagePath = outputDir?.FullName ?? Path.Combine(AppContext.BaseDirectory, "backup");
            var storage = new LocalFileAdapter(storagePath);

            using var engine = new RDRFEngine(password, storage);
            int count = 0;
            string? firstFp = null;

            if (source is FileInfo file)
            {
                await ProgressReporter.Run($"Backing up {file.Name}", async progress =>
                {
                    firstFp = await engine.BackupFileAsync(file.FullName, strategy, progress: progress);
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
                            var fp = await engine.BackupFileAsync(f.FullName, strategy);
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
