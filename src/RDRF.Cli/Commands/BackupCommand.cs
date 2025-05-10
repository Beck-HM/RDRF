using RDRF.Core;
using RDRF.Core.Storage;
using RDRF.Cli.Services;
using System.CommandLine;

namespace RDRF.Cli.Commands;

public class BackupCommand : Command
{
    public BackupCommand() : base("backup", "Backup a file or directory")
    {
        var sourceArg = new Argument<FileSystemInfo>("source");
        var outputOpt = new Option<DirectoryInfo?>("-o") { Description = "Storage directory (default: ./backup/)" };
        var fss1 = new Option<bool>("--fss1") { Description = "FSS1 strategy" };
        var fss2 = new Option<bool>("--fss2") { Description = "FSS2 strategy" };
        var fss2r = new Option<bool>("--fss2r") { Description = "FSS2R strategy" };
        var fss3 = new Option<bool>("--fss3") { Description = "FSS3 strategy" };
        var fss5 = new Option<bool>("--fss5") { Description = "FSS5 strategy" };
        var fss5p = new Option<bool>("--fss5+") { Description = "FSS5+ strategy" };

        Arguments.Add(sourceArg);
        Options.Add(outputOpt);
        Add(fss1); Add(fss2); Add(fss2r);
        Add(fss3); Add(fss5); Add(fss5p);

        SetAction((ParseResult parseResult) =>
        {
            var source = parseResult.GetValue(sourceArg);
            var outputDir = parseResult.GetValue(outputOpt);

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

            string storagePath = outputDir?.FullName ?? Path.Combine(AppContext.BaseDirectory, "backup");
            var storage = new LocalFileAdapter(storagePath);
            byte[] password = PasswordProvider.ReadInteractive();

            using var engine = new RDRFEngine(password, storage);
            int count = 0;
            string? firstFp = null;

            if (source is FileInfo file)
            {
                firstFp = engine.BackupFile(file.FullName, strategy);
                count = 1;
            }
            else if (source is DirectoryInfo dir)
            {
                foreach (var f in dir.EnumerateFiles("*", SearchOption.AllDirectories))
                {
                    var fp = engine.BackupFile(f.FullName, strategy);
                    firstFp ??= fp;
                    count++;
                }
            }

            Console.WriteLine($"Fingerprint: {firstFp}");
            Console.WriteLine($"Strategy: {strategy}");
            if (count > 1) Console.WriteLine($"Backed up {count} files");
            return 0;
        });
    }
}
