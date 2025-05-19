using RDRF.Core;
using RDRF.Core.Storage;
using RDRF.Cli.Services;
using System.CommandLine;
using System.Text;

namespace RDRF.Cli.Commands;

public class RestoreCommand : Command
{
    public RestoreCommand() : base("res", "Restore a backup from its index file")
    {
        var indexArg = new Argument<FileInfo>("indexFile");
        var outputOpt = new Option<FileInfo>("-o") { Description = "Output file path" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password (skip interactive prompt)" };

        Arguments.Add(indexArg);
        Options.Add(outputOpt);
        Options.Add(passwordOpt);

        SetAction(async (ParseResult parseResult) =>
        {
            var indexFile = parseResult.GetValue(indexArg);
            var output = parseResult.GetValue(outputOpt);
            var pwd = parseResult.GetValue(passwordOpt);

            if (!indexFile.Exists)
            {
                Console.Error.WriteLine($"Error: index file not found: {indexFile.FullName}");
                return 1;
            }
            if (output == null)
            {
                Console.Error.WriteLine("Error: -o <outputPath> is required");
                return 1;
            }

            byte[] password = pwd != null ? Encoding.UTF8.GetBytes(pwd) : PasswordProvider.ReadInteractive();
            if (password.Length == 0)
            {
                Console.Error.WriteLine("Error: password cannot be empty");
                return 1;
            }

            string storageDir = indexFile.DirectoryName!;
            byte[] encryptedIndex = File.ReadAllBytes(indexFile.FullName);

            var storage = new LocalFileAdapter(storageDir);
            using var engine = new RDRFEngine(password, storage);

            var index = RDRFEngine.DecryptIndex(encryptedIndex, password);
            string prefix = index.CustomName ?? index.FileFingerprint;

            bool success = false;
            await ProgressReporter.Run($"Restoring {index.OriginalName}", async progress =>
            {
                success = await engine.RestoreFileAsync(index.FileFingerprint, output.FullName, filePrefix: prefix, progress: progress);
            });

            if (success)
            {
                Console.WriteLine($"Restored to: {output.FullName}");
                return 0;
            }
            Console.Error.WriteLine("Error: restore failed");
            return 1;
        });
    }
}
