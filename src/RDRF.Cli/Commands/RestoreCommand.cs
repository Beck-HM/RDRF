using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Core.Storage;
using RDRF.Cli.Services;
using System.CommandLine;
using System.Text;

namespace RDRF.Cli.Commands;

public class RestoreCommand : Command
{
    public RestoreCommand() : base("res", "Restore a backup from its index file")
    {
        var indexArg = new Argument<FileInfo>("indexFile") { Description = "Path to the .indrdrf index file" };
        var outputOpt = new Option<FileInfo>("-o") { Description = "Output file path for the restored data (required)" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password as plain text (omit for interactive prompt)" };

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

            try
            {
                (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
                var index = IndexManager.DeserializeIndex(cbor);
                string prefix = index.CustomName ?? index.FileFingerprint;

                bool success = false;
                try
                {
                    await ProgressReporter.Run($"Restoring {index.OriginalName}", async progress =>
                    {
                        success = await engine.RestoreFileAsync(index.FileFingerprint, output.FullName, filePrefix: prefix, progress: progress);
                    });
                }
                catch (System.Security.Cryptography.AuthenticationTagMismatchException)
                {
                    Console.Error.WriteLine("Error: wrong password or corrupt index file");
                    return 1;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Error: {ex.Message}");
                    return 1;
                }

                if (success)
                {
                    Console.WriteLine($"Restored to: {output.FullName}");
                    return 0;
                }
                Console.Error.WriteLine("Error: restore failed (data may be corrupted)");
                return 1;
            }
            catch (System.Security.Cryptography.AuthenticationTagMismatchException)
            {
                Console.Error.WriteLine("Error: wrong password or corrupt index file");
                return 1;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                return 1;
            }
        });
    }
}
