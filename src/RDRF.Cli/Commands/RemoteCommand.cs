using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Storage;
using RDRF.Cli.Services;
using System.CommandLine;

namespace RDRF.Cli.Commands;

public class RemoteCommand : Command
{
    public RemoteCommand() : base("remote", "Register a backup project and bind storage backends")
    {
        var indexArg = new Argument<FileInfo>("indexFile") { Description = "Path to the .indrdrf index file" };
        var addOpt = new Option<string[]>("-add") { Description = "Backend name(s) to add (space-separated)", AllowMultipleArgumentsPerToken = true };
        var removeOpt = new Option<string>("-remove") { Description = "Backend name to remove" };

        Add(indexArg);
        Add(addOpt);
        Add(removeOpt);

        SetAction((ParseResult parseResult) =>
        {
            var indexFile = parseResult.GetValue(indexArg);
            var addBackends = parseResult.GetValue(addOpt);
            var removeBackend = parseResult.GetValue(removeOpt);

            if (!indexFile.Exists)
            {
                Console.Error.WriteLine($"Error: index file not found: {indexFile.FullName}");
                return 1;
            }

            if ((addBackends == null || addBackends.Length == 0) && string.IsNullOrEmpty(removeBackend))
            {
                Console.Error.WriteLine("Error: specify -add <backends...> or -remove <backend>");
                return 1;
            }

            byte[] encryptedIndex = File.ReadAllBytes(indexFile.FullName);
            byte[] password = PasswordProvider.ReadInteractive();
            if (password == null || password.Length == 0)
            {
                Console.Error.WriteLine("Error: password is required");
                return 1;
            }

            try
            {
                (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
                var index = IndexManager.DeserializeIndex(cbor);
                string fingerprint = index.FileFingerprint;
                string storageDir = indexFile.DirectoryName!;

                var mgmt = new ManagementFile(storageDir);

                if (addBackends != null && addBackends.Length > 0)
                {
                    foreach (var be in addBackends)
                    {
                        mgmt.RecordRemote(be, be,
                            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));
                        Console.WriteLine($"  Backend '{be}' bound to project {fingerprint}");
                    }
                }

                if (!string.IsNullOrEmpty(removeBackend))
                {
                    mgmt.DeleteRemote(removeBackend);
                    Console.WriteLine($"  Backend '{removeBackend}' unbound from project {fingerprint}");
                }

                Console.WriteLine($"Project '{fingerprint}' registered in management file");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                return 1;
            }
        });
    }
}
