using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Dssa;
using System.CommandLine;

namespace RDRF.Cli.Commands;

public class RemoteCommand : Command
{
    public RemoteCommand() : base("remote", "Register a backup project and bind storage backends")
    {
        var indexArg = new Argument<FileInfo>("indexFile") { Description = "Path to the .indrdrf index file" };
        var addOpt = new Option<string[]>("-add") { Description = "Backend name(s) to add (space-separated)", AllowMultipleArgumentsPerToken = true };
        var removeOpt = new Option<string>("-remove") { Description = "Backend name to remove" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password as plain text (INSECURE: visible in process list; omit for secure prompt)" };

        Add(indexArg);
        Add(addOpt);
        Add(removeOpt);
        Add(passwordOpt);

        SetAction(async (ParseResult parseResult) =>
        {
            var indexFile = parseResult.GetValue(indexArg);
            var addBackends = parseResult.GetValue(addOpt);
            var removeBackend = parseResult.GetValue(removeOpt);
            var pwd = parseResult.GetValue(passwordOpt);

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

            byte[] password = pwd != null ? System.Text.Encoding.UTF8.GetBytes(pwd) : Services.PasswordProvider.ReadInteractive();
            if (password.Length == 0) { Console.Error.WriteLine("Error: password cannot be empty"); return 1; }

            try
            {
                byte[] encryptedIndex = await File.ReadAllBytesAsync(indexFile.FullName);
                (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
                var index = IndexManager.DeserializeIndex(cbor);
                string fingerprint = index.FileFingerprint;
                string storageDir = indexFile.DirectoryName!;

                var mgmt = new ManagementFile(storageDir);

                if (addBackends != null)
                    foreach (var be in addBackends)
                        mgmt.RecordRemote(be, be, new(System.StringComparer.OrdinalIgnoreCase));

                if (!string.IsNullOrEmpty(removeBackend))
                    mgmt.DeleteRemote(removeBackend);

                Console.WriteLine($"Project '{fingerprint}' registered in management file");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                return 1;
            }
            finally
            {
                if (password.Length > 0)
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(password);
            }
        });
    }
}
