using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Storage;
using System.CommandLine;

namespace RDRF.Cli.Commands;

public class RemoveBackendCommand : Command
{
    public RemoveBackendCommand() : base("remove", "Remove a backend configuration or delete a remote version")
    {
        var indexArg = new Argument<FileInfo?>("indexFile") { Description = "Index file to purge (use with -v)" };
        var versionOpt = new Option<int>("-v") { Description = "Version number to delete from backends" };
        var nameOpt = new Option<string?>("-name") { Description = "Backend name to remove" };
        var nodeOpt = new Option<bool>("-node") { Description = "Remove a backend from configuration" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password (INSECURE: visible in process list; omit for secure prompt)" };

        Add(indexArg);
        Add(versionOpt);
        Add(nameOpt);
        Add(nodeOpt);
        Add(passwordOpt);

        SetAction((ParseResult parseResult) =>
        {
            var indexFile = parseResult.GetValue(indexArg);
            int version = parseResult.GetValue(versionOpt);
            var name = parseResult.GetValue(nameOpt);
            bool node = parseResult.GetValue(nodeOpt);
            var pwd = parseResult.GetValue(passwordOpt);

            // Backend remove mode
            if (node && !string.IsNullOrEmpty(name))
            {
                ConfigManager.RemoveBackend(name);
                Console.WriteLine($"Backend '{name}' removed from rdrf_config.yaml");
                return 0;
            }

            // Purge mode
            if (indexFile == null || version <= 0)
            {
                Console.Error.WriteLine("Usage:");
                Console.Error.WriteLine("  rdrf remove -name <name> -node          (remove backend config)");
                Console.Error.WriteLine("  rdrf remove <index> -v <version>        (purge remote version)");
                return 1;
            }
            if (!indexFile.Exists)
            {
                Console.Error.WriteLine($"Error: index file not found: {indexFile.FullName}");
                return 1;
            }

            byte[] password = pwd != null ? System.Text.Encoding.UTF8.GetBytes(pwd) : Services.PasswordProvider.ReadInteractive();
            if (password.Length == 0) { Console.Error.WriteLine("Error: password cannot be empty"); return 1; }

            try
            {
                byte[] encryptedIndex = File.ReadAllBytes(indexFile.FullName);
                (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
                var idx = IndexManager.DeserializeIndex(cbor);
                string fingerprint = idx.FileFingerprint;
                string storageDir = indexFile.DirectoryName!;

                var mgmt = new ManagementFile(storageDir);
                var records = mgmt.Lookup(fingerprint, version);
                if (records.Count == 0)
                {
                    Console.WriteLine($"No records found for version {version}.");
                    return 0;
                }

                mgmt.DeleteVersion(fingerprint, version);
                Console.WriteLine($"Version {version} deleted from management file.");
                Console.WriteLine("Note: remote fragments were NOT deleted. Backend plugins required.");
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
