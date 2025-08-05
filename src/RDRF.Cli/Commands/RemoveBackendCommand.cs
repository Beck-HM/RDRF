using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Storage;
using RDRF.Cli.Services;
using System.CommandLine;

namespace RDRF.Cli.Commands;

public class RemoveBackendCommand : Command
{
    public RemoveBackendCommand() : base("remove", "Remove a backend configuration or delete a remote version")
    {
        // Purge mode: rdrf remove <index> -v <version>
        var indexArg = new Argument<FileInfo?>("indexFile") { Description = "Index file to purge (use with -v)" };
        var versionOpt = new Option<int>("-v") { Description = "Version number to delete from backends" };

        // Backend mode: rdrf remove -name <name> -node
        var nameOpt = new Option<string?>("-name") { Description = "Backend name to remove" };
        var nodeOpt = new Option<bool>("-node") { Description = "Remove a backend from configuration" };

        Add(indexArg);
        Add(versionOpt);
        Add(nameOpt);
        Add(nodeOpt);

        SetAction((ParseResult parseResult) =>
        {
            var indexFile = parseResult.GetValue(indexArg);
            int version = parseResult.GetValue(versionOpt);
            var name = parseResult.GetValue(nameOpt);
            bool node = parseResult.GetValue(nodeOpt);

            // Backend remove mode
            if (node && !string.IsNullOrEmpty(name))
            {
                ConfigManager.RemoveBackend(name);
                Console.WriteLine($"Backend '{name}' removed from rdrf_config.yaml");
                return 0;
            }

            // Purge mode: remove <index> -v <version>
            if (indexFile != null && version > 0)
            {
                if (!indexFile.Exists)
                {
                    Console.Error.WriteLine($"Error: index file not found: {indexFile.FullName}");
                    return 1;
                }

                byte[] password = PasswordProvider.ReadInteractive();
                if (password == null || password.Length == 0)
                {
                    Console.Error.WriteLine("Error: password is required");
                    return 1;
                }

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
            }

            Console.Error.WriteLine("Usage:");
            Console.Error.WriteLine("  rdrf remove -name <name> -node          (remove backend config)");
            Console.Error.WriteLine("  rdrf remove <index> -v <version>        (purge remote version)");
            return 1;
        });
    }
}
