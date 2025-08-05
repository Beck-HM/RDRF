using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Storage;
using RDRF.Cli.Services;
using System.CommandLine;

namespace RDRF.Cli.Commands;

public class PushCommand : Command
{
    public PushCommand() : base("push", "Push fragments to registered backends")
    {
        var indexArg = new Argument<FileInfo>("indexFile") { Description = "Path to the .indrdrf index file" };

        Add(indexArg);

        SetAction(async (ParseResult parseResult) =>
        {
            var indexFile = parseResult.GetValue(indexArg);

            if (!indexFile.Exists)
            {
                Console.Error.WriteLine($"Error: index file not found: {indexFile.FullName}");
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
                (byte[] aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
                var index = IndexManager.DeserializeIndex(cbor);
                string fingerprint = index.FileFingerprint;
                string prefix = index.CustomName ?? fingerprint;
                string storageDir = indexFile.DirectoryName!;

                var mgmt = new ManagementFile(storageDir);
                var remotes = mgmt.ListRemotes();

                if (remotes.Count == 0)
                {
                    Console.Error.WriteLine("Error: no backends configured. Use 'rdrf remote <index> -add <name>' first.");
                    return 1;
                }

                // Load backends from config
                var configs = ConfigManager.Load();
                var orchestrator = new StorageOrchestrator(storageDir);

                foreach (var rc in remotes)
                {
                    var cfg = configs.FirstOrDefault(c =>
                        c.Name.Equals(rc.Name, StringComparison.OrdinalIgnoreCase));
                    if (cfg == null)
                    {
                        Console.Error.WriteLine($"  Backend '{rc.Name}' not found in rdrf_config.yaml. Skip.");
                        continue;
                    }

                    Console.WriteLine($"  Backend '{rc.Name}' requires a plugin (type: {rc.Type}).");
                    Console.WriteLine($"    Install the plugin and register it before pushing.");
                }

                // Scan local fragments
                var localDir = storageDir;
                var fragFiles = Directory.GetFiles(localDir, $"{prefix}_*.rdrf")
                    .Concat(Directory.GetFiles(localDir, $"{fingerprint}.rdrc"))
                    .ToList();

                if (fragFiles.Count == 0)
                {
                    Console.WriteLine("No local fragments found. Run 'rdrf backup -node' first.");
                    return 0;
                }

                Console.WriteLine($"Found {fragFiles.Count} local file(s) ready to push.");
                Console.WriteLine("Push requires backend plugins (not yet implemented).");
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
