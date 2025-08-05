using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Storage;
using System.CommandLine;

namespace RDRF.Cli.Commands;

public class PushCommand : Command
{
    public PushCommand() : base("push", "Push fragments to registered backends")
    {
        var indexArg = new Argument<FileInfo>("indexFile") { Description = "Path to the .indrdrf index file" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password as plain text (INSECURE: visible in process list; omit for secure prompt)" };

        Add(indexArg);
        Add(passwordOpt);

        SetAction(async (ParseResult parseResult) =>
        {
            var indexFile = parseResult.GetValue(indexArg);
            var pwd = parseResult.GetValue(passwordOpt);

            if (!indexFile.Exists)
            {
                Console.Error.WriteLine($"Error: index file not found: {indexFile.FullName}");
                return 1;
            }

            byte[] password = pwd != null ? System.Text.Encoding.UTF8.GetBytes(pwd) : Services.PasswordProvider.ReadInteractive();
            if (password.Length == 0) { Console.Error.WriteLine("Error: password cannot be empty"); return 1; }

            try
            {
                byte[] encryptedIndex = await File.ReadAllBytesAsync(indexFile.FullName);
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
                }

                var fragFiles = Directory.GetFiles(storageDir, $"{prefix}_*.rdrf")
                    .Concat(Directory.GetFiles(storageDir, $"{fingerprint}.rdrc"))
                    .ToList();

                Console.WriteLine(fragFiles.Count == 0
                    ? "No local fragments found."
                    : $"Found {fragFiles.Count} local file(s) ready to push.");
                if (fragFiles.Count == 0) return 0;

                Console.WriteLine("Push requires backend plugins (not yet implemented).");
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
