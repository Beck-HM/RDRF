using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Storage;
using System.CommandLine;

namespace RDRF.Cli.Commands;

public class PullCommand : Command
{
    public PullCommand() : base("pull", "Pull fragments from backends and restore")
    {
        var indexArg = new Argument<FileInfo>("indexFile") { Description = "Path to the .indrdrf index file" };
        var versionOpt = new Option<string>("-v") { Description = "Version to pull (number or 'list' for version list)" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password as plain text (INSECURE: visible in process list; omit for secure prompt)" };

        Add(indexArg);
        Add(versionOpt);
        Add(passwordOpt);

        SetAction(async (ParseResult parseResult) =>
        {
            var indexFile = parseResult.GetValue(indexArg);
            var versionArg = parseResult.GetValue(versionOpt);
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
                (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
                var idx = IndexManager.DeserializeIndex(cbor);
                string fingerprint = idx.FileFingerprint;
                string storageDir = indexFile.DirectoryName!;

                var mgmt = new ManagementFile(storageDir);
                var versions = mgmt.GetVersionNumbers(fingerprint);

                // List mode: rdrf pull <index> -v list
                if (string.Equals(versionArg, "list", StringComparison.OrdinalIgnoreCase))
                {
                    if (versions.Count == 0)
                    {
                        Console.WriteLine("No versions have been pushed yet.");
                        return 0;
                    }
                    Console.WriteLine($"Project: {fingerprint}");
                    foreach (var v in versions)
                    {
                        var records = mgmt.Lookup(fingerprint, v);
                        int fragCount = records.Count(r => r.ContentType == "fragment");
                        Console.WriteLine($"  v{v}: {fragCount} fragments, {records.Count} total files");
                    }
                    return 0;
                }

                // Determine version
                int targetVersion;
                if (string.IsNullOrEmpty(versionArg))
                    targetVersion = versions.LastOrDefault();
                else if (!int.TryParse(versionArg, out targetVersion))
                {
                    Console.Error.WriteLine("Error: -v must be a version number or 'list'");
                    return 1;
                }

                if (targetVersion <= 0)
                {
                    Console.Error.WriteLine("Error: no versions found. Push the project first.");
                    return 1;
                }

                var locations = mgmt.Lookup(fingerprint, targetVersion);
                if (locations.Count == 0)
                {
                    Console.Error.WriteLine($"Error: version {targetVersion} not found in management file.");
                    return 1;
                }

                Console.WriteLine($"Ready to pull version {targetVersion}: {locations.Count} file(s).");
                Console.WriteLine("Pull requires backend plugins (not yet implemented).");
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
