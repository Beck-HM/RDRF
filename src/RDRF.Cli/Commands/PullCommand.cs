using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Storage;
using RDRF.Cli.Services;
using System.CommandLine;

namespace RDRF.Cli.Commands;

public class PullCommand : Command
{
    public PullCommand() : base("pull", "Pull fragments from backends and restore")
    {
        var indexArg = new Argument<FileInfo>("indexFile") { Description = "Path to the .indrdrf index file" };
        var versionOpt = new Option<int>("-v") { Description = "Version number to pull (default: latest)" };
        var checkOpt = new Option<bool>("check") { Description = "List version history without downloading" };
        var listOpt = new Option<bool>("list") { Description = "List versions (use with -v) as 'list'" };

        Add(indexArg);
        Add(versionOpt);
        Add(checkOpt);
        Add(listOpt);

        SetAction((ParseResult parseResult) =>
        {
            var indexFile = parseResult.GetValue(indexArg);
            var version = parseResult.GetValue(versionOpt);
            bool check = parseResult.GetValue(checkOpt);
            bool list = parseResult.GetValue(listOpt);

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
                (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
                var idx = IndexManager.DeserializeIndex(cbor);
                string fingerprint = idx.FileFingerprint;
                string storageDir = indexFile.DirectoryName!;

                var mgmt = new ManagementFile(storageDir);

                // Check mode: list versions without downloading
                if (check && list)
                {
                    var versions = mgmt.GetVersionNumbers(fingerprint);
                    if (versions.Count == 0)
                    {
                        Console.WriteLine("No versions have been pushed yet.");
                        Console.WriteLine("Use 'rdrf push' after registering backends.");
                        return 0;
                    }

                    Console.WriteLine($"Project: {fingerprint}");
                    Console.WriteLine($"Available versions: {string.Join(", ", versions)}");
                    Console.WriteLine();
                    foreach (var v in versions)
                    {
                        var records = mgmt.Lookup(fingerprint, v);
                        int fragCount = records.Count(r => r.ContentType == "fragment");
                        Console.WriteLine($"  v{v}: {fragCount} fragments, {records.Count} total files");
                    }
                    return 0;
                }

                // Pull mode
                var targetVersion = version > 0 ? version : mgmt.GetVersionNumbers(fingerprint).LastOrDefault();
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
        });
    }
}
