using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Core.Dssa;
using System.CommandLine;

namespace RDRF.Cli.Commands;

public class RemoveBackendCommand : Command
{
    public RemoveBackendCommand() : base("remove", "Remove a backend configuration, delete a remote version, or clean local fragments")
    {
        var indexArg = new Argument<FileInfo?>("indexFile") { Description = "Index file (use with -v or -clean)" };
        var versionOpt = new Option<int>("-v") { Description = "Version number to delete from backends" };
        var nameOpt = new Option<string?>("-name") { Description = "Backend name to remove" };
        var nodeOpt = new Option<bool>("-node") { Description = "Remove a backend from configuration" };
        var cleanOpt = new Option<bool>("-clean") { Description = "Delete local fragment and RC files, keep index" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password (INSECURE: visible in process list; omit for secure prompt)" };
        Add(indexArg);
        Add(versionOpt);
        Add(nameOpt);
        Add(nodeOpt);
        Add(cleanOpt);
        Add(passwordOpt);

        this.SetAction((ParseResult parseResult) =>
        {
            var indexFile = parseResult.GetValue(indexArg);
            int version = parseResult.GetValue(versionOpt);
            var name = parseResult.GetValue(nameOpt);
            bool node = parseResult.GetValue(nodeOpt);
            bool clean = parseResult.GetValue(cleanOpt);
            var pwd = parseResult.GetValue(passwordOpt);

            if (node && !string.IsNullOrEmpty(name))
            {
                ConfigManager.RemoveBackend(name);
                Console.WriteLine("Backend '{0}' removed from rdrf_config.yaml", name);
                return 0;
            }

            if (clean)
            {
                if (indexFile == null)
                {
                    Console.Error.WriteLine("Usage: rdrf remove <indexFile> -clean");
                    return 1;
                }
                if (!indexFile.Exists)
                {
                    Console.Error.WriteLine("Error: index file not found: {0}", indexFile.FullName);
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
                    string dir = indexFile.DirectoryName!;
                    int deletedCount = 0;
                    var rcFiles = Directory.GetFiles(dir, fingerprint + ".rdrc");
                    foreach (var f in rcFiles)
                    {
                        File.Delete(f);
                        deletedCount++;
                        Console.WriteLine("Deleted: {0}", Path.GetFileName(f));
                    }
                    var fragmentFiles = Directory.GetFiles(dir, fingerprint + "_*.rdrf");
                    foreach (var f in fragmentFiles)
                    {
                        File.Delete(f);
                        deletedCount++;
                        Console.WriteLine("Deleted: {0}", Path.GetFileName(f));
                    }
                    Console.WriteLine("Cleanup complete: {0} local file(s) removed, index kept.", deletedCount);
                    return 0;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("Error: {0}", ex.Message);
                    return 1;
                }
                finally
                {
                    if (password.Length > 0)
                        System.Security.Cryptography.CryptographicOperations.ZeroMemory(password);
                }
            }

            if (indexFile == null || version <= 0)
            {
                Console.Error.WriteLine("Usage:");
                Console.Error.WriteLine("  rdrf remove -name <name> -node          (remove backend config)");
                Console.Error.WriteLine("  rdrf remove <index> -v <version>        (purge remote version)");
                Console.Error.WriteLine("  rdrf remove <index> -clean              (delete local fragments/RC)");
                return 1;
            }
            if (!indexFile.Exists)
            {
                Console.Error.WriteLine("Error: index file not found: {0}", indexFile.FullName);
                return 1;
            }
            byte[] password2 = pwd != null ? System.Text.Encoding.UTF8.GetBytes(pwd) : Services.PasswordProvider.ReadInteractive();
            if (password2.Length == 0) { Console.Error.WriteLine("Error: password cannot be empty"); return 1; }
            try
            {
                byte[] encryptedIndex = File.ReadAllBytes(indexFile.FullName);
                (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password2);
                var idx = IndexManager.DeserializeIndex(cbor);
                string fingerprint = idx.FileFingerprint;
                string storageDir = indexFile.DirectoryName!;
                var mgmt = new ManagementFile(storageDir);
                var records = mgmt.Lookup(fingerprint, version);
                if (records.Count == 0)
                {
                    Console.WriteLine("No records found for version {0}.", version);
                    return 0;
                }
                var pluginsDir = Path.Combine(AppContext.BaseDirectory, "plugins");
                var factories = PluginLoader.Load(pluginsDir);
                var configs = ConfigManager.Load();
                var backends = new Dictionary<string, IStorageBackend>(StringComparer.OrdinalIgnoreCase);
                foreach (var cfg in configs)
                {
                    var factory = factories.FirstOrDefault(f =>
                        f.Type.Equals(cfg.Type, StringComparison.OrdinalIgnoreCase));
                    if (factory == null) continue;
                    var backendConfig = cfg.Parameters.ToDictionary(kv => kv.Key, kv => (object)kv.Value);
                    backends[cfg.Name] = factory.Create(backendConfig);
                }
                int remoteDeleted = 0;
                foreach (var rec in records)
                {
                    if (backends.TryGetValue(rec.BackendName, out var backend))
                    {
                        try
                        {
                            backend.DeleteAsync(rec.RemotePath).GetAwaiter().GetResult();
                            remoteDeleted++;
                        }
                        catch (Exception ex)
                        {
                            Console.Error.WriteLine("  Failed to delete from '{0}': {1}", rec.BackendName, ex.Message);
                        }
                    }
                }
                mgmt.DeleteVersion(fingerprint, version);
                Console.WriteLine("Version {0} deleted (SQLite + {1}/{2} remote files).", version, remoteDeleted, records.Count);
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error: {0}", ex.Message);
                return 1;
            }
            finally
            {
                if (password2.Length > 0)
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(password2);
            }
        });
    }
}
