using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Core.DSAA;
using Spectre.Console;
using System.CommandLine;
using System.Security.Cryptography;
using System.Text;

namespace RDRF.Cli.Commands;

/// <summary>
/// Remove backend, purge version, or clean local fragments. CLI: rdrf remove.
/// </summary>

public class RemoveBackendCommand : Command
{
    public RemoveBackendCommand() : base("remove", "Remove a backend configuration, delete a remote version, or clean local fragments")
    {
        // Optional: backend-only modes (-node) need no index path.
        var indexArg = new Argument<FileInfo?>("indexFile")
        {
            Description = "Index file (use with -v or -clean); omit for -node",
            Arity = ArgumentArity.ZeroOrOne,
        };
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
                AnsiConsole.MarkupLine($"[green]Backend '{name.EscapeMarkup()}' removed from rdrf_config.yaml[/]");
                return 0;
            }

            if (clean)
            {
                if (indexFile == null)
                {
                    AnsiConsole.MarkupLine("[red]Usage: rdrf remove <indexFile> -clean[/]");
                    return 1;
                }
                if (!indexFile.Exists)
                {
                    AnsiConsole.MarkupLine($"[red]Error: index file not found: {indexFile.FullName.EscapeMarkup()}[/]");
                    return 1;
                }
                byte[] password = pwd != null ? Encoding.UTF8.GetBytes(pwd) : Services.PasswordProvider.ReadInteractive();
                if (password.Length == 0) { AnsiConsole.MarkupLine("[red]Error: password cannot be empty[/]"); return 1; }
                try
                {
                    byte[] encryptedIndex = File.ReadAllBytes(indexFile.FullName);
                    (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
                    var idx = IndexManager.DeserializeIndex(cbor);
                    // Fragments/RC use CustomName when set, else content fingerprint.
                    string prefix = idx.CustomName ?? idx.FileFingerprint;
                    string dir = indexFile.DirectoryName!;
                    int deletedCount = 0;

                    AnsiConsole.Status().Start("Cleaning local files...", ctx =>
                    {
                        var rcFiles = Directory.GetFiles(dir, prefix + ".rdrc");
                        foreach (var f in rcFiles)
                        {
                            File.Delete(f);
                            deletedCount++;
                            ctx.Status($"Deleting {Path.GetFileName(f)}...");
                        }
                        var fragmentFiles = Directory.GetFiles(dir, prefix + "_*.rdrf");
                        foreach (var f in fragmentFiles)
                        {
                            File.Delete(f);
                            deletedCount++;
                            ctx.Status($"Deleting {Path.GetFileName(f)}...");
                        }
                    });

                    AnsiConsole.MarkupLine($"[green]Cleanup complete:[/] {deletedCount} local file(s) removed, index kept.");
                    return 0;
                }
                catch (Exception ex)
                {
                    AnsiConsole.MarkupLine($"[red]Error: {ex.Message.EscapeMarkup()}[/]");
                    return 1;
                }
                finally
                {
                    if (password.Length > 0)
                        CryptographicOperations.ZeroMemory(password);
                }
            }

            if (indexFile == null || version <= 0)
            {
                AnsiConsole.MarkupLine("[red]Usage: rdrf remove -name <name> -node          (remove backend config)[/]");
                AnsiConsole.MarkupLine("[red]       rdrf remove <index> -v <version>        (purge remote version)[/]");
                AnsiConsole.MarkupLine("[red]       rdrf remove <index> -clean              (delete local fragments/RC)[/]");
                return 1;
            }
            if (!indexFile.Exists)
            {
                AnsiConsole.MarkupLine($"[red]Error: index file not found: {indexFile.FullName.EscapeMarkup()}[/]");
                return 1;
            }
            byte[] password2 = pwd != null ? Encoding.UTF8.GetBytes(pwd) : Services.PasswordProvider.ReadInteractive();
            if (password2.Length == 0) { AnsiConsole.MarkupLine("[red]Error: password cannot be empty[/]"); return 1; }
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
                    AnsiConsole.MarkupLine($"[yellow]No remote records found for version {version}. It may be local-only. Use -clean to delete local fragments.[/]");
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
                            Task.Run(() => backend.DeleteAsync(rec.RemotePath)).GetAwaiter().GetResult();
                            remoteDeleted++;
                        }
                        catch (Exception ex)
                        {
                            AnsiConsole.MarkupLine($"[red]  Failed to delete from '{rec.BackendName.EscapeMarkup()}': {ex.Message.EscapeMarkup()}[/]");
                        }
                    }
                }
                mgmt.DeleteVersion(fingerprint, version);
                AnsiConsole.MarkupLine($"[green]Version {version} deleted[/] (SQLite + {remoteDeleted}/{records.Count} remote files).");
                return 0;
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Error: {ex.Message.EscapeMarkup()}[/]");
                return 1;
            }
            finally
            {
                if (password2.Length > 0)
                    CryptographicOperations.ZeroMemory(password2);
            }
        });
    }
}







