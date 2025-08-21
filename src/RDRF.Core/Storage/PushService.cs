using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.FragmentEngine;
using RDRF.Core.Index;

namespace RDRF.Storage;

public static class PushService
{
    public static async Task<int> Run(string indexPath, byte[] password,
        bool dryRun = false, int concurrency = 1,
        IProgress<RdrfProgressReport>? progress = null)
    {
        if (password.Length == 0)
        {
            Console.Error.WriteLine("Error: password cannot be empty");
            return 1;
        }

        byte[] encryptedIndex = await File.ReadAllBytesAsync(indexPath);
        (byte[] aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
        var index = IndexManager.DeserializeIndex(cbor);
        string fingerprint = index.FileFingerprint;
        string prefix = index.CustomName ?? fingerprint;
        string storageDir = Path.GetDirectoryName(indexPath)!;

        var mgmt = new ManagementFile(storageDir);
        var configs = ConfigManager.Load();
        var remotes = mgmt.ListRemotes();

        if (configs.Count == 0)
        {
            Console.Error.WriteLine("Error: no backends configured in rdrf_config.yaml. Run 'rdrf init' first.");
            return 1;
        }

        var pluginsDir = Path.Combine(AppContext.BaseDirectory, "plugins");
        var orchestrator = new StorageOrchestrator(storageDir);
        var registeredBackends = LoadPlugins(pluginsDir, configs, orchestrator, dryRun);

        if (registeredBackends.Count == 0)
        {
            Console.Error.WriteLine("Error: no backends could be registered");
            return 1;
        }

        var targetBackends = remotes.Count > 0
            ? remotes.Select(r => r.Name)
                .Where(n => registeredBackends.Contains(n, StringComparer.OrdinalIgnoreCase))
                .ToList()
            : registeredBackends;

        if (targetBackends.Count == 0)
            targetBackends = registeredBackends;

        int fragmentCount = index.FragmentCount;
        int versionNumber = index.VersionNumber ?? 1;

        // Collect all push items
        var items = new List<(int index, string path)>();
        for (int i = 0; i < fragmentCount; i++)
        {
            string fragName = Frags.FragmentFilename(prefix, i);
            string fragPath = Path.Combine(storageDir, fragName);
            if (!File.Exists(fragPath))
            {
                Console.Error.WriteLine($"  Fragment {i} not found: {fragName}");
                continue;
            }
            items.Add((i, fragPath));
        }

        string rcName = fingerprint + Constants.RcFileSuffix;
        string rcPath = Path.Combine(storageDir, rcName);
        bool hasRc = File.Exists(rcPath);

        int totalItems = items.Count + (hasRc ? 1 : 0);
        int done = 0, errors = 0;

        if (dryRun)
        {
            Console.WriteLine($"Project: {fingerprint} v{versionNumber}");
            Console.WriteLine($"Backends: {string.Join(", ", targetBackends)}");
            Console.WriteLine($"Would push {items.Count} fragment(s)" + (hasRc ? " + RC" : ""));
            foreach (var (idx, _) in items)
                Console.WriteLine($"  Fragment {idx}/{fragmentCount}");
            if (hasRc)
                Console.WriteLine("  RC file");
            return 0;
        }

        // Push fragments (with optional concurrency)
        if (concurrency > 1)
        {
            var semaphore = new SemaphoreSlim(concurrency);
            var pushTasks = items.Select(async item =>
            {
                await semaphore.WaitAsync();
                try
                {
                    byte[] data = await File.ReadAllBytesAsync(item.path);
                    var options = new StorageUploadOptions
                    {
                        Fingerprint = fingerprint,
                        FragmentCount = fragmentCount,
                        FragmentIndex = item.index,
                        VersionNumber = versionNumber,
                        Backends = targetBackends,
                        FileSize = data.Length,
                        Note = "pushed via rdrf-push",
                    };
                    await orchestrator.WriteFragmentAsync(data, options);
                    Interlocked.Increment(ref done);
                    progress?.Report(new RdrfProgressReport
                    {
                        Stage = "Pushing", CurrentItem = done, TotalItems = totalItems
                    });
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"  Fragment {item.index} error: {ex.Message}");
                    Interlocked.Increment(ref errors);
                }
                finally
                {
                    semaphore.Release();
                }
            }).ToList();
            await Task.WhenAll(pushTasks);
        }
        else
        {
            foreach (var item in items)
            {
                try
                {
                    byte[] data = await File.ReadAllBytesAsync(item.path);
                    var options = new StorageUploadOptions
                    {
                        Fingerprint = fingerprint,
                        FragmentCount = fragmentCount,
                        FragmentIndex = item.index,
                        VersionNumber = versionNumber,
                        Backends = targetBackends,
                        FileSize = data.Length,
                        Note = "pushed via rdrf-push",
                    };
                    await orchestrator.WriteFragmentAsync(data, options);
                    done++;
                    progress?.Report(new RdrfProgressReport
                    {
                        Stage = "Pushing", CurrentItem = done, TotalItems = totalItems
                    });
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"  Fragment {item.index} error: {ex.Message}");
                    errors++;
                }
            }
        }

        // Push RC file
        if (hasRc)
        {
            try
            {
                byte[] rcData = await File.ReadAllBytesAsync(rcPath);
                var rcOptions = new StorageUploadOptions
                {
                    Fingerprint = fingerprint,
                    FragmentCount = fragmentCount,
                    FragmentIndex = -1,
                    VersionNumber = versionNumber,
                    Backends = targetBackends,
                    FileSize = rcData.Length,
                    Note = "pushed via rdrf-push",
                };
                await orchestrator.WriteRcAsync(rcData, rcOptions);
                done++;
                progress?.Report(new RdrfProgressReport
                {
                    Stage = "Pushing", CurrentItem = done, TotalItems = totalItems
                });
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"  RC error: {ex.Message}");
                errors++;
            }
        }

        Console.WriteLine($"Done: {done} file(s) pushed, {errors} error(s)");
        return errors > 0 ? 1 : 0;
    }

    internal static List<string> LoadPlugins(string pluginsDir,
        List<BackendConfigEntry> configs, StorageOrchestrator orchestrator,
        bool dryRun = false)
    {
        var factories = PluginLoader.Load(pluginsDir);
        if (factories.Count == 0 && !dryRun)
            Console.Error.WriteLine("Warning: no plugins found in " + pluginsDir);

        var registered = new List<string>();
        foreach (var cfg in configs)
        {
            var factory = factories.FirstOrDefault(f =>
                f.Type.Equals(cfg.Type, StringComparison.OrdinalIgnoreCase));
            if (factory == null)
            {
                Console.Error.WriteLine($"  No plugin found for backend type '{cfg.Type}' (backend '{cfg.Name}')");
                continue;
            }

            if (!dryRun)
            {
                var backendConfig = cfg.Parameters
                    .ToDictionary(kv => kv.Key, kv => (object)kv.Value);
                var backend = factory.Create(backendConfig);
                orchestrator.RegisterBackend(cfg.Name, backend);
            }

            registered.Add(cfg.Name);
            Console.WriteLine($"  Backend '{cfg.Name}' ({cfg.Type}) registered");
        }
        return registered;
    }
}
