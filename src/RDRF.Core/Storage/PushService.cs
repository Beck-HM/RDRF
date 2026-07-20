using System.Diagnostics;
using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.FragmentEngine;
using RDRF.Core.Index;

namespace RDRF.Core.DSAA;

/// <summary>
/// Push fragments/RC to remote backends via round-robin distribution through registered plugins.
/// </summary>

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
            Console.Error.WriteLine("Error: no backends configured in rdrf_config.yaml. Run 'rdrf init -path/...' first.");
            Console.Error.WriteLine("Hint: use 'rdrf list -node' to inspect backends, then 'rdrf remote <index> -add <name>'.");
            return 1;
        }

        var pluginsDir = Path.Combine(AppContext.BaseDirectory, "plugins");
        var orchestrator = new StorageOrchestrator(storageDir);
        var registeredBackends = LoadPlugins(pluginsDir, configs, orchestrator, dryRun);

        if (registeredBackends.Count == 0)
        {
            Console.Error.WriteLine("Error: no backends could be registered (missing plugins or bad config).");
            Console.Error.WriteLine($"Plugins dir: {pluginsDir}");
            return 1;
        }

        var targetBackends = remotes.Count > 0
            ? remotes.Select(r => r.Name)
                .Where(n => registeredBackends.Contains(n, StringComparer.OrdinalIgnoreCase))
                .ToList()
            : registeredBackends;

        if (targetBackends.Count == 0 && remotes.Count > 0)
        {
            Debug.WriteLine("Error: none of the configured remotes could be loaded");
            return 1;
        }
        if (targetBackends.Count == 0)
            targetBackends = registeredBackends;

        int fragmentCount = index.FragmentCount;
        int versionNumber = index.VersionNumber ?? 1;

        // Check which fragments already exist on backends
        var existingOnBackends = new HashSet<int>();
        if (remotes.Count > 0)
        {
            var existingRecords = mgmt.Lookup(fingerprint, versionNumber);
            foreach (var rec in existingRecords.Where(r => r.ContentType == "fragment"))
                existingOnBackends.Add(rec.FragmentIndex);
        }

        // Collect all push items
        var items = new List<(int index, string path)>();
        for (int i = 0; i < fragmentCount; i++)
        {
            if (existingOnBackends.Contains(i))
            {
                Debug.WriteLine($"  Fragment {i}/{fragmentCount} already on backend, skipped");
                continue;
            }
            string fragName = Frags.FragmentFilename(prefix, i);
            string fragPath = Path.Combine(storageDir, fragName);
            if (!File.Exists(fragPath))
            {
                Debug.WriteLine($"  Fragment {i} not found: {fragName}");
                continue;
            }
            items.Add((i, fragPath));
        }

        string rcName = fingerprint + Constants.RcFileSuffix;
        string rcPath = Path.Combine(storageDir, rcName);
        bool hasRc = File.Exists(rcPath);

        int totalItems = items.Count + (hasRc ? 1 : 0);
        if (totalItems == 0)
        {
            Debug.WriteLine("All fragments already up-to-date. Nothing to push.");
            return 0;
        }
        int done = 0, errors = 0;

        if (dryRun)
        {
            Console.WriteLine($"[dry-run] Project: {fingerprint} v{versionNumber}");
            Console.WriteLine($"[dry-run] Backends: {string.Join(", ", targetBackends)}");
            Console.WriteLine($"[dry-run] Would push {items.Count} fragment(s)" + (hasRc ? " + RC" : ""));
            foreach (var (idx, _) in items)
                Console.WriteLine($"[dry-run]   Fragment {idx}/{fragmentCount}");
            if (hasRc)
                Console.WriteLine("[dry-run]   RC file");
            if (items.Count == 0 && !hasRc)
                Console.WriteLine("[dry-run] Nothing to push (fragments missing or already recorded).");
            return 0;
        }

        // Push fragments via file stream (hash-while-copy; no full-buffer ReadAllBytes)
        if (concurrency > 1)
        {
            var semaphore = new SemaphoreSlim(concurrency);
            var pushTasks = items.Select(async item =>
            {
                await semaphore.WaitAsync();
                try
                {
                    long fileSize = new FileInfo(item.path).Length;
                    var options = new StorageUploadOptions
                    {
                        Fingerprint = fingerprint,
                        FragmentCount = fragmentCount,
                        FragmentIndex = item.index,
                        VersionNumber = versionNumber,
                        Backends = targetBackends,
                        FileSize = fileSize,
                        Note = "pushed via rdrf-push",
                    };
                    await orchestrator.WriteFragmentFromFileAsync(item.path, options).ConfigureAwait(false);
                    Interlocked.Increment(ref done);
                    progress?.Report(new RdrfProgressReport
                    {
                        Stage = "Pushing", CurrentItem = done, TotalItems = totalItems
                    });
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"  Fragment {item.index} error: {ex.Message}");
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
                    long fileSize = new FileInfo(item.path).Length;
                    var options = new StorageUploadOptions
                    {
                        Fingerprint = fingerprint,
                        FragmentCount = fragmentCount,
                        FragmentIndex = item.index,
                        VersionNumber = versionNumber,
                        Backends = targetBackends,
                        FileSize = fileSize,
                        Note = "pushed via rdrf-push",
                    };
                    await orchestrator.WriteFragmentFromFileAsync(item.path, options).ConfigureAwait(false);
                    done++;
                    progress?.Report(new RdrfProgressReport
                    {
                        Stage = "Pushing", CurrentItem = done, TotalItems = totalItems
                    });
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"  Fragment {item.index} error: {ex.Message}");
                    errors++;
                }
            }
        }

        // Push RC file (stream)
        if (hasRc)
        {
            try
            {
                long rcSize = new FileInfo(rcPath).Length;
                var rcOptions = new StorageUploadOptions
                {
                    Fingerprint = fingerprint,
                    FragmentCount = fragmentCount,
                    FragmentIndex = -1,
                    VersionNumber = versionNumber,
                    Backends = targetBackends,
                    FileSize = rcSize,
                    Note = "pushed via rdrf-push",
                };
                await orchestrator.WriteRcFromFileAsync(rcPath, rcOptions).ConfigureAwait(false);
                done++;
                progress?.Report(new RdrfProgressReport
                {
                    Stage = "Pushing", CurrentItem = done, TotalItems = totalItems
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"  RC error: {ex.Message}");
                errors++;
            }
        }

        Debug.WriteLine($"Done: {done} file(s) pushed, {errors} error(s)");
        return errors > 0 ? 1 : 0;
    }

    internal static List<string> LoadPlugins(string pluginsDir,
        List<BackendConfigEntry> configs, StorageOrchestrator orchestrator,
        bool dryRun = false)
    {
        var factories = PluginLoader.Load(pluginsDir);
        if (factories.Count == 0 && !dryRun)
            Debug.WriteLine("Warning: no plugins found in " + pluginsDir);

        var registered = new List<string>();
        foreach (var cfg in configs)
        {
            var factory = factories.FirstOrDefault(f =>
                f.Type.Equals(cfg.Type, StringComparison.OrdinalIgnoreCase));
            if (factory == null)
            {
                Debug.WriteLine($"  No plugin found for backend type '{cfg.Type}' (backend '{cfg.Name}')");
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
            Debug.WriteLine($"  Backend '{cfg.Name}' ({cfg.Type}) registered");
        }
        return registered;
    }
}



