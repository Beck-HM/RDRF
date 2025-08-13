using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.FragmentEngine;
using RDRF.Core.Index;

namespace RDRF.Storage;

public static class PushService
{
    public static async Task<int> Run(string indexPath, byte[] password)
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
        var registeredBackends = LoadPlugins(pluginsDir, configs, orchestrator);

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
        int pushed = 0, errors = 0;

        // Push fragments
        for (int i = 0; i < fragmentCount; i++)
        {
            string fragName = Frags.FragmentFilename(prefix, i);
            string fragPath = Path.Combine(storageDir, fragName);
            if (!File.Exists(fragPath))
            {
                Console.Error.WriteLine($"  Fragment {i} not found: {fragName}");
                errors++;
                continue;
            }

            byte[] data = await File.ReadAllBytesAsync(fragPath);
            var options = new StorageUploadOptions
            {
                Fingerprint = fingerprint,
                FragmentCount = fragmentCount,
                FragmentIndex = i,
                VersionNumber = versionNumber,
                Backends = targetBackends,
                FileSize = data.Length,
                Note = "pushed via rdrf-push",
            };

            await orchestrator.WriteFragmentAsync(data, options);
            Console.WriteLine($"  Fragment {i}/{fragmentCount} pushed");
            pushed++;
        }

        // Push RC file
        string rcName = fingerprint + Constants.RcFileSuffix;
        string rcPath = Path.Combine(storageDir, rcName);
        if (File.Exists(rcPath))
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
            Console.WriteLine("  RC file pushed");
            pushed++;
        }

        Console.WriteLine($"Done: {pushed} file(s) pushed, {errors} error(s)");
        return errors > 0 ? 1 : 0;
    }

    internal static List<string> LoadPlugins(string pluginsDir,
        List<BackendConfigEntry> configs, StorageOrchestrator orchestrator)
    {
        var factories = PluginLoader.Load(pluginsDir);
        if (factories.Count == 0)
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

            var backendConfig = cfg.Parameters
                .ToDictionary(kv => kv.Key, kv => (object)kv.Value);
            var backend = factory.Create(backendConfig);
            orchestrator.RegisterBackend(cfg.Name, backend);
            registered.Add(cfg.Name);
            Console.WriteLine($"  Backend '{cfg.Name}' ({cfg.Type}) registered");
        }
        return registered;
    }
}
