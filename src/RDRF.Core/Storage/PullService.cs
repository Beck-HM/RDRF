using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.FragmentEngine;
using RDRF.Core.Index;
using RDRF.Core.Versioning;

namespace RDRF.Storage;

public static class PullService
{
    public static async Task<int> Run(string indexPath, byte[] password, string? versionArg)
    {
        if (password.Length == 0)
        {
            Console.Error.WriteLine("Error: password cannot be empty");
            return 1;
        }

        byte[] encryptedIndex = await File.ReadAllBytesAsync(indexPath);
        (byte[] aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
        var index = IndexManager.DeserializeIndex(cbor);
        string currentFingerprint = index.FileFingerprint;
        string storageDir = Path.GetDirectoryName(indexPath)!;
        var allVersions = index.Versions?.OrderBy(v => v.Version).ToList()
            ?? new List<VersionRecord>();

        var mgmt = new ManagementFile(storageDir);
        var configs = ConfigManager.Load();

        // List mode
        if (string.Equals(versionArg, "list", StringComparison.OrdinalIgnoreCase))
        {
            if (allVersions.Count == 0)
            {
                Console.WriteLine("No version history found in index.");
                return 0;
            }
            Console.WriteLine($"Project: {currentFingerprint}");
            foreach (var vr in allVersions)
            {
                var records = mgmt.Lookup(vr.FileFingerprint, vr.Version);
                int fragCount = records.Count(r => r.ContentType == "fragment");
                Console.WriteLine($"  v{vr.Version}: {fragCount} fragment(s)");
            }
            return 0;
        }

        // Determine target version
        int targetVersion;
        if (!string.IsNullOrEmpty(versionArg))
        {
            if (!int.TryParse(versionArg, out targetVersion))
            {
                Console.Error.WriteLine("Error: -v must be a version number or 'list'");
                return 1;
            }
        }
        else
        {
            if (allVersions.Count == 0)
            {
                Console.Error.WriteLine("Error: no version history in index.");
                return 1;
            }
            targetVersion = allVersions.Last().Version;
        }

        var targetVr = allVersions.FirstOrDefault(v => v.Version == targetVersion);
        if (targetVr == null)
        {
            Console.Error.WriteLine($"Error: version {targetVersion} not found in index history");
            return 1;
        }

        string lookupFingerprint = targetVr.FileFingerprint;
        string lookupPrefix = index.CustomName ?? lookupFingerprint;

        // Load plugins and create backends
        var pluginsDir = Path.Combine(AppContext.BaseDirectory, "plugins");
        var backends = new Dictionary<string, IStorageBackend>(StringComparer.OrdinalIgnoreCase);

        var factories = PluginLoader.Load(pluginsDir);
        if (factories.Count == 0)
            Console.Error.WriteLine("Warning: no plugins found in " + pluginsDir);

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
            backends[cfg.Name] = factory.Create(backendConfig);
        }

        // Lookup fragment locations by version's own fingerprint
        var locations = mgmt.Lookup(lookupFingerprint, targetVersion);
        if (locations.Count == 0)
        {
            Console.Error.WriteLine($"Error: no fragments found for version {targetVersion}");
            return 1;
        }

        // Download all files
        Directory.CreateDirectory(storageDir);
        int downloaded = 0, errors = 0;

        foreach (var loc in locations)
        {
            if (!backends.TryGetValue(loc.BackendName, out var backend))
            {
                Console.Error.WriteLine($"  Backend '{loc.BackendName}' not available");
                errors++;
                continue;
            }

            try
            {
                await using var stream = await backend.OpenReadAsync(loc.RemotePath);
                using var ms = new MemoryStream();
                await stream.CopyToAsync(ms);
                byte[] data = ms.ToArray();

                string localName = loc.ContentType == "rc"
                    ? lookupFingerprint + Constants.RcFileSuffix
                    : Frags.FragmentFilename(lookupPrefix, loc.FragmentIndex);

                string localPath = Path.Combine(storageDir, localName);
                await File.WriteAllBytesAsync(localPath, data);

                string label = loc.ContentType == "rc" ? "RC" : $"Fragment {loc.FragmentIndex}";
                Console.WriteLine($"  {label} downloaded ({data.Length:N0} bytes)");
                downloaded++;
            }
            catch (Exception ex)
            {
                string label = loc.ContentType == "rc" ? "RC" : $"Fragment {loc.FragmentIndex}";
                Console.Error.WriteLine($"  {label} error: {ex.Message}");
                errors++;
            }
        }

        Console.WriteLine($"Done: {downloaded} file(s) downloaded, {errors} error(s)");
        return errors > 0 ? 1 : 0;
    }
}
