using System.Security.Cryptography;
using System.Text;
using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.FragmentEngine;
using RDRF.Core.Index;
using RDRF.Storage;

namespace RDRF.Deploy.Push;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Length < 1 || args[0] is "-h" or "--help")
        {
            Console.Error.WriteLine("Usage: rdrf-push <indexFile> [-p password]");
            return 1;
        }

        var indexPath = Path.GetFullPath(args[0]);
        if (!File.Exists(indexPath))
        {
            Console.Error.WriteLine($"Error: index file not found: {indexPath}");
            return 1;
        }

        string? pwdArg = null;
        for (int i = 1; i < args.Length; i++)
            if (args[i] == "-p" && i + 1 < args.Length)
                pwdArg = args[++i];

        byte[] password = pwdArg != null
            ? Encoding.UTF8.GetBytes(pwdArg)
            : ReadPasswordInteractive();

        try
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
            var factories = PluginLoader.PluginLoader.Load(pluginsDir);
            if (factories.Count == 0)
                Console.Error.WriteLine("Warning: no plugins found in " + pluginsDir);

            var orchestrator = new StorageOrchestrator(storageDir);
            var registeredBackends = new List<string>();

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
                registeredBackends.Add(cfg.Name);
                Console.WriteLine($"  Backend '{cfg.Name}' ({cfg.Type}) registered");
            }

            if (registeredBackends.Count == 0)
            {
                Console.Error.WriteLine("Error: no backends could be registered");
                return 1;
            }

            // Determine which backends to use for this project
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
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(password);
        }
    }

    private static byte[] ReadPasswordInteractive()
    {
        Console.Error.Write("Password: ");
        var sb = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.Error.WriteLine();
                break;
            }
            if (key.Key == ConsoleKey.Backspace && sb.Length > 0)
            {
                sb.Length--;
            }
            else if (key.KeyChar is >= ' ' and <= '~')
            {
                sb.Append(key.KeyChar);
            }
        }
        return Encoding.UTF8.GetBytes(sb.ToString());
    }
}
