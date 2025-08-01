using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace RDRF.Storage;

public static class StorageConfig
{
    private static readonly Dictionary<string, IStorageBackendFactory> _factories = new();

    private sealed class YamlRoot
    {
        public List<YamlBackend>? Backends { get; set; }
    }

    private sealed class YamlBackend
    {
        public string? Name { get; set; }
        public string? Type { get; set; }
        public Dictionary<string, string>? Parameters { get; set; }
    }

    public static void RegisterFactory(string type, IStorageBackendFactory factory)
    {
        _factories[type] = factory ?? throw new ArgumentNullException(nameof(factory));
    }

    public static void LoadFromFile(StorageOrchestrator orchestrator, string configPath)
    {
        if (!File.Exists(configPath))
            return;

        var yaml = File.ReadAllText(configPath);
        var entries = ParseYaml(yaml);
        LoadFromConfig(orchestrator, entries);
    }

    public static void LoadFromConfig(StorageOrchestrator orchestrator,
        List<BackendConfigEntry> entries)
    {
        foreach (var entry in entries)
        {
            if (!_factories.TryGetValue(entry.Type, out var factory))
                throw new InvalidOperationException(
                    $"No factory registered for backend type '{entry.Type}'. " +
                    $"Call StorageConfig.RegisterFactory(\"{entry.Type}\", ...) first.");

            var config = new Dictionary<string, object>(
                StringComparer.OrdinalIgnoreCase);
            foreach (var (key, value) in entry.Parameters)
                config[key] = ExpandEnv(value);

            var backend = factory.Create(config);
            orchestrator.RegisterBackend(entry.Name, backend);
        }
    }

    private static List<BackendConfigEntry> ParseYaml(string yaml)
    {
        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .Build();

        var root = deserializer.Deserialize<YamlRoot>(yaml);
        if (root?.Backends == null || root.Backends.Count == 0)
            return new List<BackendConfigEntry>();

        return root.Backends
            .Where(b => b.Name != null && b.Type != null)
            .Select(b => new BackendConfigEntry
            {
                Name = b.Name!,
                Type = b.Type!,
                Parameters = b.Parameters
                    ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
            })
            .ToList();
    }

    private static string ExpandEnv(string value)
    {
        if (string.IsNullOrEmpty(value))
            return value;

        int start = value.IndexOf("${", StringComparison.Ordinal);
        if (start < 0)
            return value;

        int end = value.IndexOf('}', start + 2);
        if (end < 0)
            return value;

        var varName = value[(start + 2)..end];
        var envValue = Environment.GetEnvironmentVariable(varName);
        if (envValue == null)
            return value;

        return value[..start] + envValue + ExpandEnv(value[(end + 1)..]);
    }
}
