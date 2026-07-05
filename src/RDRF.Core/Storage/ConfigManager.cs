using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace RDRF.Core.Dssa;

/// <summary>
/// CRUD operations for YAML backend configuration file (rdrf_config.yaml).
/// </summary>

public static class ConfigManager
{
    private static readonly string DefaultPath =
        Path.Combine(Directory.GetCurrentDirectory(), ".rdrf", "rdrf_config.yaml");

    private sealed class YamlRoot
    {
        public List<YamlBackend>? Backends { get; set; }
    }

    private sealed class YamlBackend
    {
        public string? Name { get; set; }
        public string? Type { get; set; }
        public string? ApiUrl { get; set; }
        public string? Token { get; set; }
        public string? Endpoint { get; set; }
        public string? Bucket { get; set; }
        public string? AccessKey { get; set; }
        public string? SecretKey { get; set; }
        public string? Region { get; set; }
        public string? BasePath { get; set; }
    }

    public static List<BackendConfigEntry> Load(string? configPath = null)
    {
        var path = configPath ?? DefaultPath;
        if (!File.Exists(path))
            return new List<BackendConfigEntry>();

        var yaml = File.ReadAllText(path);
        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .Build();

        var root = deserializer.Deserialize<YamlRoot>(yaml);
        if (root?.Backends == null)
            return new List<BackendConfigEntry>();

        return root.Backends
            .Where(b => b.Name != null && b.Type != null)
            .Select(ToEntry)
            .ToList();
    }

    public static void AddBackend(BackendConfigEntry entry, string? configPath = null)
    {
        var path = configPath ?? DefaultPath;
        var backends = Load(path);

        var existing = backends.FirstOrDefault(b =>
            b.Name.Equals(entry.Name, StringComparison.OrdinalIgnoreCase));
        if (existing != null)
            backends.Remove(existing);

        backends.Add(entry);
        SaveAll(backends, path);
    }

    public static void RemoveBackend(string name, string? configPath = null)
    {
        var path = configPath ?? DefaultPath;
        var backends = Load(path);
        backends.RemoveAll(b =>
            b.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        SaveAll(backends, path);
    }

    public static void UpdateBackend(string name, BackendConfigEntry updated,
        string? configPath = null)
    {
        var path = configPath ?? DefaultPath;
        var backends = Load(path);
        backends.RemoveAll(b =>
            b.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        backends.Add(updated);
        SaveAll(backends, path);
    }

    private static void SaveAll(List<BackendConfigEntry> backends, string path)
    {
        var dir = Path.GetDirectoryName(path);
        if (dir != null)
            Directory.CreateDirectory(dir);
        var root = new YamlRoot
        {
            Backends = backends.Select(ToYaml).ToList(),
        };

        var serializer = new SerializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .Build();

        var yaml = serializer.Serialize(root);
        File.WriteAllText(path, yaml);
    }

    private static BackendConfigEntry ToEntry(YamlBackend y)
    {
        var entry = new BackendConfigEntry
        {
            Name = y.Name!,
            Type = y.Type!,
        };

        switch (y.Type)
        {
            case "rest":
                if (y.ApiUrl != null) entry.Parameters["api_url"] = y.ApiUrl;
                if (y.Token != null) entry.Parameters["token"] = y.Token;
                break;
            case "key":
                if (y.Endpoint != null) entry.Parameters["endpoint"] = y.Endpoint;
                if (y.Bucket != null) entry.Parameters["bucket"] = y.Bucket;
                if (y.AccessKey != null) entry.Parameters["access_key"] = y.AccessKey;
                if (y.SecretKey != null) entry.Parameters["secret_key"] = y.SecretKey;
                if (y.Region != null) entry.Parameters["region"] = y.Region;
                break;
            case "path":
                if (y.BasePath != null) entry.Parameters["base_path"] = y.BasePath;
                break;
        }

        return entry;
    }

    private static YamlBackend ToYaml(BackendConfigEntry e)
    {
        var y = new YamlBackend
        {
            Name = e.Name,
            Type = e.Type,
        };

        switch (e.Type)
        {
            case "rest":
                y.ApiUrl = e.Parameters.GetValueOrDefault("api_url");
                y.Token = e.Parameters.GetValueOrDefault("token");
                break;
            case "key":
                y.Endpoint = e.Parameters.GetValueOrDefault("endpoint");
                y.Bucket = e.Parameters.GetValueOrDefault("bucket");
                y.AccessKey = e.Parameters.GetValueOrDefault("access_key");
                y.SecretKey = e.Parameters.GetValueOrDefault("secret_key");
                y.Region = e.Parameters.GetValueOrDefault("region");
                break;
            case "path":
                y.BasePath = e.Parameters.GetValueOrDefault("base_path");
                break;
        }

        return y;
    }
}

