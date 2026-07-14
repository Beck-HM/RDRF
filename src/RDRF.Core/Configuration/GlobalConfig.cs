using System.Text.Json;

namespace RDRF.Core.Configuration;

public class GlobalConfig
{
    private static readonly string ConfigPath = Path.Combine(RdrfConfig.RootDir, "config");
    private static GlobalConfigData? _cached;

    public static string LogLevel { get; set; } = "Information";
    public static bool AutoFp { get; set; }
    public static string DefaultStorage { get; set; } = "";

    public static void Load()
    {
        try
        {
            if (File.Exists(ConfigPath))
            {
                string json = File.ReadAllText(ConfigPath);
                var data = JsonSerializer.Deserialize<GlobalConfigData>(json);
                if (data != null)
                {
                    LogLevel = data.LogLevel ?? "Information";
                    AutoFp = data.AutoFp;
                    DefaultStorage = data.DefaultStorage ?? "";
                    _cached = data;
                }
            }
        }
        catch { }
    }

    public static void Save()
    {
        try
        {
            var data = new GlobalConfigData
            {
                LogLevel = LogLevel,
                AutoFp = AutoFp,
                DefaultStorage = DefaultStorage,
            };
            string json = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
            Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
            File.WriteAllText(ConfigPath, json);
            _cached = data;
        }
        catch { }
    }

    private class GlobalConfigData
    {
        public string? LogLevel { get; set; }
        public bool AutoFp { get; set; }
        public string? DefaultStorage { get; set; }
    }
}

public class GlobalConfigCommand
{
    public string Key { get; set; } = "";
    public string Value { get; set; } = "";
}
