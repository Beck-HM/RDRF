using System.Diagnostics;
using System.Text.Json;

namespace RDRF.Core.Configuration;

public class GlobalConfigService
{
    internal static GlobalConfigService? _instance;
    internal static void SetInstance(GlobalConfigService instance) { _instance ??= instance; }
    internal static GlobalConfigService Instance => _instance ?? throw new InvalidOperationException("GlobalConfigService not initialized.");
    internal static bool IsInitialized => _instance != null;

    private readonly string _configPath;
    private GlobalConfigData? _cached;

    public string LogLevel { get; set; } = "Information";
    public bool AutoFp { get; set; }
    public string DefaultStorage { get; set; } = "";

    public GlobalConfigService(RdrfConfigService rdrf)
    {
        _configPath = Path.Combine(rdrf.RootDir, "config");
    }

    public void Load()
    {
        try
        {
            if (File.Exists(_configPath))
            {
                string json = File.ReadAllText(_configPath);
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
        catch (Exception ex) { Debug.WriteLine($"[GlobalConfig] Failed to load config: {ex.Message}"); }
    }

    public void Save()
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
            Directory.CreateDirectory(Path.GetDirectoryName(_configPath)!);
            File.WriteAllText(_configPath, json);
            _cached = data;
        }
        catch (Exception ex) { Debug.WriteLine($"[GlobalConfig] Failed to save config: {ex.Message}"); }
    }

    private class GlobalConfigData
    {
        public string? LogLevel { get; set; }
        public bool AutoFp { get; set; }
        public string? DefaultStorage { get; set; }
    }
}

/// <summary>
/// Static facade for backward compatibility. Delegates to the singleton service instance.
/// New code should inject GlobalConfigService via DI.
/// </summary>
public static class GlobalConfig
{
    private static void EnsureInitialized()
    {
        if (GlobalConfigService._instance == null)
        {
            if (!RdrfConfigService.IsInitialized)
                RdrfConfig.EnsureInitialized();
            var rdrf = RdrfConfigService.Instance;
            var svc = new GlobalConfigService(rdrf);
            GlobalConfigService.SetInstance(svc);
        }
    }

    public static string LogLevel
    {
        get { EnsureInitialized(); return GlobalConfigService.Instance.LogLevel; }
        set { EnsureInitialized(); GlobalConfigService.Instance.LogLevel = value; }
    }
    public static bool AutoFp
    {
        get { EnsureInitialized(); return GlobalConfigService.Instance.AutoFp; }
        set { EnsureInitialized(); GlobalConfigService.Instance.AutoFp = value; }
    }
    public static string DefaultStorage
    {
        get { EnsureInitialized(); return GlobalConfigService.Instance.DefaultStorage; }
        set { EnsureInitialized(); GlobalConfigService.Instance.DefaultStorage = value; }
    }
    public static void Load() { EnsureInitialized(); GlobalConfigService.Instance.Load(); }
    public static void Save() { EnsureInitialized(); GlobalConfigService.Instance.Save(); }
}

public class GlobalConfigCommand
{
    public string Key { get; set; } = "";
    public string Value { get; set; } = "";
}
