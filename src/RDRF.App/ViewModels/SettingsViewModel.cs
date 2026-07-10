using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows.Input;

namespace RDRF.App.ViewModels;

public class SettingsViewModel : ViewModelBase
{
    private string _defaultOutputPath = "./backup";
    private bool _closeExit = true;
    private bool _closeTray;
    private string _configDir = string.Empty;
    private string _configPath = string.Empty;

    public string DefaultOutputPath
    {
        get => _defaultOutputPath;
        set => SetProperty(ref _defaultOutputPath, value);
    }

    public bool CloseExit
    {
        get => _closeExit;
        set
        {
            if (SetProperty(ref _closeExit, value) && value)
                OnPropertyChanged(nameof(CloseTray));
        }
    }

    public bool CloseTray
    {
        get => _closeTray;
        set
        {
            if (SetProperty(ref _closeTray, value) && value)
                OnPropertyChanged(nameof(CloseExit));
        }
    }

    public ICommand BrowseOutputCommand { get; }
    public ICommand SaveCommand { get; }

    public SettingsViewModel()
    {
        SaveCommand = new RelayCommand(_ => SaveConfig());
        BrowseOutputCommand = new RelayCommand(_ =>
        {
            using var dialog = new System.Windows.Forms.FolderBrowserDialog();
            if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                DefaultOutputPath = dialog.SelectedPath;
        });
    }

    public void Initialize(string configDir)
    {
        _configDir = configDir;
        _configPath = Path.Combine(_configDir, "config.json");
        LoadConfig();
    }

    private void LoadConfig()
    {
        try
        {
            if (File.Exists(_configPath))
            {
                string json = File.ReadAllText(_configPath);
                var config = JsonSerializer.Deserialize<AppConfig>(json);
                if (config != null)
                {
                    _defaultOutputPath = config.DefaultOutputPath;
                    _closeExit = config.CloseBehavior == "exit";
                    _closeTray = config.CloseBehavior == "tray";
                }
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            Debug.WriteLine($"[RDRF] Failed to load config: {ex.Message}");
        }
    }

    private void SaveConfig()
    {
        try
        {
            var config = File.Exists(_configPath)
                ? JsonSerializer.Deserialize<AppConfig>(File.ReadAllText(_configPath)) ?? new AppConfig()
                : new AppConfig();

            config.DefaultOutputPath = _defaultOutputPath;
            config.CloseBehavior = _closeExit ? "exit" : "tray";

            Directory.CreateDirectory(_configDir);
            string json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_configPath, json);
        }
        catch (Exception ex) when (ex is IOException)
        {
            Debug.WriteLine($"[RDRF] Failed to save config: {ex.Message}");
        }
    }

    public AppConfig ExportConfig()
    {
        return new AppConfig
        {
            DefaultOutputPath = _defaultOutputPath,
            CloseBehavior = _closeExit ? "exit" : "tray"
        };
    }
}

public class AppConfig
{
    public string OutputPath { get; set; } = "./backup";
    public string DecryptOutputPath { get; set; } = "./restored";
    public int FragmentSizeMB { get; set; } = 1;
    public string DefaultOutputPath { get; set; } = "./backup";
    public string CloseBehavior { get; set; } = "exit";
}
