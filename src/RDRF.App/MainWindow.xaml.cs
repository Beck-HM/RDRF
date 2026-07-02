using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using RDRF.App.ViewModels;

namespace RDRF.App;

public partial class MainWindow : Window
{
    private readonly EncryptViewModel _encryptVM = new();
    private readonly DecryptViewModel _decryptVM = new();
    private readonly HistoryViewModel _historyVM = new();

    private string _configDir = string.Empty;
    private string _configPath = string.Empty;
    private AppConfig _config = new();

    private readonly Dictionary<string, Button> _strategyBorders = new();
    private Hardcodet.Wpf.TaskbarNotification.TaskbarIcon? _notifyIcon;

    private const int WM_COPYDATA = 0x004A;

    [StructLayout(LayoutKind.Sequential)]
    private struct COPYDATASTRUCT
    {
        public IntPtr dwData;
        public int cbData;
        public IntPtr lpData;
    }

    public MainWindow()
    {
        InitializeComponent();
        InitializeConfig();

        EncryptPage.DataContext = _encryptVM;
        DecryptPage.DataContext = _decryptVM;
        HistoryPage.DataContext = _historyVM;

        InitializeStrategyCards();
        FsaToggle.IsEnabled = false;
        _encryptVM.ConfigDir = _configDir;
        LoadConfig();

        _encryptVM.RequestShowError += (title, msg, info) =>
            Dispatcher.Invoke(() => RdrfMessageBox.Show(msg, title, RdrfMessageBox.DialogIcon.Error, info));
        _encryptVM.RequestShowSuccess += (title, fingerprint) =>
            Dispatcher.Invoke(() => RdrfMessageBox.Show(title, "RDRF", RdrfMessageBox.DialogIcon.Success, fingerprint));
        _encryptVM.RequestSaveConfig += () => Dispatcher.Invoke(SaveConfig);

        _decryptVM.RequestShowError += (title, msg, info) =>
            Dispatcher.Invoke(() => RdrfMessageBox.Show(msg, title, RdrfMessageBox.DialogIcon.Error, info));
        _decryptVM.RequestShowSuccess += (title, _) =>
            Dispatcher.Invoke(() => RdrfMessageBox.Show(title, "RDRF", RdrfMessageBox.DialogIcon.Success));
        _decryptVM.RequestShowWarning += (title, msg) =>
            Dispatcher.Invoke(() => RdrfMessageBox.Show(msg, title, RdrfMessageBox.DialogIcon.Warning));
        _decryptVM.RequestSaveConfig += () => Dispatcher.Invoke(SaveConfig);

        _historyVM.RequestShowError += (title, msg, info) =>
            Dispatcher.Invoke(() => RdrfMessageBox.Show(msg, title, RdrfMessageBox.DialogIcon.Error, info));
        _historyVM.RequestShowSuccess += (title, _) =>
            Dispatcher.Invoke(() => RdrfMessageBox.Show(title, "RDRF", RdrfMessageBox.DialogIcon.Success));
        _historyVM.RequestShowWarning += (title, msg) =>
            Dispatcher.Invoke(() => RdrfMessageBox.Show(msg, title, RdrfMessageBox.DialogIcon.Warning));

        FragmentSizeMB.TextChanged += (_, _) => QueuePreviewUpdate();
        _encryptVM.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(EncryptViewModel.EncryptFilePath))
                QueuePreviewUpdate();
        };

        // HwndSource hook for WM_COPYDATA IPC (used by rdrf-mcp-wpf)
        SourceInitialized += OnSourceInitialized;

        // NotifyIcon for system tray
        _notifyIcon = new Hardcodet.Wpf.TaskbarNotification.TaskbarIcon
        {
            IconSource = new System.Windows.Media.Imaging.BitmapImage(
                new Uri("pack://application:,,,/rdrf.ico")),
            ToolTipText = "RDRF"
        };
        _notifyIcon.TrayLeftMouseUp += (_, _) =>
        {
            Show();
            WindowState = WindowState.Normal;
            Activate();
        };
    }

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        if (_config.CloseBehavior == "tray")
        {
            Hide();
            e.Cancel = true;
            return;
        }
        _notifyIcon?.Dispose();
        base.OnClosing(e);
    }

    private void OnSourceInitialized(object? sender, EventArgs e)
    {
        try
        {
            var src = HwndSource.FromHwnd(new WindowInteropHelper(this).Handle);
            src?.AddHook(WndProc);
        }
        catch { }
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == WM_COPYDATA)
        {
            try
            {
                var cds = Marshal.PtrToStructure<COPYDATASTRUCT>(lParam);

                if (cds.cbData > 0 && cds.lpData != IntPtr.Zero)
                {
                    byte[] bytes = new byte[cds.cbData];
                    Marshal.Copy(cds.lpData, bytes, 0, cds.cbData);
                    string json = Encoding.UTF8.GetString(bytes);

                    using var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;
                    string action = root.GetProperty("action").GetString() ?? "";
                    string value = root.TryGetProperty("value", out var valueEl) ? valueEl.GetString() ?? "" : "";

                    // WndProc runs on UI thread — dispatch directly
                    switch (action)
                    {
                            case "set_encrypt_path":
                                if (!string.IsNullOrEmpty(value) && File.Exists(value))
                                {
                                    _encryptVM.EncryptFilePath = value;
                                    _encryptVM.FilePathDisplay = Path.GetFileName(value);
                                }
                                break;

                            case "set_decrypt_path":
                                if (!string.IsNullOrEmpty(value) && File.Exists(value))
                                    _decryptVM.SetIndexPath(value);
                                break;

                            case "set_password":
                                EncryptKeyBox.Password = value;
                                break;

                            case "set_decrypt_password":
                                DecryptKeyBox.Password = value;
                                break;

                            case "start_encrypt":
                                try
                                {
                                    // IPC: set strategy is handled by set_strategy action before this.
                                    // IPC: set_output_path is handled and stays in ViewModel.
                                    // Read values from ViewModel, not from UI controls (binding may not have updated yet).
                                    _encryptVM.SetPassword(EncryptKeyBox.Password);
                                    _encryptVM.FragmentSizeMB = int.TryParse(FragmentSizeMB.Text, out int mb) && mb >= 1 ? mb : 1;
                                    _encryptVM.CustomName = CustomNameBox.Text;
                                    // OutputPath was set by set_output_path IPC — keep ViewModel value
                                    _encryptVM.StartEncrypt();
                                }
                                catch (Exception ex_start)
                                {
                                    try { System.IO.File.AppendAllText(@"F:\RDRF\RDRF.NET\tests\RDRF_TestOutput\rdrf_error.txt",
                                        $"[{DateTime.Now:HH:mm:ss}] start_encrypt failed: {ex_start}{Environment.NewLine}"); }
                                    catch { }
                                }
                                break;

                            case "set_strategy":
                                SelectStrategy(value);
                                break;

                            case "set_output_path":
                                if (!string.IsNullOrEmpty(value))
                                    _encryptVM.OutputPath = value;
                                break;

                            case "set_decrypt_output_path":
                                if (!string.IsNullOrEmpty(value))
                                    _decryptVM.OutputPath = value;
                                break;

                            case "start_decrypt":
                                try
                                {
                                    _decryptVM.SetPassword(DecryptKeyBox.Password);
                                    _decryptVM.StartDecrypt();
                                }
                                catch (Exception ex_start)
                                {
                                    try { System.IO.File.AppendAllText(@"F:\RDRF\RDRF.NET\tests\RDRF_TestOutput\rdrf_error.txt",
                                        $"[{DateTime.Now:HH:mm:ss}] start_decrypt failed: {ex_start}{Environment.NewLine}"); }
                                    catch { }
                                }
                                break;

                            case "read_backup_info":
                                var info = new
                                {
                                    file = _decryptVM.InfoFileName ?? "",
                                    size = _decryptVM.InfoFileSize ?? "",
                                    strategy = _decryptVM.InfoStrategy ?? "",
                                    fragments = _decryptVM.InfoFragmentCount ?? "",
                                    created = _decryptVM.InfoCreated ?? "",
                                };
                                try
                                {
                                    string infoJson = System.Text.Json.JsonSerializer.Serialize(info);
                                    System.IO.File.WriteAllText(
                                        @"F:\RDRF\RDRF.NET\tests\RDRF_TestOutput\rdrf_info.json", infoJson);
                                }
                                catch { }
                                break;
                        }
                    }
                }
                catch { /* ignore malformed IPC messages */ }
            handled = true;
        }
        return IntPtr.Zero;
    }

    private void QueuePreviewUpdate()
    {
        Dispatcher.BeginInvoke(new Action(UpdateFragmentPreview), DispatcherPriority.Background);
    }

    private void InitializeConfig()
    {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        _configDir = Path.Combine(baseDir, ".rdrf");
        _configPath = Path.Combine(_configDir, "config.json");
    }

    private void InitializeStrategyCards()
    {
        _strategyBorders["FSS1"] = StrategyFSS1;
        _strategyBorders["FSS2"] = StrategyFSS2;
        _strategyBorders["FSS2R"] = StrategyFSS2R;
        _strategyBorders["FSS3"] = StrategyFSS3;
        _strategyBorders["FSS5"] = StrategyFSS5;
        _strategyBorders["FSS5P"] = StrategyFSS5P;
        _strategyBorders["FSS6"] = StrategyFSS6;
        _strategyBorders["FSS6.1"] = StrategyFSS61;
        _strategyBorders["FSS6.2"] = StrategyFSS62;
    }

    // ── Window Controls ──

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2) ToggleMaximize();
        else DragMove();
    }

    private void MinimizeButton_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void MaximizeButton_Click(object sender, RoutedEventArgs e) => ToggleMaximize();

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        _decryptVM.StopFragmentWatcher();
        _decryptVM.Dispose();
        _historyVM.ClearPassword();
        Close();
    }

    private void ToggleMaximize()
    {
        if (WindowState == WindowState.Maximized)
        {
            WindowState = WindowState.Normal;
            WindowBorder.CornerRadius = new CornerRadius(12);
            WindowBorder.BorderThickness = new Thickness(1);
        }
        else
        {
            WindowState = WindowState.Maximized;
            WindowBorder.CornerRadius = new CornerRadius(0);
            WindowBorder.BorderThickness = new Thickness(0);
        }
    }

    // ── Tab Switching ──

    private void TabEncrypt_Click(object sender, RoutedEventArgs e)
    {
        TabEncrypt.Style = (Style)FindResource("TabButtonActiveStyle");
        TabDecrypt.Style = (Style)FindResource("TabButtonStyle");
        TabHistory.Style = (Style)FindResource("TabButtonStyle");
        EncryptPage.Visibility = Visibility.Visible;
        DecryptPage.Visibility = Visibility.Collapsed;
        HistoryPage.Visibility = Visibility.Collapsed;
        _decryptVM.StopFragmentWatcher();
    }

    private void TabDecrypt_Click(object sender, RoutedEventArgs e)
    {
        TabDecrypt.Style = (Style)FindResource("TabButtonActiveStyle");
        TabEncrypt.Style = (Style)FindResource("TabButtonStyle");
        TabHistory.Style = (Style)FindResource("TabButtonStyle");
        DecryptPage.Visibility = Visibility.Visible;
        EncryptPage.Visibility = Visibility.Collapsed;
        HistoryPage.Visibility = Visibility.Collapsed;
        _decryptVM.StopFragmentWatcher();
    }

    private void TabHistory_Click(object sender, RoutedEventArgs e)
    {
        TabHistory.Style = (Style)FindResource("TabButtonActiveStyle");
        TabEncrypt.Style = (Style)FindResource("TabButtonStyle");
        TabDecrypt.Style = (Style)FindResource("TabButtonStyle");
        HistoryPage.Visibility = Visibility.Visible;
        EncryptPage.Visibility = Visibility.Collapsed;
        DecryptPage.Visibility = Visibility.Collapsed;
        _decryptVM.StopFragmentWatcher();
    }

    private void TabSettings_Click(object sender, RoutedEventArgs e)
    {
        TabSettings.Style = (Style)FindResource("TabButtonActiveStyle");
        TabEncrypt.Style = (Style)FindResource("TabButtonStyle");
        TabDecrypt.Style = (Style)FindResource("TabButtonStyle");
        TabHistory.Style = (Style)FindResource("TabButtonStyle");
        SettingsPage.Visibility = Visibility.Visible;
        EncryptPage.Visibility = Visibility.Collapsed;
        DecryptPage.Visibility = Visibility.Collapsed;
        HistoryPage.Visibility = Visibility.Collapsed;
        _decryptVM.StopFragmentWatcher();
    }

    private void SettingsBrowseOutput_Click(object sender, RoutedEventArgs e)
    {
        using var dialog = new System.Windows.Forms.FolderBrowserDialog();
        if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            SettingsOutputPath.Text = dialog.SelectedPath;
    }

    private void SettingsTheme_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (SettingsTheme.SelectedItem is ComboBoxItem item && item.Tag is string tag)
            ApplyTheme(tag);
    }

    private void ApplyTheme(string theme)
    {
        var uri = theme == "light" ? "Themes/Light.xaml" : "Themes/Dark.xaml";
        var dict = new ResourceDictionary { Source = new Uri(uri, UriKind.Relative) };
        System.Windows.Application.Current.Resources.MergedDictionaries[0] = dict;
    }

    private void SettingsSave_Click(object sender, RoutedEventArgs e)
    {
        _config.DefaultOutputPath = SettingsOutputPath.Text;
        if (SettingsTheme.SelectedItem is ComboBoxItem themeItem)
            _config.Theme = themeItem.Tag as string ?? "dark";
        if (SettingsCloseBehavior.SelectedItem is ComboBoxItem closeItem)
            _config.CloseBehavior = closeItem.Tag as string ?? "exit";
        SaveConfig();
    }

    // ── Strategy Selection ──

    private bool _fsaEnabled;
    private string? _fsaPrimary;

    private void FsaToggle_Click(object sender, RoutedEventArgs e)
    {
        _fsaEnabled = FsaToggle.IsChecked == true;
        _encryptVM.IsFsaEnabled = _fsaEnabled;
        _fsaPrimary = null;

        if (!_fsaEnabled)
        {
            SelectSingle("FSS1");
            return;
        }

        _encryptVM.FsaPrimaryStrategy = null;
        SelectFsa(null, false);
    }

    private void SelectStrategy(string strategy)
    {
        if (!_fsaEnabled)
        {
            SelectSingle(strategy);
            return;
        }

        if (strategy == "FSS6")
        {
            bool select = _fsaPrimary != null && !_encryptVM.IsFsaAuxSelected;
            _encryptVM.IsFsaAuxSelected = select;
            SelectFsa(_fsaPrimary, _encryptVM.IsFsaAuxSelected);
        }
        else
        {
            _fsaPrimary = (_fsaPrimary == strategy) ? null : strategy;
            _encryptVM.FsaPrimaryStrategy = _fsaPrimary;
            SelectFsa(_fsaPrimary, _fsaPrimary != null);
        }
    }

    private void SelectSingle(string strategy)
    {
        _encryptVM.SelectedStrategy = strategy;
        foreach (var kvp in _strategyBorders)
        {
            bool isSelected = kvp.Key == strategy;
            kvp.Value.Style = FindResource(isSelected ? "StrategyCardActiveButtonStyle" : "StrategyCardButtonStyle") as Style ?? kvp.Value.Style;
            var sp = kvp.Value.Content as StackPanel;
            if (sp?.Children.Count > 0 && sp.Children[0] is TextBlock tb)
                tb.Foreground = FindResource(isSelected ? "AccentBrush" : "TextSecondaryBrush") as Brush ?? tb.Foreground;
            kvp.Value.IsEnabled = true;
            kvp.Value.Opacity = 1;
        }
    }

    private void SelectFsa(string? primary, bool auxSelected)
    {
        foreach (var kvp in _strategyBorders)
        {
            bool isFss6 = kvp.Key == "FSS6";
            bool isPrimary = kvp.Key == primary;
            bool isSelected = isPrimary || (isFss6 && auxSelected);

            kvp.Value.Style = FindResource(isSelected ? "StrategyCardActiveButtonStyle" : "StrategyCardButtonStyle") as Style ?? kvp.Value.Style;
            var sp = kvp.Value.Content as StackPanel;
            if (sp?.Children.Count > 0 && sp.Children[0] is TextBlock tb)
                tb.Foreground = FindResource(isSelected ? "AccentBrush" : "TextSecondaryBrush") as Brush ?? tb.Foreground;

            if (primary != null)
            {
                kvp.Value.IsEnabled = isPrimary || isFss6;
                kvp.Value.Opacity = (isPrimary || isFss6) ? 1 : 0.3;
            }
            else
            {
                kvp.Value.IsEnabled = true;
                kvp.Value.Opacity = 1;
            }
        }
    }

    private void StrategyFSS1_Click(object sender, RoutedEventArgs e) => SelectStrategy("FSS1");
    private void StrategyFSS2_Click(object sender, RoutedEventArgs e) => SelectStrategy("FSS2");
    private void StrategyFSS2R_Click(object sender, RoutedEventArgs e) => SelectStrategy("FSS2R");
    private void StrategyFSS3_Click(object sender, RoutedEventArgs e) => SelectStrategy("FSS3");
    private void StrategyFSS5_Click(object sender, RoutedEventArgs e) => SelectStrategy("FSS5");
    private void StrategyFSS5P_Click(object sender, RoutedEventArgs e) => SelectStrategy("FSS5P");
    private void StrategyFSS6_Click(object sender, RoutedEventArgs e) => SelectStrategy("FSS6");
    private void StrategyFSS61_Click(object sender, RoutedEventArgs e) => SelectStrategy("FSS6.1");
    private void StrategyFSS62_Click(object sender, RoutedEventArgs e) => SelectStrategy("FSS6.2");

    // ── Encrypt Page (thin coordination) ──

    private void EncryptBrowse_Click(object sender, RoutedEventArgs e) => _encryptVM.BrowseFileCommand.Execute(null);
    private void EncryptOutputBrowse_Click(object sender, RoutedEventArgs e) => _encryptVM.BrowseOutputCommand.Execute(null);

    private void UpdateFragmentPreview()
    {
        string? filePath = _encryptVM.EncryptFilePath;
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
        {
            EncryptFragmentPreviewCard.Visibility = Visibility.Collapsed;
            return;
        }

        var fileInfo = new FileInfo(filePath);
        long fileSize = fileInfo.Length;
        int fragSizeMB = int.TryParse(FragmentSizeMB.Text, out int mb) && mb >= 1 ? mb : 1;
        int fragSizeBytes = fragSizeMB * 1024 * 1024;
        int dataFrags = RDRF.Core.FragmentEngine.Frags.GetFragmentCount(fileSize, fragSizeBytes);

        EncryptFragmentSummary.Text = $"{fileSize / 1024.0 / 1024.0:F1} MB  ->  {dataFrags} fragments  x  {fragSizeMB} MB";

        var items = new List<object>();
        int maxShow = Math.Min(dataFrags, 48);
        for (int i = 0; i < maxShow; i++)
            items.Add(new { Index = i.ToString() });

        EncryptFragmentGrid.ItemsSource = items;
        EncryptFragmentPreviewCard.Visibility = Visibility.Visible;
    }

    private void StartEncrypt_Click(object sender, RoutedEventArgs e)
    {
        _encryptVM.SetPassword(EncryptKeyBox.Password);
        _encryptVM.FragmentSizeMB = int.TryParse(FragmentSizeMB.Text, out int mb) && mb >= 1 ? mb : 1;
        _encryptVM.CustomName = CustomNameBox.Text;
        _encryptVM.OutputPath = EncryptOutputPath.Text;
        _encryptVM.StartEncryptCommand.Execute(null);
    }

    // ── Drag and Drop ──

    private void EncryptPage_DragEnter(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            e.Effects = DragDropEffects.Copy;
            EncryptDropOverlay.Visibility = Visibility.Visible;
        }
        else e.Effects = DragDropEffects.None;
    }

    private void EncryptPage_DragLeave(object sender, DragEventArgs e) =>
        EncryptDropOverlay.Visibility = Visibility.Collapsed;

    private void EncryptPage_Drop(object sender, DragEventArgs e)
    {
        EncryptDropOverlay.Visibility = Visibility.Collapsed;
        if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;
        string[]? files = (string[]?)e.Data.GetData(DataFormats.FileDrop);
        if (files is { Length: > 0 })
            _encryptVM.SetDroppedFiles(files);
    }

    // ── Decrypt Page (thin coordination) ──

    private void DecryptBrowse_Click(object sender, RoutedEventArgs e) => _decryptVM.BrowseBackupCommand.Execute(null);

    private void DecryptKeyBox_PasswordChanged(object sender, RoutedEventArgs e)
        => _decryptVM.SetPassword(DecryptKeyBox.Password);

    private void DecryptOutputBrowse_Click(object sender, RoutedEventArgs e) => _decryptVM.BrowseOutputCommand.Execute(null);

    private void StartDecrypt_Click(object sender, RoutedEventArgs e)
    {
        _decryptVM.OutputPath = DecryptOutputPath.Text;
        _decryptVM.StartDecryptCommand.Execute(null);
    }

    // ── History Page ──

    private void HistoryBrowseBackup_Click(object sender, RoutedEventArgs e) => _historyVM.BrowseBackupCommand.Execute(null);

    private void HistoryBrowseIncremental_Click(object sender, RoutedEventArgs e) => _historyVM.BrowseIncrementalCommand.Execute(null);

    private void HistoryKeyBox_PasswordChanged(object sender, RoutedEventArgs e)
        => _historyVM.SetPassword(HistoryKeyBox.Password);

    private void HistoryApply_Click(object sender, RoutedEventArgs e)
        => _historyVM.ApplyIncrementalCommand.Execute(null);

    // ── Config ──

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
                    _config = config;
                    ApplyConfigToUI();
                }
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            Debug.WriteLine($"[RDRF] Config load failed: {ex.Message}");
            _config = new AppConfig();
        }
    }

    private void SaveConfig()
    {
        try
        {
            if (int.TryParse(FragmentSizeMB.Text, out int fragSizeMB))
                _config.FragmentSizeMB = fragSizeMB;
            _config.OutputPath = EncryptOutputPath.Text;
            _config.DecryptOutputPath = DecryptOutputPath.Text;
            _config.DefaultOutputPath = SettingsOutputPath.Text;
            if (SettingsTheme.SelectedItem is ComboBoxItem themeItem)
                _config.Theme = themeItem.Tag as string ?? "dark";
            if (SettingsCloseBehavior.SelectedItem is ComboBoxItem closeItem)
                _config.CloseBehavior = closeItem.Tag as string ?? "exit";

            Directory.CreateDirectory(_configDir);
            string json = JsonSerializer.Serialize(_config, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_configPath, json);
        }
        catch (Exception ex) when (ex is IOException)
        {
            Debug.WriteLine($"[RDRF] Config save failed: {ex.Message}");
        }
    }

    private void ApplyConfigToUI()
    {
        if (_config.FragmentSizeMB >= 1)
            FragmentSizeMB.Text = _config.FragmentSizeMB.ToString();
        if (!string.IsNullOrEmpty(_config.OutputPath))
            EncryptOutputPath.Text = _config.OutputPath;
        if (!string.IsNullOrEmpty(_config.DecryptOutputPath))
            DecryptOutputPath.Text = _config.DecryptOutputPath;

        SettingsOutputPath.Text = _config.DefaultOutputPath;

        foreach (ComboBoxItem item in SettingsTheme.Items)
            if (item.Tag as string == _config.Theme)
                SettingsTheme.SelectedItem = item;
        foreach (ComboBoxItem item in SettingsCloseBehavior.Items)
            if (item.Tag as string == _config.CloseBehavior)
                SettingsCloseBehavior.SelectedItem = item;

        ApplyTheme(_config.Theme);
    }
}

public class AppConfig
{
    public string OutputPath { get; set; } = "./backup";
    public string DecryptOutputPath { get; set; } = "./restored";
    public int FragmentSizeMB { get; set; } = 1;
    public string DefaultOutputPath { get; set; } = "./backup";
    public string Theme { get; set; } = "dark";
    public string CloseBehavior { get; set; } = "exit";
}
