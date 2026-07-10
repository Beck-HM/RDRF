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
using Microsoft.Extensions.DependencyInjection;
using RDRF.App.ViewModels;

namespace RDRF.App;

public partial class MainWindow : Window
{
    private readonly EncryptViewModel _encryptVM;
    private readonly DecryptViewModel _decryptVM;
    private readonly HistoryViewModel _historyVM;
    internal readonly SettingsViewModel _settingsVM;

    private string _configDir = string.Empty;

    private readonly Dictionary<string, Button> _strategyBorders = new();
    private Hardcodet.Wpf.TaskbarNotification.TaskbarIcon? _notifyIcon;
    private int _allowedIpcPid;

    private const int WM_COPYDATA = 0x004A;

    [StructLayout(LayoutKind.Sequential)]
    private struct COPYDATASTRUCT
    {
        public IntPtr dwData;
        public int cbData;
        public IntPtr lpData;
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    public MainWindow(IServiceProvider serviceProvider)
    {
        _encryptVM = serviceProvider.GetRequiredService<EncryptViewModel>();
        _decryptVM = serviceProvider.GetRequiredService<DecryptViewModel>();
        _historyVM = serviceProvider.GetRequiredService<HistoryViewModel>();
        _settingsVM = serviceProvider.GetRequiredService<SettingsViewModel>();

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
        _settingsVM.Initialize(_configDir);

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

        // Set window icon from embedded assembly icon
        try
        {
            var hIcon = System.Drawing.Icon.ExtractAssociatedIcon(
                System.IO.Path.Combine(System.AppContext.BaseDirectory, "RDRF.App.exe"));
            if (hIcon != null)
                Icon = System.Windows.Interop.Imaging.CreateBitmapSourceFromHIcon(
                    hIcon.Handle,
                    new System.Windows.Int32Rect(0, 0, 32, 32),
                    System.Windows.Media.Imaging.BitmapSizeOptions.FromEmptyOptions());

            // Also set the title bar icon image
            using var iconStream = new System.IO.MemoryStream();
            hIcon?.Save(iconStream);
            iconStream.Position = 0;
            var bitmap = new System.Windows.Media.Imaging.BitmapImage();
            bitmap.BeginInit();
            bitmap.StreamSource = iconStream;
            bitmap.CacheOption = System.Windows.Media.Imaging.BitmapCacheOption.OnLoad;
            bitmap.EndInit();
            AppIconImage.Source = bitmap;
        }
        catch (Exception ex) { Debug.WriteLine($"[RDRF] Failed to set window icon: {ex.Message}"); }

        // NotifyIcon for system tray
        var showItem = new System.Windows.Controls.MenuItem { Header = "Show" };
        showItem.Click += (_, _) =>
        {
            Show();
            WindowState = WindowState.Normal;
            Activate();
        };
        var exitItem = new System.Windows.Controls.MenuItem { Header = "Exit" };
        exitItem.Click += (_, _) =>
        {
            _notifyIcon?.Dispose();
            System.Windows.Application.Current.Shutdown();
        };
        _notifyIcon = new Hardcodet.Wpf.TaskbarNotification.TaskbarIcon
        {
            IconSource = new System.Windows.Media.Imaging.BitmapImage(
                new Uri("pack://application:,,,/rdrf.ico")),
            ToolTipText = "RDRF",
            ContextMenu = new System.Windows.Controls.ContextMenu
            {
                Items = { showItem, exitItem }
            }
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
        if (_settingsVM.CloseTray)
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
        catch (Exception ex) { Debug.WriteLine($"[RDRF] Failed to register WndProc: {ex.Message}"); }
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg != WM_COPYDATA) return IntPtr.Zero;

        GetWindowThreadProcessId(wParam, out uint senderPid);
        if (_allowedIpcPid == 0)
            _allowedIpcPid = (int)senderPid;
        else if (_allowedIpcPid != (int)senderPid)
        {
            handled = true;
            return IntPtr.Zero;
        }

        handled = true;
        try
        {
            var cds = Marshal.PtrToStructure<COPYDATASTRUCT>(lParam);
            if (cds.cbData <= 0 || cds.lpData == IntPtr.Zero)
                return IntPtr.Zero;

            byte[] bytes = new byte[cds.cbData];
            Marshal.Copy(cds.lpData, bytes, 0, cds.cbData);
            var (action, value) = ParseIpcMessage(bytes);
            DispatchIpcAction(action, value);
        }
        catch (Exception ex_ipc) { Debug.WriteLine($"[RDRF] Malformed IPC message ignored: {ex_ipc.Message}"); }
        return IntPtr.Zero;
    }

    private static (string action, string value) ParseIpcMessage(byte[] bytes)
    {
        string json = Encoding.UTF8.GetString(bytes);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        string action = root.GetProperty("action").GetString() ?? "";
        string value = root.TryGetProperty("value", out var valueEl) ? valueEl.GetString() ?? "" : "";
        return (action, value);
    }

    private void DispatchIpcAction(string action, string value)
    {
        switch (action)
        {
            case "set_encrypt_path":        HandleSetEncryptPath(value); break;
            case "set_decrypt_path":        HandleSetDecryptPath(value); break;
            case "set_password":            HandleSetPassword(value); break;
            case "set_decrypt_password":    HandleSetDecryptPassword(value); break;
            case "start_encrypt":           HandleStartEncryptIpc(); break;
            case "set_strategy":            SelectStrategy(value); break;
            case "set_output_path":         HandleSetOutputPath(value); break;
            case "set_decrypt_output_path": HandleSetDecryptOutputPath(value); break;
            case "start_decrypt":           HandleStartDecryptIpc(); break;
            case "read_backup_info":        HandleReadBackupInfo(); break;
        }
    }

    private void HandleSetEncryptPath(string value)
    {
        if (!string.IsNullOrEmpty(value) && File.Exists(value))
        {
            _encryptVM.EncryptFilePath = value;
            _encryptVM.FilePathDisplay = Path.GetFileName(value);
        }
    }

    private void HandleSetDecryptPath(string value)
    {
        if (!string.IsNullOrEmpty(value) && File.Exists(value))
            _decryptVM.SetIndexPath(value);
    }

    private void HandleSetPassword(string value) => EncryptKeyBox.Password = value;
    private void HandleSetDecryptPassword(string value) => DecryptKeyBox.Password = value;

    private void HandleStartEncryptIpc()
    {
        try
        {
            _encryptVM.SetPassword(EncryptKeyBox.Password);
            _encryptVM.FragmentSizeMB = int.TryParse(FragmentSizeMB.Text, out int mb) && mb >= 1 ? mb : 1;
            _encryptVM.CustomName = CustomNameBox.Text;
            _encryptVM.StartEncrypt();
        }
        catch (Exception ex)
        {
            try { System.IO.File.AppendAllText(Path.Combine(_configDir, "ipc_error.log"),
                $"[{DateTime.Now:HH:mm:ss}] start_encrypt failed: {ex}{Environment.NewLine}"); }
            catch { Debug.WriteLine($"[RDRF] Failed to write IPC error log: {ex.Message}"); }
        }
    }

    private void HandleStartDecryptIpc()
    {
        try
        {
            _decryptVM.SetPassword(DecryptKeyBox.Password);
            _decryptVM.StartDecrypt();
        }
        catch (Exception ex)
        {
            try { System.IO.File.AppendAllText(Path.Combine(_configDir, "ipc_error.log"),
                $"[{DateTime.Now:HH:mm:ss}] start_decrypt failed: {ex}{Environment.NewLine}"); }
            catch { Debug.WriteLine($"[RDRF] Failed to write IPC error log: {ex.Message}"); }
        }
    }

    private void HandleSetOutputPath(string value)
    {
        if (!string.IsNullOrEmpty(value))
            _encryptVM.OutputPath = value;
    }

    private void HandleSetDecryptOutputPath(string value)
    {
        if (!string.IsNullOrEmpty(value))
            _decryptVM.OutputPath = value;
    }

    private void HandleReadBackupInfo()
    {
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
            System.IO.File.WriteAllText(Path.Combine(_configDir, "ipc_backup_info.json"), infoJson);
        }
        catch (Exception ex) { Debug.WriteLine($"[RDRF] Failed to write backup info: {ex.Message}"); }
    }

    private void QueuePreviewUpdate()
    {
        Dispatcher.BeginInvoke(new Action(UpdateFragmentPreview), DispatcherPriority.Background);
    }

    private void InitializeConfig()
    {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        _configDir = Path.Combine(baseDir, ".rdrf");
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

    // -- Window Controls --

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

    public void LoadIndexFile(string path)
    {
        TabDecrypt_Click(null, null);
        _decryptVM.SetIndexPath(path);
        DecryptKeyBox.Focus();
    }

    // -- Tab Switching --

    private void TabEncrypt_Click(object sender, RoutedEventArgs e)
    {
        TabEncrypt.Style = (Style)FindResource("TabButtonActiveStyle");
        TabDecrypt.Style = (Style)FindResource("TabButtonStyle");
        TabHistory.Style = (Style)FindResource("TabButtonStyle");
        EncryptPage.Visibility = Visibility.Visible;
        DecryptPage.Visibility = Visibility.Collapsed;
        HistoryPage.Visibility = Visibility.Collapsed;
        SettingsPage.Visibility = Visibility.Collapsed;
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
        SettingsPage.Visibility = Visibility.Collapsed;
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
        SettingsPage.Visibility = Visibility.Collapsed;
        _decryptVM.StopFragmentWatcher();
    }

    private void SettingsButton_Click(object sender, RoutedEventArgs e)
    {
        bool isOpen = SettingsPage.Visibility == Visibility.Visible;
        SettingsPage.Visibility = isOpen ? Visibility.Collapsed : Visibility.Visible;
        if (SettingsPage.Visibility == Visibility.Visible)
        {
            SettingsPage.DataContext = _settingsVM;
            EncryptPage.Visibility = Visibility.Collapsed;
            DecryptPage.Visibility = Visibility.Collapsed;
            HistoryPage.Visibility = Visibility.Collapsed;
            _decryptVM.StopFragmentWatcher();
        }
    }

    // -- Strategy Selection --

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

    // -- Encrypt Page (thin coordination) --

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

    // -- Drag and Drop --

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

    // -- Decrypt Page (thin coordination) --

    private void DecryptBrowse_Click(object sender, RoutedEventArgs e) => _decryptVM.BrowseBackupCommand.Execute(null);

    private void DecryptKeyBox_PasswordChanged(object sender, RoutedEventArgs e)
        => _decryptVM.SetPassword(DecryptKeyBox.Password);

    private void DecryptOutputBrowse_Click(object sender, RoutedEventArgs e) => _decryptVM.BrowseOutputCommand.Execute(null);

    private void StartDecrypt_Click(object sender, RoutedEventArgs e)
    {
        _decryptVM.OutputPath = DecryptOutputPath.Text;
        _decryptVM.StartDecryptCommand.Execute(null);
    }

    // -- History Page --

    private void HistoryBrowseBackup_Click(object sender, RoutedEventArgs e) => _historyVM.BrowseBackupCommand.Execute(null);

    private void HistoryBrowseIncremental_Click(object sender, RoutedEventArgs e) => _historyVM.BrowseIncrementalCommand.Execute(null);

    private void HistoryKeyBox_PasswordChanged(object sender, RoutedEventArgs e)
        => _historyVM.SetPassword(HistoryKeyBox.Password);

    private void HistoryApply_Click(object sender, RoutedEventArgs e)
        => _historyVM.ApplyIncrementalCommand.Execute(null);

    // -- Config --

    private void LoadConfig()
    {
        try
        {
            string configPath = Path.Combine(_configDir, "config.json");
            if (File.Exists(configPath))
            {
                string json = File.ReadAllText(configPath);
                var config = JsonSerializer.Deserialize<AppConfig>(json);
                if (config != null)
                {
                    if (config.FragmentSizeMB >= 1)
                        FragmentSizeMB.Text = config.FragmentSizeMB.ToString();
                    if (!string.IsNullOrEmpty(config.OutputPath))
                        EncryptOutputPath.Text = config.OutputPath;
                    if (!string.IsNullOrEmpty(config.DecryptOutputPath))
                        DecryptOutputPath.Text = config.DecryptOutputPath;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            Debug.WriteLine($"[RDRF] Config load failed: {ex.Message}");
        }
    }

    private void SaveConfig()
    {
        try
        {
            string configPath = Path.Combine(_configDir, "config.json");
            var config = File.Exists(configPath)
                ? JsonSerializer.Deserialize<AppConfig>(File.ReadAllText(configPath)) ?? new AppConfig()
                : new AppConfig();

            config.FragmentSizeMB = int.TryParse(FragmentSizeMB.Text, out int fmb) ? fmb : 1;
            config.OutputPath = EncryptOutputPath.Text;
            config.DecryptOutputPath = DecryptOutputPath.Text;

            Directory.CreateDirectory(_configDir);
            string json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(configPath, json);
        }
        catch (Exception ex) when (ex is IOException)
        {
            Debug.WriteLine($"[RDRF] Config save failed: {ex.Message}");
        }
    }
}
