using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using RDRF.App.Services;
using RDRF.Core;

namespace RDRF.App.ViewModels;

public class DecryptViewModel : ViewModelBase, IDisposable
{
    private string? _decryptIndexPath;
    private string? _decryptStoragePath;
    private string? _decryptFragmentPrefix;
    private DecryptService? _decryptService;
    private DateTime _decryptStartTime;
    private bool _disposed;

    private FileSystemWatcher? _fragmentWatcher;
    private DispatcherTimer? _refreshTimer;

    private bool _showFileInfo;
    private bool _showFragmentStatus;
    private bool _isStartEnabled;
    private string _infoFileName = "";
    private string _infoFileSize = "";
    private string _infoStrategy = "";
    private string _infoFragmentCount = "";
    private string _infoCreated = "";
    private string _fragmentSummary = "";
    private string _fileHint = "Select .indrdrf (index) or .rdrf (fragment) file";
    private string _indexPathDisplay = "No file selected...";
    private string _outputPath = "./restored";

    private bool _isDecrypting;
    private bool _showProgress;
    private string _stageText = "Preparing...";
    private double _progressPercent;
    private string _speedText = "Speed: 0 MB/s";
    private string _etaText = "ETA: --:--";

    public event Action<string, string>? RequestShowError;
    public event Action<string, string?>? RequestShowSuccess;
    public event Action<string, string?>? RequestShowWarning;
    public event Action? RequestSaveConfig;

    public bool ShowFileInfo
    {
        get => _showFileInfo;
        set => SetProperty(ref _showFileInfo, value);
    }

    public bool ShowFragmentStatus
    {
        get => _showFragmentStatus;
        set => SetProperty(ref _showFragmentStatus, value);
    }

    public bool IsStartEnabled
    {
        get => _isStartEnabled;
        set => SetProperty(ref _isStartEnabled, value);
    }

    public string InfoFileName
    {
        get => _infoFileName;
        set => SetProperty(ref _infoFileName, value);
    }

    public string InfoFileSize
    {
        get => _infoFileSize;
        set => SetProperty(ref _infoFileSize, value);
    }

    public string InfoStrategy
    {
        get => _infoStrategy;
        set => SetProperty(ref _infoStrategy, value);
    }

    public string InfoFragmentCount
    {
        get => _infoFragmentCount;
        set => SetProperty(ref _infoFragmentCount, value);
    }

    public string InfoCreated
    {
        get => _infoCreated;
        set => SetProperty(ref _infoCreated, value);
    }

    public string FragmentSummary
    {
        get => _fragmentSummary;
        set => SetProperty(ref _fragmentSummary, value);
    }

    public string FileHint
    {
        get => _fileHint;
        set => SetProperty(ref _fileHint, value);
    }

    public string IndexPathDisplay
    {
        get => _indexPathDisplay;
        set => SetProperty(ref _indexPathDisplay, value);
    }

    public string OutputPath
    {
        get => _outputPath;
        set => SetProperty(ref _outputPath, value);
    }

    public bool IsDecrypting
    {
        get => _isDecrypting;
        set
        {
            if (SetProperty(ref _isDecrypting, value))
                ShowProgress = value;
        }
    }

    public bool ShowProgress
    {
        get => _showProgress;
        set => SetProperty(ref _showProgress, value);
    }

    public string StageText
    {
        get => _stageText;
        set => SetProperty(ref _stageText, value);
    }

    public double ProgressPercent
    {
        get => _progressPercent;
        set
        {
            if (SetProperty(ref _progressPercent, value))
                OnPropertyChanged(nameof(PercentText));
        }
    }

    public string PercentText => $"{_progressPercent:F1}%";

    public string SpeedText
    {
        get => _speedText;
        set => SetProperty(ref _speedText, value);
    }

    public string EtaText
    {
        get => _etaText;
        set => SetProperty(ref _etaText, value);
    }

    public ObservableCollection<FragmentStatusItem> FragmentItems { get; }
        = new ObservableCollection<FragmentStatusItem>();

    public DecryptService? CurrentService => _decryptService;
    public string? StoragePath => _decryptStoragePath;
    public string? FragmentPrefix => _decryptFragmentPrefix;

    public System.Windows.Input.ICommand BrowseBackupCommand { get; }
    public System.Windows.Input.ICommand BrowseOutputCommand { get; }
    public System.Windows.Input.ICommand StartDecryptCommand { get; }

    public DecryptViewModel()
    {
        BrowseBackupCommand = new RelayCommand(_ => BrowseBackup());
        BrowseOutputCommand = new RelayCommand(_ => BrowseOutput());
        StartDecryptCommand = new RelayCommand(_ => StartDecrypt());
    }

    private void BrowseBackup()
    {
        StopFragmentWatcher();

        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select RDRF Backup File",
            Filter = "RDRF Files (*.indrdrf;*.rdrf)|*.indrdrf;*.rdrf|All Files (*.*)|*.*"
        };

        if (dialog.ShowDialog() == true)
        {
            string filePath = dialog.FileName;
            _decryptIndexPath = filePath;
            IndexPathDisplay = Path.GetFileName(filePath);

            _decryptStoragePath = Path.GetDirectoryName(filePath);

            _decryptService?.Dispose();
            _decryptService = null;
            _decryptFragmentPrefix = null;

            string extension = Path.GetExtension(filePath).ToLowerInvariant();

            if (extension == ".rdrf")
            {
                string fileName = Path.GetFileNameWithoutExtension(filePath);
                int lastUnderscore = fileName.LastIndexOf('_');
                if (lastUnderscore > 0)
                {
                    string suffix = fileName[(lastUnderscore + 1)..];
                    if (int.TryParse(suffix, out _))
                        _decryptFragmentPrefix = fileName[..lastUnderscore];
                }

                if (_decryptFragmentPrefix == null)
                {
                    ShowFileInfo = true;
                    ShowFragmentStatus = false;
                    IsStartEnabled = false;
                    InfoFileName = "Invalid fragment filename";
                    return;
                }

                FileHint = $"Fragment mode (prefix: {_decryptFragmentPrefix})";
            }
            else
            {
                FileHint = "Index mode — select .rdrf fragment to use embedded index";
            }
        }
    }

    private void BrowseOutput()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select Output Folder (select any file inside the folder)",
            Filter = "All Files (*.*)|*.*",
            CheckFileExists = false,
            FileName = "Select Folder"
        };
        if (dialog.ShowDialog() == true && !string.IsNullOrEmpty(dialog.FileName))
        {
            string? folder = Path.GetDirectoryName(dialog.FileName);
            if (folder is not null)
                OutputPath = folder;
        }
    }

    private byte[]? _pendingPassword;

    public void SetPassword(string password)
    {
        if (_pendingPassword != null)
            CryptographicOperations.ZeroMemory(_pendingPassword);
        _pendingPassword = System.Text.Encoding.UTF8.GetBytes(password);
        if (!string.IsNullOrEmpty(_decryptIndexPath) && _pendingPassword is { Length: > 0 })
            LoadDecryptInfo();
    }

    public void ClearPassword()
    {
        if (_pendingPassword != null)
        {
            CryptographicOperations.ZeroMemory(_pendingPassword);
            _pendingPassword = null;
        }
    }

    private void LoadDecryptInfo()
    {
        if (string.IsNullOrEmpty(_decryptIndexPath) || string.IsNullOrEmpty(_decryptStoragePath))
            return;

        try
        {
            _decryptService?.Dispose();
            _decryptService = new DecryptService(_pendingPassword);

            var result = _decryptFragmentPrefix != null
                ? _decryptService.LoadFromFragment(_decryptStoragePath, _decryptFragmentPrefix)
                : _decryptService.LoadFromIndex(_decryptStoragePath, _decryptIndexPath);

            ShowFileInfo = true;
            ShowFragmentStatus = true;
            IsStartEnabled = true;

            InfoFileName = result.OriginalName;
            InfoFileSize = FormatFileSize(result.FileSize);
            InfoStrategy = result.StrategyDisplay;
            InfoFragmentCount = result.FragmentCount.ToString();
            InfoCreated = result.CreatedAt.ToString("yyyy-MM-dd HH:mm");

            var statusList = _decryptService.ScanFragments();
            int available = statusList.Count(s => s.Available);
            int total = statusList.Count;

            FragmentItems.Clear();
            foreach (var s in statusList)
            {
                FragmentItems.Add(new FragmentStatusItem
                {
                    Index = s.Index.ToString(),
                    Brush = s.Available
                        ? (Brush)Application.Current.FindResource("SuccessBrush")
                        : (Brush)Application.Current.FindResource("ErrorBrush")
                });
            }

            FragmentSummary = $"{available} available / {total} total";

            StartFragmentWatcher();
        }
        catch (Exception)
        {
            ShowFileInfo = true;
            ShowFragmentStatus = false;
            IsStartEnabled = false;

            InfoFileName = "Invalid key or corrupted backup";
            InfoFileSize = "-";
            InfoStrategy = "-";
            InfoFragmentCount = "-";
            InfoCreated = "-";
        }
    }

    private void StartFragmentWatcher()
    {
        StopFragmentWatcher();

        if (string.IsNullOrEmpty(_decryptStoragePath) || !Directory.Exists(_decryptStoragePath))
            return;

        _fragmentWatcher = new FileSystemWatcher(_decryptStoragePath)
        {
            Filter = "*.rdrf",
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
            EnableRaisingEvents = true
        };
        _fragmentWatcher.Created += OnFragmentChanged;
        _fragmentWatcher.Deleted += OnFragmentChanged;
        _fragmentWatcher.Renamed += OnFragmentChanged;

        _refreshTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(500)
        };
        _refreshTimer.Tick += (s, e) =>
        {
            _refreshTimer?.Stop();
            RefreshFragmentStatus();
        };
    }

    public void StopFragmentWatcher()
    {
        if (_fragmentWatcher != null)
        {
            _fragmentWatcher.EnableRaisingEvents = false;
            _fragmentWatcher.Dispose();
            _fragmentWatcher = null;
        }

        if (_refreshTimer != null)
        {
            _refreshTimer.Stop();
            _refreshTimer = null;
        }
    }

    private void OnFragmentChanged(object sender, FileSystemEventArgs e)
    {
        string? prefix = _decryptService?.FilePrefix;
        if (prefix != null &&
            Path.GetFileName(e.FullPath).StartsWith(prefix))
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                _refreshTimer?.Stop();
                _refreshTimer?.Start();
            });
        }
    }

    private void RefreshFragmentStatus()
    {
        if (_decryptService == null)
            return;

        try
        {
            var statusList = _decryptService.ScanFragments();
            int available = statusList.Count(s => s.Available);
            int total = statusList.Count;

            FragmentItems.Clear();
            foreach (var s in statusList)
            {
                FragmentItems.Add(new FragmentStatusItem
                {
                    Index = s.Index.ToString(),
                    Brush = s.Available
                        ? (Brush)Application.Current.FindResource("SuccessBrush")
                        : (Brush)Application.Current.FindResource("ErrorBrush")
                });
            }

            FragmentSummary = $"{available} available / {total} total";
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[RDRF] Fragment status refresh failed: {ex.Message}");
        }
    }

    private void StartDecrypt()
    {
        if (string.IsNullOrEmpty(_decryptIndexPath) || _decryptService == null)
        {
            RequestShowError?.Invoke("Validation", "Please select and load a backup file.");
            return;
        }

        if (_decryptService.LoadResult == null)
        {
            RequestShowError?.Invoke("Validation",
                "Backup not loaded. Please reselect the file and enter the key.");
            return;
        }

        IsDecrypting = true;
        StageText = "Preparing...";
        ProgressPercent = 0;
        SpeedText = "Speed: 0 MB/s";
        EtaText = "ETA: --:--";
        _decryptStartTime = DateTime.Now;

        string outputDir = OutputPath;
        string originalName = _decryptService.LoadResult.OriginalName;
        var service = _decryptService;

        var progress = new Progress<RdrfProgressReport>(UpdateDecryptProgress);

        System.Threading.Tasks.Task.Run(() =>
        {
            try
            {
                Directory.CreateDirectory(outputDir);
                string outputFilePath = Path.Combine(outputDir, originalName);

                bool success = service.Restore(outputFilePath, progress);

                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (success)
                    {
                        RequestSaveConfig?.Invoke();
                        RequestShowSuccess?.Invoke("Decryption completed successfully!", null);
                    }
                    else
                    {
                        RequestShowWarning?.Invoke("Decryption incomplete",
                            "Decryption failed. Some fragments may be missing or corrupted.");
                    }
                });
            }
            catch (Exception ex)
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    RequestShowError?.Invoke("Decryption failed", ex.Message);
                });
            }
            finally
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    IsDecrypting = false;
                });
            }
        });
    }

    private void UpdateDecryptProgress(RdrfProgressReport report)
    {
        StageText = report.Stage;
        ProgressPercent = report.TotalBytes > 0 ? (double)report.CurrentBytes / report.TotalBytes * 100 : 0;

        TimeSpan elapsed = DateTime.Now - _decryptStartTime;
        if (elapsed.TotalSeconds > 0.5 && report.CurrentBytes > 0)
        {
            double speedBytesPerSec = report.CurrentBytes / elapsed.TotalSeconds;
            double speedMBps = speedBytesPerSec / (1024 * 1024);
            SpeedText = $"Speed: {speedMBps:F2} MB/s";

            if (speedBytesPerSec > 0 && report.TotalBytes > report.CurrentBytes)
            {
                long remainingBytes = report.TotalBytes - report.CurrentBytes;
                double etaSeconds = remainingBytes / speedBytesPerSec;
                EtaText = $"ETA: {FormatEta(etaSeconds)}";
            }
            else
            {
                EtaText = "ETA: --:--";
            }
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            StopFragmentWatcher();
            _decryptService?.Dispose();
            _disposed = true;
        }
    }

    private static string FormatFileSize(long bytes)
    {
        string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
        int counter = 0;
        decimal number = bytes;
        while (Math.Round(number / 1024) >= 1)
        {
            number /= 1024;
            counter++;
        }
        return $"{number:n1} {suffixes[counter]}";
    }

    private static string FormatEta(double seconds)
    {
        if (seconds < 60)
            return $"{(int)seconds}s";
        else if (seconds < 3600)
        {
            int mins = (int)(seconds / 60);
            int secs = (int)(seconds % 60);
            return $"{mins}:{secs:D2}";
        }
        else
        {
            int hours = (int)(seconds / 3600);
            int mins = (int)((seconds % 3600) / 60);
            return $"{hours}h {mins}m";
        }
    }
}

public class FragmentStatusItem
{
    public string Index { get; set; } = string.Empty;
    public Brush Brush { get; set; } = Brushes.Gray;
}
