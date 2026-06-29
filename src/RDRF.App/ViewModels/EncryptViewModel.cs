using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Input;
using RDRF.App.Services;
using RDRF.Core;

namespace RDRF.App.ViewModels;

public class EncryptViewModel : ViewModelBase
{
    private string _selectedStrategy = "FSS1";
    private string? _encryptFilePath;
    private string? _tempZipPath;
    private DateTime _encryptStartTime;

    private bool _isEncrypting;
    private bool _showProgress;
    private string _stageText = "Preparing...";
    private double _progressPercent;
    private string _speedText = "Speed: 0 MB/s";
    private string _etaText = "ETA: --:--";

    private string _outputPath = "./backup";
    private int _fragmentSizeMB = 1;
    private string _customName = "";
    private string _filePathDisplay = "No file selected...";

    private string _configDir = "";

    public event Action<string, string, string?>? RequestShowError;
    public event Action<string, string?>? RequestShowSuccess;
    public event Action? RequestSaveConfig;

    public string SelectedStrategy
    {
        get => _selectedStrategy;
        set => SetProperty(ref _selectedStrategy, value);
    }

    private bool _isFsaEnabled;
    public bool IsFsaEnabled
    {
        get => _isFsaEnabled;
        set
        {
            if (SetProperty(ref _isFsaEnabled, value) && !value)
            {
                FsaPrimaryStrategy = null;
                IsFsaAuxSelected = false;
            }
        }
    }

    private string? _fsaPrimaryStrategy;
    public string? FsaPrimaryStrategy
    {
        get => _fsaPrimaryStrategy;
        set => SetProperty(ref _fsaPrimaryStrategy, value);
    }

    private bool _isFsaAuxSelected;
    public bool IsFsaAuxSelected
    {
        get => _isFsaAuxSelected;
        set => SetProperty(ref _isFsaAuxSelected, value);
    }

    public string? EncryptFilePath
    {
        get => _encryptFilePath;
        set => SetProperty(ref _encryptFilePath, value);
    }

    public string FilePathDisplay
    {
        get => _filePathDisplay;
        set => SetProperty(ref _filePathDisplay, value);
    }

    public string OutputPath
    {
        get => _outputPath;
        set => SetProperty(ref _outputPath, value);
    }

    public int FragmentSizeMB
    {
        get => _fragmentSizeMB;
        set => SetProperty(ref _fragmentSizeMB, value);
    }

    public string CustomName
    {
        get => _customName;
        set => SetProperty(ref _customName, value);
    }

    public bool IsEncrypting
    {
        get => _isEncrypting;
        set
        {
            if (SetProperty(ref _isEncrypting, value))
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

    public string ConfigDir
    {
        get => _configDir;
        set => _configDir = value;
    }

    public ICommand BrowseFileCommand { get; }
    public ICommand BrowseOutputCommand { get; }
    public ICommand StartEncryptCommand { get; }

    public EncryptViewModel()
    {
        BrowseFileCommand = new RelayCommand(_ => BrowseFile());
        BrowseOutputCommand = new RelayCommand(_ => BrowseOutput());
        StartEncryptCommand = new RelayCommand(_ => StartEncrypt());
    }

    private void BrowseFile()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select File to Encrypt",
            Filter = "All Files (*.*)|*.*"
        };
        if (dialog.ShowDialog() == true)
        {
            EncryptFilePath = dialog.FileName;
            FilePathDisplay = Path.GetFileName(dialog.FileName);
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
            if (!string.IsNullOrEmpty(folder))
                OutputPath = folder;
        }
    }

    public void SetDroppedFiles(string[] files)
    {
        try
        {
            CleanupTempZip();

            if (files.Length == 1 && File.Exists(files[0]))
            {
                EncryptFilePath = files[0];
                FilePathDisplay = Path.GetFileName(files[0]);
            }
            else
            {
                string zipPath = PackFilesToZip(files);
                EncryptFilePath = zipPath;
                _tempZipPath = zipPath;
                FilePathDisplay = Path.GetFileName(zipPath) + " (auto-packed)";
            }
        }
        catch (Exception ex)
        {
            RequestShowError?.Invoke("Failed to process dropped files", ex.Message, ex.ToString());
        }
    }

    private string PackFilesToZip(string[] paths)
    {
        string tempDir = _configDir;
        Directory.CreateDirectory(tempDir);

        string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        string zipPath = Path.Combine(tempDir, $"backup_{timestamp}.zip");

        using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            foreach (string path in paths)
            {
                if (File.Exists(path))
                {
                    string entryName = Path.GetFileName(path);
                    archive.CreateEntryFromFile(path, entryName);
                }
                else if (Directory.Exists(path))
                {
                    string dirName = Path.GetFileName(path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
                    AddDirectoryToZip(archive, path, dirName);
                }
            }
        }

        return zipPath;
    }

    private static void AddDirectoryToZip(ZipArchive archive, string sourceDir, string entryBasePath)
    {
        foreach (string file in Directory.GetFiles(sourceDir))
        {
            string entryName = string.IsNullOrEmpty(entryBasePath)
                ? Path.GetFileName(file)
                : Path.Combine(entryBasePath, Path.GetFileName(file));
            archive.CreateEntryFromFile(file, entryName);
        }

        foreach (string dir in Directory.GetDirectories(sourceDir))
        {
            string dirName = Path.GetFileName(dir);
            string subEntryPath = string.IsNullOrEmpty(entryBasePath)
                ? dirName
                : Path.Combine(entryBasePath, dirName);
            AddDirectoryToZip(archive, dir, subEntryPath);
        }
    }

    public void CleanupTempZip()
    {
        if (!string.IsNullOrEmpty(_tempZipPath) && File.Exists(_tempZipPath))
        {
            try
            {
                File.Delete(_tempZipPath);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Debug.WriteLine($"[RDRF] Temp zip cleanup failed: {ex.Message}");
            }
            _tempZipPath = null;
        }
    }

    public void StartEncrypt()
    {
        // Diagnostic: append to a file that we can check
        try
        {
            string log = $"[{DateTime.Now:HH:mm:ss.fff}] StartEncrypt called. " +
                $"File='{EncryptFilePath}' pw={_pendingPassword?.Length ?? -1} sz={FragmentSizeMB} out='{OutputPath}'" +
                Environment.NewLine;
            System.IO.File.AppendAllText(@"C:\Users\admin\Desktop\rdrf_start.txt", log);
        }
        catch { }

        if (string.IsNullOrEmpty(EncryptFilePath))
        {
            RequestShowError?.Invoke("Validation", "Please select a file to encrypt.", null);
            return;
        }

        if (_pendingPassword == null || _pendingPassword.Length == 0)
        {
            RequestShowError?.Invoke("Validation", "Please enter an encryption key.", null);
            return;
        }

        if (FragmentSizeMB < 1)
        {
            RequestShowError?.Invoke("Validation", "Please enter a valid fragment size (minimum 1 MB).", null);
            return;
        }

        string? customName = null;
        string customNameInput = CustomName.Trim();
        if (!string.IsNullOrEmpty(customNameInput))
        {
            foreach (char c in customNameInput)
            {
                if (!char.IsLetterOrDigit(c) && c != '_' && c != '-')
                {
                    RequestShowError?.Invoke("Validation",
                        "Custom name can only contain letters, numbers, underscores and hyphens.", null);
                    return;
                }
            }
            customName = customNameInput;
        }

        int fragmentSizeBytes = FragmentSizeMB * 1024 * 1024;

        IsEncrypting = true;
        StageText = "Preparing...";
        ProgressPercent = 0;
        SpeedText = "Speed: 0 MB/s";
        EtaText = "ETA: --:--";
        _encryptStartTime = DateTime.Now;

        byte[] password = _pendingPassword!;
        string outputPath = OutputPath;
        string filePath = EncryptFilePath!;
        string strategy = SelectedStrategy;
        int fragSize = fragmentSizeBytes;
        string? custName = customName;
        string configDir = _configDir;

        var progress = new Progress<RdrfProgressReport>(UpdateEncryptProgress);

        System.Threading.Tasks.Task.Run(() =>
        {
            try
            {
                var adapter = new RDRF.Core.Dssa.LocalDssaAdapter(outputPath);
                using var service = new EncryptService(password, adapter);

                string primaryStrategy = strategy;
                List<string>? auxiliary = null;

                if (IsFsaEnabled && !string.IsNullOrEmpty(FsaPrimaryStrategy))
                {
                    primaryStrategy = FsaPrimaryStrategy;
                    auxiliary = new List<string> { "FSS6" };
                }

                string fingerprint = service.BackupFile(
                    filePath,
                    primaryStrategy,
                    auxiliary,
                    fragmentSize: fragSize,
                    customName: custName,
                    progress: progress
                );

                System.Windows.Application.Current.Dispatcher.Invoke(() =>
                {
                    RequestSaveConfig?.Invoke();
                    RequestShowSuccess?.Invoke("Encryption completed successfully!", fingerprint);
                });
            }
            catch (Exception ex)
            {
                try
                {
                    System.IO.File.AppendAllText(
                        @"C:\Users\admin\Desktop\rdrf_error.txt",
                        $"[{DateTime.Now:HH:mm:ss}] Backup failed: {ex}{Environment.NewLine}");
                }
                catch { }
                try
                {
                    System.Windows.Application.Current.Dispatcher.Invoke(() =>
                    {
                        RequestShowError?.Invoke("Encryption failed", ex.Message, ex.ToString());
                    });
                }
                catch { }
            }
            finally
            {
                System.Windows.Application.Current.Dispatcher.Invoke(() =>
                {
                    IsEncrypting = false;
                    CleanupTempZip();
                });
            }
        });
    }

    private byte[]? _pendingPassword;

    public void SetPassword(string password) => _pendingPassword = Encoding.UTF8.GetBytes(password);

    public void ClearPassword()
    {
        if (_pendingPassword != null)
        {
            CryptographicOperations.ZeroMemory(_pendingPassword);
            _pendingPassword = null;
        }
    }

    private void UpdateEncryptProgress(RdrfProgressReport report)
    {
        StageText = report.Stage;
        ProgressPercent = report.TotalBytes > 0 ? (double)report.CurrentBytes / report.TotalBytes * 100 : 0;

        TimeSpan elapsed = DateTime.Now - _encryptStartTime;
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

