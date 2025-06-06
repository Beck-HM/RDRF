using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using RDRF.Core;
using RDRF.Core.Versioning;
using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Core.Storage;

namespace RDRF.App.ViewModels;

public class VersionHistoryItem
{
    public int Version { get; set; }
    public string Timestamp { get; set; } = "";
    public string Message { get; set; } = "";
    public string Diff { get; set; } = "";
}

public class HistoryViewModel : ViewModelBase
{
    private string? _backupFilePath;
    private string? _storagePath;
    private string? _fingerprint;
    private string? _incrementalFilePath;
    private string _indexPathDisplay = "No file selected...";
    private string _incrementalDisplay = "";
    private byte[]? _password;
    private string _commitMessage = "";
    private bool _showIncrementalSection;
    private bool _showVersionHistory;
    private bool _showDiffPanel;
    private bool _isLoading;
    private string _statusText = "";
    private string _diffContent = "";
    private VersionHistoryItem? _selectedItem;

    public event Action<string, string>? RequestShowError;
    public event Action<string, string?>? RequestShowSuccess;
    public event Action<string, string?>? RequestShowWarning;

    public string IndexPathDisplay
    {
        get => _indexPathDisplay;
        set => SetProperty(ref _indexPathDisplay, value);
    }

    public string IncrementalDisplay
    {
        get => _incrementalDisplay;
        set => SetProperty(ref _incrementalDisplay, value);
    }

    public string CommitMessage
    {
        get => _commitMessage;
        set => SetProperty(ref _commitMessage, value);
    }

    public bool ShowIncrementalSection
    {
        get => _showIncrementalSection;
        set => SetProperty(ref _showIncrementalSection, value);
    }

    public bool ShowVersionHistory
    {
        get => _showVersionHistory;
        set => SetProperty(ref _showVersionHistory, value);
    }

    public bool ShowDiffPanel
    {
        get => _showDiffPanel;
        set => SetProperty(ref _showDiffPanel, value);
    }

    public bool IsLoading
    {
        get => _isLoading;
        set => SetProperty(ref _isLoading, value);
    }

    public string StatusText
    {
        get => _statusText;
        set => SetProperty(ref _statusText, value);
    }

    public string DiffContent
    {
        get => _diffContent;
        set => SetProperty(ref _diffContent, value);
    }

    public VersionHistoryItem? SelectedItem
    {
        get => _selectedItem;
        set
        {
            if (SetProperty(ref _selectedItem, value))
                OnSelectedVersionChanged();
        }
    }

    public ObservableCollection<VersionHistoryItem> Versions { get; } = new();

    public System.Windows.Input.ICommand BrowseBackupCommand { get; }
    public System.Windows.Input.ICommand BrowseIncrementalCommand { get; }
    public System.Windows.Input.ICommand ApplyIncrementalCommand { get; }

    public HistoryViewModel()
    {
        BrowseBackupCommand = new RelayCommand(_ => BrowseBackup());
        BrowseIncrementalCommand = new RelayCommand(_ => BrowseIncremental());
        ApplyIncrementalCommand = new RelayCommand(_ => ApplyIncremental(), _ => CanApplyIncremental());
    }

    public void SetPassword(string password)
    {
        if (_password != null)
            CryptographicOperations.ZeroMemory(_password);
        _password = System.Text.Encoding.UTF8.GetBytes(password);
        if (!string.IsNullOrEmpty(_backupFilePath) && _password is { Length: > 0 })
            LoadHistory();
    }

    public void ClearPassword()
    {
        if (_password != null)
        {
            CryptographicOperations.ZeroMemory(_password);
            _password = null;
        }
    }

    private void BrowseBackup()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select RDRF Backup File",
            Filter = "RDRF Files (*.indrdrf;*.rdrf)|*.indrdrf;*.rdrf|All Files (*.*)|*.*"
        };

        if (dialog.ShowDialog() == true)
        {
            _backupFilePath = dialog.FileName;
            _storagePath = Path.GetDirectoryName(dialog.FileName);
            _fingerprint = null;

            string ext = Path.GetExtension(dialog.FileName).ToLowerInvariant();
            if (ext == ".rdrf")
            {
                string name = Path.GetFileNameWithoutExtension(dialog.FileName);
                int us = name.LastIndexOf('_');
                if (us > 0 && int.TryParse(name[(us + 1)..], out _))
                    _fingerprint = name[..us];
            }

            IndexPathDisplay = Path.GetFileName(dialog.FileName);
            ShowVersionHistory = false;
            ShowDiffPanel = false;
            Versions.Clear();
            DiffContent = "";

            if (_password is { Length: > 0 })
                LoadHistory();
        }
    }

    private void BrowseIncremental()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select New Content to Add",
            Filter = "All Files (*.*)|*.*"
        };

        if (dialog.ShowDialog() == true)
        {
            _incrementalFilePath = dialog.FileName;
            IncrementalDisplay = Path.GetFileName(dialog.FileName);
            ShowIncrementalSection = true;
        }
    }

    private bool CanApplyIncremental()
    {
        return !string.IsNullOrEmpty(_incrementalFilePath)
            && File.Exists(_incrementalFilePath)
            && _password is { Length: > 0 }
            && !string.IsNullOrEmpty(_commitMessage)
            && !string.IsNullOrEmpty(_storagePath);
    }

    private void ApplyIncremental()
    {
        if (!CanApplyIncremental()) return;

        try
        {
            IsLoading = true;
            StatusText = "Applying incremental backup...";

            System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    string fp = VersionedBackup.BackupAsync(
                        _incrementalFilePath!,
                        _storagePath!,
                        _password!,
                        _commitMessage
                    ).GetAwaiter().GetResult();

                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        _fingerprint = fp;
                        StatusText = "Incremental backup applied successfully.";
                        LoadHistory();
                        RequestShowSuccess?.Invoke("Incremental backup completed.", null);
                    });
                }
                catch (Exception ex)
                {
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        RequestShowError?.Invoke("Incremental backup failed", ex.Message);
                    });
                }
                finally
                {
                    Application.Current.Dispatcher.Invoke(() => IsLoading = false);
                }
            });
        }
        catch (Exception ex)
        {
            RequestShowError?.Invoke("Error", ex.Message);
            IsLoading = false;
        }
    }

    private void LoadHistory()
    {
        if (string.IsNullOrEmpty(_storagePath) || _password is not { Length: > 0 })
            return;

        try
        {
            Versions.Clear();
            ShowVersionHistory = false;
            ShowDiffPanel = false;
            DiffContent = "";

            var records = VersionedRestore.GetVersionHistory(_storagePath, _password);
            if (records.Count == 0)
            {
                StatusText = "No version history found for this backup.";
                return;
            }

            foreach (var r in records)
            {
                Versions.Add(new VersionHistoryItem
                {
                    Version = r.Version,
                    Timestamp = DateTimeOffset.FromUnixTimeSeconds(r.CreatedAt).LocalDateTime.ToString("yyyy-MM-dd HH:mm"),
                    Message = r.UserMessage,
                    Diff = r.SystemDiff
                });
            }

            ShowVersionHistory = true;
            StatusText = $"{records.Count} version(s) found.";
        }
        catch (Exception ex)
        {
            StatusText = $"Failed to load history: {ex.Message}";
            Debug.WriteLine($"[RDRF] History load failed: {ex}");
        }
    }

    private void OnSelectedVersionChanged()
    {
        if (_selectedItem != null && !string.IsNullOrEmpty(_selectedItem.Diff))
        {
            DiffContent = _selectedItem.Diff;
            ShowDiffPanel = true;
        }
        else
        {
            DiffContent = "";
            ShowDiffPanel = false;
        }
    }
}
