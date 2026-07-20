using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Input;
using RDRF.Core.Configuration;
using RDRF.Core.PasswordManager;

namespace RDRF.App.ViewModels;

public class PasswordItem : ViewModelBase
{
    private string _key = "";
    private string _created = "";

    public string Key { get => _key; set => SetProperty(ref _key, value); }
    public string Created { get => _created; set => SetProperty(ref _created, value); }
}

public class PasswordViewModel : ViewModelBase
{
    private readonly PasswordManager _manager;
    private bool _overlayVisible;
    private string _newKey = "";

    public ObservableCollection<PasswordItem> Items { get; } = new();

    public bool OverlayVisible
    {
        get => _overlayVisible;
        set => SetProperty(ref _overlayVisible, value);
    }

    public string NewKey
    {
        get => _newKey;
        set => SetProperty(ref _newKey, value);
    }

    public ICommand ShowAddCommand { get; }
    public ICommand HideOverlayCommand { get; }
    public ICommand DeleteCommand { get; }
    public ICommand RefreshCommand { get; }

    public PasswordViewModel()
    {
        RdrfConfig.Initialize();
        _manager = new PasswordManager();
        _manager.Initialize();

        ShowAddCommand = new RelayCommand(_ =>
        {
            NewKey = "";
            OverlayVisible = true;
        });
        HideOverlayCommand = new RelayCommand(_ => OverlayVisible = false);
        DeleteCommand = new RelayCommand(_ => DeleteSelected(), _ => SelectedItem != null);
        RefreshCommand = new RelayCommand(_ => Refresh());

        Refresh();
    }

    public void SubmitAddWithPassword(string password)
    {
        if (string.IsNullOrWhiteSpace(NewKey) || string.IsNullOrWhiteSpace(password)) return;
        try
        {
            _manager.Set(NewKey, password);
            OverlayVisible = false;
            Refresh();
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[PasswordViewModel] Add failed: {ex.Message}");
        }
    }

    private PasswordItem? _selectedItem;
    public PasswordItem? SelectedItem
    {
        get => _selectedItem;
        set
        {
            if (SetProperty(ref _selectedItem, value))
            {
                ((RelayCommand)DeleteCommand).RaiseCanExecuteChanged();
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public void Refresh()
    {
        try
        {
            var keys = _manager.ListKeys();
            Items.Clear();
            Debug.WriteLine($"[PasswordViewModel] Refresh: {keys.Length} keys");
            foreach (var key in keys)
            {
                var detail = _manager.GetKeyDetail(key);
                Items.Add(new PasswordItem
                {
                    Key = key,
                    Created = detail.Length > 0
                        ? DateTimeOffset.FromUnixTimeSeconds(detail[0].CreatedAt).LocalDateTime.ToString("yyyy-MM-dd HH:mm")
                        : "",
                });
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[PasswordViewModel] Refresh failed: {ex.Message}");
        }
        SelectedItem = null;
    }

    public string? GetPassword(string key) => _manager.GetByKey(key);

    public Func<string, string, bool>? ShowConfirmDialog { get; set; }

    private void DeleteSelected()
    {
        if (SelectedItem == null) return;
        if (ShowConfirmDialog != null)
        {
            if (!ShowConfirmDialog("Confirm Delete", $"Delete FastPassword '{SelectedItem.Key}'?"))
                return;
        }
        _manager.Delete(SelectedItem.Key);
        Refresh();
    }
}
