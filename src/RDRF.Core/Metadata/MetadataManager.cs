using RDRF.Core.Logging;using System.Diagnostics;
using System.Text.Json;

namespace RDRF.Core.Metadata;

/// <summary>
/// Thread-safe JSON metadata store with backup record tracking and persistence.
/// </summary>

public class MetadataManager
{
    private static readonly object _fileLock = new();

    private readonly string _filePath;
    private MetadataStore _store;
    private readonly ReaderWriterLockSlim _lock = new(LockRecursionPolicy.SupportsRecursion);
    private Timer? _saveTimer;
    private int _savePending;

    public MetadataManager(string? filePath = null) : this(filePath, skipLoad: false) { }

    internal MetadataManager(string? filePath, bool skipLoad)
    {
        _filePath = filePath ?? Path.Combine(Directory.GetCurrentDirectory(), "rdrf_metadata.json");
        _store = new MetadataStore();
        if (!skipLoad) Load();
    }

    private void Load()
    {
        MetadataStore? loaded;
        try
        {
            if (!File.Exists(_filePath)) { loaded = null; }
            else
            {
                string json = File.ReadAllText(_filePath);
                loaded = JsonSerializer.Deserialize<MetadataStore>(json);
            }
        }
        catch (Exception ex)
        {
            RdrfLogger.Default.Debug("",$"Failed to load metadata file '{_filePath}': {ex.Message}");
            loaded = null;
        }

        if (loaded != null)
            _store = loaded;
    }

    private void Save()
    {
        _lock.EnterWriteLock();
        try { SaveNoLock(); }
        finally { _lock.ExitWriteLock(); }
    }

    private void SaveNoLock()
    {
        string? dir = Path.GetDirectoryName(_filePath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        string json = JsonSerializer.Serialize(_store, new JsonSerializerOptions { WriteIndented = true });

        lock (_fileLock)
        {
            string tmpPath = _filePath + ".tmp";
            File.WriteAllText(tmpPath, json);
            File.Move(tmpPath, _filePath, overwrite: true);
        }
    }

    private void ScheduleSave()
    {
        if (Interlocked.Exchange(ref _savePending, 1) == 0)
        {
            _saveTimer?.Dispose();
            _saveTimer = new Timer(_ =>
            {
                Interlocked.Exchange(ref _savePending, 0);
                Save();
            }, null, 500, Timeout.Infinite);
        }
    }

    // -- Backup Records --

    public void SaveBackup(
        string fileFingerprint,
        string originalFilename,
        long originalSize,
        string originalHash,
        string fssStrategy,
        List<string> fragmentHashes,
        string storageBackend = "local")
    {
        _lock.EnterWriteLock();
        try
        {
            string now = DateTimeOffset.UtcNow.ToString("o");
            _store.Backups[fileFingerprint] = new BackupRecord
            {
                FileFingerprint = fileFingerprint,
                OriginalFilename = originalFilename,
                OriginalSize = originalSize,
                OriginalHash = originalHash,
                FssStrategy = fssStrategy,
                FragmentCount = fragmentHashes.Count,
                StorageBackend = storageBackend,
                CreatedAt = now
            };

            var fragments = new List<FragmentRecord>();
            for (int i = 0; i < fragmentHashes.Count; i++)
            {
                fragments.Add(new FragmentRecord
                {
                    FragmentIndex = i,
                    Hash = fragmentHashes[i],
                    Status = "ok",
                    CheckedAt = now
                });
            }
            _store.Fragments[fileFingerprint] = fragments;
            SaveNoLock();
        }
        finally { _lock.ExitWriteLock(); }
    }

    public void DeleteBackup(string fileFingerprint)
    {
        _lock.EnterWriteLock();
        try
        {
            _store.Backups.Remove(fileFingerprint);
            _store.Fragments.Remove(fileFingerprint);
            SaveNoLock();
        }
        finally { _lock.ExitWriteLock(); }
    }

    public Dictionary<string, object>? GetBackup(string fileFingerprint)
    {
        _lock.EnterReadLock();
        try
        {
            if (_store.Backups.TryGetValue(fileFingerprint, out var b))
            {
                return new Dictionary<string, object>
                {
                    ["file_fingerprint"] = b.FileFingerprint,
                    ["original_filename"] = b.OriginalFilename,
                    ["original_size"] = b.OriginalSize,
                    ["original_hash"] = b.OriginalHash,
                    ["fss_strategy"] = b.FssStrategy,
                    ["fragment_count"] = b.FragmentCount,
                    ["storage_backend"] = b.StorageBackend,
                    ["created_at"] = b.CreatedAt,
                };
            }
            return null;
        }
        finally { _lock.ExitReadLock(); }
    }

    public List<Dictionary<string, object>> ListBackups(int limit = 50)
    {
        _lock.EnterReadLock();
        try
        {
            return _store.Backups.Values
                .OrderByDescending(b => b.CreatedAt)
                .Take(limit)
                .Select(b => new Dictionary<string, object>
                {
                    ["file_fingerprint"] = b.FileFingerprint,
                    ["original_filename"] = b.OriginalFilename,
                    ["original_size"] = b.OriginalSize,
                    ["fss_strategy"] = b.FssStrategy,
                    ["fragment_count"] = b.FragmentCount,
                    ["created_at"] = b.CreatedAt,
                })
                .ToList();
        }
        finally { _lock.ExitReadLock(); }
    }

    // -- Fragment Status --

    public void MarkFragmentOk(string fileFingerprint, int fragmentIndex)
    {
        _lock.EnterWriteLock();
        try { UpdateFragmentStatus(fileFingerprint, fragmentIndex, "ok"); }
        finally { _lock.ExitWriteLock(); }
    }

    public void MarkFragmentMissing(string fileFingerprint, int fragmentIndex)
    {
        _lock.EnterWriteLock();
        try { UpdateFragmentStatus(fileFingerprint, fragmentIndex, "missing"); }
        finally { _lock.ExitWriteLock(); }
    }

    public void MarkFragmentCorrupt(string fileFingerprint, int fragmentIndex)
    {
        _lock.EnterWriteLock();
        try { UpdateFragmentStatus(fileFingerprint, fragmentIndex, "corrupt"); }
        finally { _lock.ExitWriteLock(); }
    }

    private void UpdateFragmentStatus(string fileFingerprint, int fragmentIndex, string status)
    {
        if (!_store.Fragments.TryGetValue(fileFingerprint, out var fragments)) return;
        string now = DateTimeOffset.UtcNow.ToString("o");
        var fragment = fragments.FirstOrDefault(f => f.FragmentIndex == fragmentIndex);
        if (fragment != null)
        {
            fragment.Status = status;
            fragment.CheckedAt = now;
            ScheduleSave();
        }
    }

    public Dictionary<int, string> GetFragmentStatus(string fileFingerprint)
    {
        _lock.EnterReadLock();
        try
        {
            if (_store.Fragments.TryGetValue(fileFingerprint, out var fragments))
                return fragments.ToDictionary(f => f.FragmentIndex, f => f.Status);
            return new Dictionary<int, string>();
        }
        finally { _lock.ExitReadLock(); }
    }
}

// -- Data models --

/// <summary>
/// Thread-safe JSON metadata store with backup record tracking and persistence.
/// </summary>

public class MetadataStore
{
    public Dictionary<string, BackupRecord> Backups { get; set; } = new();
    public Dictionary<string, List<FragmentRecord>> Fragments { get; set; } = new();
}

/// <summary>
/// Thread-safe JSON metadata store with backup record tracking and persistence.
/// </summary>

public class BackupRecord
{
    public string FileFingerprint { get; set; } = "";
    public string OriginalFilename { get; set; } = "";
    public long OriginalSize { get; set; }
    public string OriginalHash { get; set; } = "";
    public string FssStrategy { get; set; } = "";
    public int FragmentCount { get; set; }
    public string StorageBackend { get; set; } = "local";
    public string CreatedAt { get; set; } = "";
}

/// <summary>
/// Thread-safe JSON metadata store with backup record tracking and persistence.
/// </summary>

public class FragmentRecord
{
    public int FragmentIndex { get; set; }
    public string Hash { get; set; } = "";
    public string Status { get; set; } = "ok";
    public string CheckedAt { get; set; } = "";
}

