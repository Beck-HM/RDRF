using System.Security.Cryptography;
using System.Text.Json;

namespace RDRF.Core.PasswordManager;

internal class PasswordStore
{
    private readonly string _filePath;
    private readonly string _dir;
    private readonly byte[] _encKey;
    private List<PasswordEntry> _keys = new();
    private List<BackupEntry> _backups = new();
    private Dictionary<string, PasswordEntry> _byKey = new();
    private Dictionary<string, BackupEntry> _byHash = new();

    public PasswordStore(string userDir)
    {
        _dir = userDir;
        _filePath = Path.Combine(_dir, "passwords.dat");
        _encKey = MachineKey.Derive();
        Load();
    }

    public PasswordEntry? GetByKey(string key)
    {
        _byKey.TryGetValue(key, out var entry);
        return entry;
    }

    public BackupEntry? GetByHash(string indexHash)
    {
        _byHash.TryGetValue(indexHash, out var entry);
        return entry;
    }

    public void UpsertKey(PasswordEntry entry)
    {
        _byKey[entry.Key] = entry;
        var existing = _keys.FindIndex(e => e.Key == entry.Key);
        if (existing >= 0)
            _keys[existing] = entry;
        else
            _keys.Add(entry);
        Save();
    }

    public void AddBackup(BackupEntry entry)
    {
        _backups.Add(entry);
        _byHash[entry.IndexHash] = entry;
        Save();
    }

    public bool DeleteKey(string key)
    {
        bool removed = _byKey.Remove(key);
        int idx = _keys.FindIndex(e => e.Key == key);
        if (idx >= 0) _keys.RemoveAt(idx);
        _backups.RemoveAll(b => b.Key == key);
        foreach (var dead in _backups.Where(b => b.Key == key).ToList())
            _byHash.Remove(dead.IndexHash);
        if (removed) Save();
        return removed;
    }

    public string[] ListKeys() => _keys.Select(e => e.Key).ToArray();

    public IReadOnlyList<BackupEntry> GetBackups(string key)
        => _backups.Where(b => b.Key == key).ToList();

    private void Load()
    {
        if (!File.Exists(_filePath))
        {
            _keys = new List<PasswordEntry>();
            _backups = new List<BackupEntry>();
            _byKey = new Dictionary<string, PasswordEntry>();
            _byHash = new Dictionary<string, BackupEntry>();
            return;
        }

        try
        {
            byte[] encrypted = File.ReadAllBytes(_filePath);
            byte[] plaintext = Decrypt(encrypted);
            var doc = JsonSerializer.Deserialize<StoreDocument>(plaintext)
                ?? new StoreDocument();

            _keys = doc.Keys ?? new List<PasswordEntry>();
            _backups = doc.Backups ?? new List<BackupEntry>();
            _byKey = _keys.ToDictionary(e => e.Key, e => e);
            _byHash = _backups.ToDictionary(e => e.IndexHash, e => e);
        }
        catch
        {
            _keys = new List<PasswordEntry>();
            _backups = new List<BackupEntry>();
            _byKey = new Dictionary<string, PasswordEntry>();
            _byHash = new Dictionary<string, BackupEntry>();
        }
    }

    private void Save()
    {
        var doc = new StoreDocument
        {
            Keys = _keys,
            Backups = _backups,
        };
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(doc, new JsonSerializerOptions { WriteIndented = true });
        byte[] encrypted = Encrypt(plaintext);
        Directory.CreateDirectory(_dir);
        File.WriteAllBytes(_filePath, encrypted);
    }

    private byte[] Encrypt(byte[] plaintext)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        using var aes = new AesGcm(_encKey, 16);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        byte[] result = new byte[12 + ciphertext.Length + 16];
        Buffer.BlockCopy(nonce, 0, result, 0, 12);
        Buffer.BlockCopy(ciphertext, 0, result, 12, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, 12 + ciphertext.Length, 16);
        return result;
    }

    private byte[] Decrypt(byte[] encrypted)
    {
        if (encrypted.Length < 12 + 16)
            throw new InvalidDataException("Invalid encrypted store");

        byte[] nonce = new byte[12];
        byte[] ciphertext = new byte[encrypted.Length - 12 - 16];
        byte[] tag = new byte[16];
        Buffer.BlockCopy(encrypted, 0, nonce, 0, 12);
        Buffer.BlockCopy(encrypted, 12, ciphertext, 0, ciphertext.Length);
        Buffer.BlockCopy(encrypted, 12 + ciphertext.Length, tag, 0, 16);

        byte[] plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(_encKey, 16);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }

    private class StoreDocument
    {
        public List<PasswordEntry>? Keys { get; set; }
        public List<BackupEntry>? Backups { get; set; }
    }
}
