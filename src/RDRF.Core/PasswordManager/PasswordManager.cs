using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using RDRF.Core.Configuration;

namespace RDRF.Core.PasswordManager;

public class PasswordManager
{
    private PasswordStore? _store;

    public void Initialize()
    {
        string userDir = RdrfConfig.RootDir;
        _store = new PasswordStore(userDir);
    }

    internal void InitializeForTest(string testDir)
    {
        _store = new PasswordStore(testDir);
    }

    public void Set(string key, string value)
    {
        EnsureStore();
        string encoded = Convert.ToBase64String(EncryptValue(value));
        _store!.UpsertKey(new PasswordEntry
        {
            Key = key,
            Value = encoded,
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        });
    }

    public void Set(string key, byte[] value)
    {
        EnsureStore();
        string encoded = Convert.ToBase64String(EncryptValueBytes(value));
        _store!.UpsertKey(new PasswordEntry
        {
            Key = key,
            Value = encoded,
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        });
    }

    public string? GetByKey(string key)
    {
        EnsureStore();
        var entry = _store!.GetByKey(key);
        if (entry == null) return null;
        try
        {
            return DecryptValue(Convert.FromBase64String(entry.Value));
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[PasswordManager] Failed to decrypt value for key '{key}': {ex.Message}");
            return null;
        }
    }

    public void AttachHash(string key, string indexHash)
    {
        EnsureStore();
        _store!.AddBackup(new BackupEntry
        {
            Key = key,
            IndexHash = indexHash,
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        });
    }

    public string? GetByIndexHash(string indexHash)
    {
        EnsureStore();
        var entry = _store!.GetByHash(indexHash);
        if (entry == null) return null;
        return GetByKey(entry.Key);
    }

    public bool Delete(string key)
    {
        EnsureStore();
        return _store!.DeleteKey(key);
    }

    public string[] ListKeys()
    {
        EnsureStore();
        return _store!.ListKeys();
    }

    public BackupInfo[] GetKeyDetail(string key)
    {
        EnsureStore();
        var backups = _store!.GetBackups(key);
        return backups.Select(b => new BackupInfo
        {
            IndexHash = b.IndexHash,
            CreatedAt = b.CreatedAt,
        }).ToArray();
    }

    public class BackupInfo
    {
        public string IndexHash { get; set; } = "";
        public long CreatedAt { get; set; }
    }

    private void EnsureStore()
    {
        if (_store == null)
            Initialize();
    }

    private byte[] EncryptValue(string value)
    {
        byte[] key = DeriveValueKey();
        byte[] plaintext = Encoding.UTF8.GetBytes(value);
        try
        {
            return EncryptBytes(key, plaintext);
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    private byte[] EncryptValueBytes(byte[] value)
    {
        byte[] key = DeriveValueKey();
        return EncryptBytes(key, value);
    }

    private static byte[] EncryptBytes(byte[] key, byte[] plaintext)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        byte[] result = new byte[12 + ciphertext.Length + 16];
        Buffer.BlockCopy(nonce, 0, result, 0, 12);
        Buffer.BlockCopy(ciphertext, 0, result, 12, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, 12 + ciphertext.Length, 16);
        return result;
    }

    private string DecryptValue(byte[] encrypted)
    {
        if (encrypted.Length < 12 + 16)
            throw new InvalidDataException("Invalid encrypted value");

        byte[] key = DeriveValueKey();
        byte[] nonce = new byte[12];
        byte[] ciphertext = new byte[encrypted.Length - 12 - 16];
        byte[] tag = new byte[16];
        Buffer.BlockCopy(encrypted, 0, nonce, 0, 12);
        Buffer.BlockCopy(encrypted, 12, ciphertext, 0, ciphertext.Length);
        Buffer.BlockCopy(encrypted, 12 + ciphertext.Length, tag, 0, 16);

        byte[] plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return Encoding.UTF8.GetString(plaintext);
    }

    private static byte[] DeriveValueKey()
    {
        return MachineKey.Derive();
    }
}
