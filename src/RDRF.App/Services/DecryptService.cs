using System.IO;
using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.Index;
using RDRF.Core.Encryption;
using RDRF.Core.Storage;

namespace RDRF.App.Services;

public class BackupLoadResult
{
    public string Fingerprint { get; init; } = string.Empty;
    public string FilePrefix { get; init; } = string.Empty;
    public string OriginalName { get; init; } = string.Empty;
    public long FileSize { get; init; }
    public string FssStrategy { get; init; } = string.Empty;
    public string StrategyDisplay { get; init; } = string.Empty;
    public int FragmentCount { get; init; }
    public DateTime CreatedAt { get; init; }
}

public class FragmentStatusInfo
{
    public int Index { get; init; }
    public bool Available { get; init; }
}

public class DecryptService : IDisposable
{
    private readonly byte[] _rcCode;
    private readonly byte[] _aesKey;
    private string? _storagePath;
    private byte[]? _encryptedIndex;
    private bool _disposed;

    public BackupLoadResult? LoadResult { get; private set; }
    public bool IsFragmentMode { get; private set; }
    public string? FilePrefix => LoadResult?.FilePrefix;
    public string? StoragePath => _storagePath;

    public DecryptService(byte[]? password)
    {
        if (password == null || password.Length == 0)
            throw new ArgumentException("Password is required", nameof(password));
        _rcCode = Rfc2898DeriveBytes.Pbkdf2(
            password,
            EncryptionLayer.PasswordSalt,
            600_000,
            HashAlgorithmName.SHA256,
            32);
        _aesKey = EncryptionLayer.DeriveKey(_rcCode);
    }

    public BackupLoadResult LoadFromIndex(string storagePath, string indexPath)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        _storagePath = storagePath;
        IsFragmentMode = false;
        _encryptedIndex = File.ReadAllBytes(indexPath);

        var index = RDRFEngine.DecryptIndex(_encryptedIndex, _aesKey);
        LoadResult = ToResult(index);
        return LoadResult;
    }

    public BackupLoadResult LoadFromFragment(string storagePath, string filePrefix)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        _storagePath = storagePath;
        IsFragmentMode = true;
        _encryptedIndex = null;

        var storage = new LocalFileAdapter(storagePath);

        byte[]? fragData = null;
        for (int i = 0; ; i++)
        {
            string fragPath = $"{filePrefix}_{i}.rdrf";
            if (storage.FragmentExists(fragPath))
            {
                fragData = storage.ReadFragment(fragPath);
                break;
            }
            if (i > 1000) break;
        }

        if (fragData == null)
            throw new FileNotFoundException($"No fragments found with prefix '{filePrefix}' in {storagePath}");

        if (!FragmentFileHeader.HasHeader(fragData))
            throw new InvalidDataException(
                "Fragment does not contain an embedded index. " +
                "This backup was created with an older version of RDRF " +
                "and requires the standalone index file.");

        var (embeddedIndexBytes, _) = RDRFEngine.DecryptFragment(fragData, _aesKey);
        if (embeddedIndexBytes == null)
            throw new InvalidDataException("Fragment does not contain an embedded index.");

        var index = RDRFEngine.DeserializeIndex(embeddedIndexBytes);
        LoadResult = ToResult(index);
        return LoadResult;
    }

    public List<FragmentStatusInfo> ScanFragments()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (LoadResult == null || string.IsNullOrEmpty(_storagePath))
            return new List<FragmentStatusInfo>();

        var storage = new LocalFileAdapter(_storagePath);
        var result = new List<FragmentStatusInfo>();

        for (int i = 0; i < LoadResult.FragmentCount; i++)
        {
            string fragPath = $"{LoadResult.FilePrefix}_{i}.rdrf";
            result.Add(new FragmentStatusInfo
            {
                Index = i,
                Available = storage.FragmentExists(fragPath)
            });
        }

        return result;
    }

    public bool Restore(string outputPath, IProgress<RdrfProgressReport>? progress)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (LoadResult == null)
            throw new InvalidOperationException("No backup loaded. Call LoadFromIndex or LoadFromFragment first.");

        if (string.IsNullOrEmpty(_storagePath))
            throw new InvalidOperationException("Storage path not set.");

        var storage = new LocalFileAdapter(_storagePath);
        var engine = new RDRFEngine(_aesKey, storage, preDerived: true, recoveryCode: _rcCode);

        if (IsFragmentMode)
        {
            return engine.RestoreFileFromFragments(LoadResult.FilePrefix, outputPath, progress: progress);
        }
        else
        {
            if (_encryptedIndex == null)
                throw new InvalidOperationException("Index data not loaded.");
            return engine.RestoreFileFromIndexData(_encryptedIndex, LoadResult.FilePrefix, outputPath, progress: progress);
        }
    }

    private static BackupLoadResult ToResult(RdrfIndex index)
    {
        bool hasFss6 = index.Fss6FragentBlockMaps != null || index.Fss6RcBlockMap != null;
        return new BackupLoadResult
        {
            Fingerprint = index.FileFingerprint,
            FilePrefix = index.CustomName ?? index.FileFingerprint,
            OriginalName = index.OriginalName,
            FileSize = index.FileSize,
            FssStrategy = index.FssStrategy,
            StrategyDisplay = hasFss6 && index.FssStrategy != "FSS6"
                ? index.FssStrategy + " + FSS6"
                : index.FssStrategy,
            FragmentCount = index.FragentCount,
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(index.CreatedAt).LocalDateTime,
        };
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            if (_rcCode is { Length: > 0 })
                CryptographicOperations.ZeroMemory(_rcCode);
            if (_aesKey is { Length: > 0 })
                CryptographicOperations.ZeroMemory(_aesKey);
            _disposed = true;
        }
        GC.SuppressFinalize(this);
    }
}
