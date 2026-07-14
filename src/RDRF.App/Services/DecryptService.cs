using System.IO;
using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.Index;
using RDRF.Core.Encryption;
using RDRF.Core.DSAA;

namespace RDRF.App.Services;

/// <summary>
/// Restore service wrapper for index/fragment loading and recovery.
/// </summary>
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

public class DecryptService : IDecryptService
{
    private readonly byte[] _rcCode;
    private byte[] _aesKey;
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
        _rcCode = (byte[])password.Clone();
        _aesKey = EncryptionLayer.DeriveKeyLegacy(_rcCode);
    }

    public BackupLoadResult LoadFromIndex(string storagePath, string indexPath)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        _storagePath = storagePath;
        IsFragmentMode = false;
        _encryptedIndex = File.ReadAllBytes(indexPath);

        (_aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(_encryptedIndex, _rcCode);
        var index = IndexManager.DeserializeIndex(cbor);
        LoadResult = ToResult(index);
        return LoadResult;
    }

    public BackupLoadResult LoadFromFragment(string storagePath, string filePrefix)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        _storagePath = storagePath;
        IsFragmentMode = true;
        _encryptedIndex = null;

        var storage = new LocalDSAAAdapter(storagePath);

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

        // Try v2 header with embedded salt first, fall back to SHA256
        byte[] fragAesKey = _aesKey;
        byte[]? fragSalt = null;
        try
        {
            var firstTry = FragmentFileHeader.DecryptWithEmbeddedIndex(fragData, fragAesKey);
            fragSalt = firstTry.salt;
            if (fragSalt != null && fragSalt.Length > 0)
            {
                fragAesKey = EncryptionLayer.DeriveKey(_rcCode, fragSalt);
                var secondTry = FragmentFileHeader.DecryptWithEmbeddedIndex(fragData, fragAesKey);
                _aesKey = fragAesKey;
                var index = IndexManager.DeserializeIndex(secondTry.embeddedIndex!);
                LoadResult = ToResult(index);
                return LoadResult;
            }
            var index2 = IndexManager.DeserializeIndex(firstTry.embeddedIndex!);
            LoadResult = ToResult(index2);
            return LoadResult;
        }
        catch (CryptographicException)
        {
            throw new CryptographicException("Decryption failed. Check your key or the backup may be corrupted.");
        }
    }

    public List<FragmentStatusInfo> ScanFragments()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (LoadResult == null || string.IsNullOrEmpty(_storagePath))
            return new List<FragmentStatusInfo>();

        var storage = new LocalDSAAAdapter(_storagePath);
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

        var storage = new LocalDSAAAdapter(_storagePath);
        using var engine = new RDRFEngine(_aesKey, _rcCode, storage);

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
        bool hasFss6 = index.Fss6FragmentBlockMaps != null || index.Fss6RcBlockMap != null;
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
            FragmentCount = index.FragmentCount,
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




