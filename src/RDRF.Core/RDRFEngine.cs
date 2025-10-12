using System.Security.Cryptography;
using RDRF.Core.Index;
using RDRF.Core.Dssa;

namespace RDRF.Core;

public class RDRFEngine : IDisposable
{
    private readonly BackupOrchestrator _backup;
    private readonly RestoreOrchestrator _restore;
    private readonly DssaAdapter _storage;
    private readonly byte[] _rcCode;

    public RDRFEngine(byte[] key, DssaAdapter storage, FSS.FSSEngine? fssEngine = null)
    {
        if (key == null || key.Length == 0)
            throw new ArgumentException("Key cannot be null or empty", nameof(key));
        _rcCode = (byte[])key.Clone();
        _storage = storage ?? throw new ArgumentNullException(nameof(storage));
        _backup = new BackupOrchestrator(_rcCode, storage, fssEngine);
        _restore = new RestoreOrchestrator(_rcCode, storage, fssEngine);
    }

    public RDRFEngine(byte[] key, DssaAdapter storage, bool preDerived, byte[]? recoveryCode, FSS.FSSEngine? fssEngine = null)
    {
        if ((key == null || key.Length == 0) && (recoveryCode == null || recoveryCode.Length == 0))
            throw new ArgumentException("Key cannot be null or empty", nameof(key));
        _rcCode = (recoveryCode ?? key)?.Clone() as byte[] ?? throw new ArgumentNullException(nameof(key));
        _storage = storage;
        _backup = new BackupOrchestrator(key, storage, fssEngine, preDerived, _rcCode);
        _restore = new RestoreOrchestrator(key, storage, fssEngine, preDerived, _rcCode);
    }

    // ── Backup ──

    public string BackupFile(
        string filePath,
        string fssStrategy = "FSS1",
        List<string>? auxiliaryStrategies = null,
        string? originalFilename = null,
        int fragmentSize = 0,
        string? customName = null,
        IProgress<RdrfProgressReport>? progress = null)
        => _backup.BackupFile(filePath, fssStrategy, auxiliaryStrategies, originalFilename, fragmentSize, customName, progress);

    public string BackupFile(
        FileInfo filePath,
        string fssStrategy = "FSS1",
        List<string>? auxiliary = null,
        int fragmentSize = 0,
        string? customName = null,
        IProgress<RdrfProgressReport>? progress = null)
        => BackupFile(filePath.FullName, fssStrategy, auxiliary, fragmentSize: fragmentSize, customName: customName, progress: progress);

    // ── Restore ──

    public bool RestoreFile(
        string fileFingerprint,
        string outputPath,
        bool allowFssRecovery = true,
        string? filePrefix = null,
        IProgress<RdrfProgressReport>? progress = null)
        => _restore.RestoreFile(fileFingerprint, outputPath, allowFssRecovery, filePrefix, progress);

    public bool RestoreFile(
        string fileFingerprint,
        FileInfo outputPath,
        bool allowFssRecovery = true,
        string? filePrefix = null,
        IProgress<RdrfProgressReport>? progress = null)
        => _restore.RestoreFile(fileFingerprint, outputPath.FullName, allowFssRecovery, filePrefix, progress);

    public Task<bool> RestoreFileAsync(
        string fileFingerprint,
        string outputPath,
        bool allowFssRecovery = true,
        string? filePrefix = null,
        IProgress<RdrfProgressReport>? progress = null,
        CancellationToken cancellationToken = default)
        => _restore.RestoreFileAsync(fileFingerprint, outputPath, allowFssRecovery, filePrefix, progress, cancellationToken);

    // ── Restore From Fragments ──

    public Task<string> BackupFileAsync(
        string filePath,
        string fssStrategy = "FSS1",
        List<string>? auxiliaryStrategies = null,
        string? originalFilename = null,
        int fragmentSize = 0,
        string? customName = null,
        IProgress<RdrfProgressReport>? progress = null,
        CancellationToken cancellationToken = default)
        => _backup.BackupFileAsync(filePath, fssStrategy, auxiliaryStrategies, originalFilename, fragmentSize, customName, progress, cancellationToken);

    public bool RestoreFileFromFragments(
        string filePrefix,
        string outputPath,
        bool allowFssRecovery = true,
        IProgress<RdrfProgressReport>? progress = null)
        => _restore.RestoreFileFromFragments(filePrefix, outputPath, allowFssRecovery, progress);

    public bool RestoreFileFromIndexData(
        byte[] encryptedIndex,
        string filePrefix,
        string outputPath,
        bool allowFssRecovery = true,
        IProgress<RdrfProgressReport>? progress = null)
        => _restore.RestoreFileFromIndexData(encryptedIndex, filePrefix, outputPath, allowFssRecovery, progress);

    public Task<bool> RestoreFileFromFragmentsAsync(
        string filePrefix,
        string outputPath,
        bool allowFssRecovery = true,
        IProgress<RdrfProgressReport>? progress = null,
        CancellationToken cancellationToken = default)
        => _restore.RestoreFileFromFragmentsAsync(filePrefix, outputPath, allowFssRecovery, progress, cancellationToken);

    // ── Utility Methods ──

    public bool FileExists(string fileFingerprint) => _storage.IndexExists(fileFingerprint);

    // ── Dispose ──

    public void Dispose()
    {
        if (_rcCode != null && _rcCode.Length > 0)
            CryptographicOperations.ZeroMemory(_rcCode);
        _backup.Dispose();
        _restore.Dispose();
        GC.SuppressFinalize(this);
    }
}
