using System.Security.Cryptography;
using RDRF.Core.Encryption;
using RDRF.Core.FSS;
using RDRF.Core.Index;
using RDRF.Core.Dssa;

namespace RDRF.Core;

/// <summary>
/// Top-level public facade for backup and restore operations.
///
/// Call chain:
///   External caller -> RDRFEngine.BackupFile/BackupFileAsync
///     -> BackupOrchestrator.BackupFile/BackupFileAsync
///       -> stream read -> fragment -> LZ4 -> FSS encode -> AES-CTR encrypt -> write
///
///   External caller -> RDRFEngine.RestoreFile/RestoreFileAsync
///     -> RestoreOrchestrator.RestoreFile/RestoreFileAsync
///       -> read -> AES-CTR decrypt -> FSS decode -> LZ4 decompress -> merge
///
/// Two constructors provide flexibility:
///   (byte[] rcCode, ...) - derives the AES key from rcCode via DeriveKeyLegacy.
///   (byte[] aesKey, byte[] rcCode, ...) - accepts a pre-derived AES key
///     for callers that already have it.
///
/// Dispose zeroes the rcCode from memory and disposes the orchestrators.
/// </summary>
public class RDRFEngine : IDisposable
{
    private readonly BackupOrchestrator _backup;
    private readonly RestoreOrchestrator _restore;
    private readonly DssaAdapter _storage;
    private readonly byte[] _rcCode;

    /// <summary>
    /// Initializes the engine with a raw rcCode. The AES key is derived
    /// from rcCode via EncryptionLayer.DeriveKeyLegacy.
    /// </summary>
    public RDRFEngine(byte[] rcCode, DssaAdapter storage, FSS.FSSEngine? fssEngine = null)
    {
        _rcCode = (byte[])rcCode.Clone();
        _storage = storage ?? throw new ArgumentNullException(nameof(storage));
        byte[] aesKey = EncryptionLayer.DeriveKeyLegacy(rcCode);
        var fssWrapped = fssEngine is not null ? new FSSEngineWrapper(fssEngine) : null;
        _backup = new BackupOrchestrator(aesKey, _rcCode, storage, fssWrapped);
        _restore = new RestoreOrchestrator(aesKey, _rcCode, storage, fssWrapped);
    }

    /// <summary>
    /// Initializes the engine with a pre-derived AES key and the
    /// original rcCode (for memory zeroing on dispose).
    /// </summary>
    public RDRFEngine(byte[] aesKey, byte[] rcCode, DssaAdapter storage, FSS.FSSEngine? fssEngine = null)
    {
        _rcCode = (byte[])rcCode.Clone();
        _storage = storage ?? throw new ArgumentNullException(nameof(storage));
        var fssWrapped2 = fssEngine is not null ? new FSSEngineWrapper(fssEngine) : null;
        _backup = new BackupOrchestrator(aesKey, _rcCode, storage, fssWrapped2);
        _restore = new RestoreOrchestrator(aesKey, _rcCode, storage, fssWrapped2);
    }

    // -- Backup --

    /// <summary>
    /// Synchronous backup. Reads the file, splits into fragments, compresses
    /// with LZ4, FSS-encodes, AES-CTR encrypts, and writes to storage.
    /// </summary>
    /// <param name="filePath">Path to the source file.</param>
    /// <param name="fssStrategy">FSS strategy (FSS1..FSS6.2).</param>
    /// <param name="auxiliaryStrategies">Auxiliary strategies for FSA fusion (currently disabled).</param>
    /// <param name="originalFilename">Original filename to store in the index (for display).</param>
    /// <param name="fragmentSize">Fragment size in bytes (default 1 MB).</param>
    /// <param name="customName">Custom prefix for fragment files (defaults to fingerprint).</param>
    /// <param name="progress">Progress reporter.</param>
    /// <returns>The file fingerprint (XxHash128 of raw content, hex).</returns>
    public string BackupFile(
        string filePath,
        string fssStrategy = "FSS1",
        List<string>? auxiliaryStrategies = null,
        string? originalFilename = null,
        int fragmentSize = 0,
        string? customName = null,
        IProgress<RdrfProgressReport>? progress = null)
        => _backup.BackupFile(filePath, fssStrategy, auxiliaryStrategies, originalFilename, fragmentSize, customName, progress);

    /// <summary>
    /// Synchronous backup accepting a FileInfo instead of a path string.
    /// </summary>
    public string BackupFile(
        FileInfo filePath,
        string fssStrategy = "FSS1",
        List<string>? auxiliary = null,
        int fragmentSize = 0,
        string? customName = null,
        IProgress<RdrfProgressReport>? progress = null)
        => BackupFile(filePath.FullName, fssStrategy, auxiliary, fragmentSize: fragmentSize, customName: customName, progress: progress);

    // -- Restore --

    /// <summary>
    /// Synchronous restore. Reads encrypted fragments, AES-CTR decrypts,
    /// FSS-decodes, LZ4 decompresses, and writes the reconstructed file.
    /// </summary>
    /// <param name="fileFingerprint">The fingerprint identifying the backup.</param>
    /// <param name="outputPath">Path for the restored output file.</param>
    /// <param name="allowFssRecovery">If true, tolerates missing fragments and attempts FSS repair.</param>
    /// <param name="filePrefix">Custom fragment prefix (defaults to fingerprint).</param>
    /// <param name="progress">Progress reporter.</param>
    /// <returns>True if the file was fully restored (possibly via FSS recovery).</returns>
    public bool RestoreFile(
        string fileFingerprint,
        string outputPath,
        bool allowFssRecovery = true,
        string? filePrefix = null,
        IProgress<RdrfProgressReport>? progress = null)
        => _restore.RestoreFile(fileFingerprint, outputPath, allowFssRecovery, filePrefix, progress);

    /// <summary>
    /// Synchronous restore accepting a FileInfo for the output path.
    /// </summary>
    public bool RestoreFile(
        string fileFingerprint,
        FileInfo outputPath,
        bool allowFssRecovery = true,
        string? filePrefix = null,
        IProgress<RdrfProgressReport>? progress = null)
        => _restore.RestoreFile(fileFingerprint, outputPath.FullName, allowFssRecovery, filePrefix, progress);

    /// <summary>
    /// Asynchronous restore. Same pipeline as RestoreFile but cancellable.
    /// </summary>
    public Task<bool> RestoreFileAsync(
        string fileFingerprint,
        string outputPath,
        bool allowFssRecovery = true,
        string? filePrefix = null,
        IProgress<RdrfProgressReport>? progress = null,
        CancellationToken cancellationToken = default)
        => _restore.RestoreFileAsync(fileFingerprint, outputPath, allowFssRecovery, filePrefix, progress, cancellationToken);

    // -- Backup Async --

    /// <summary>
    /// Asynchronous backup. Streams the file, hashes incrementally,
    /// splits into fragments, compresses, FSS-encodes, and encrypts.
    /// Cancellation is supported.
    /// </summary>
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

    // -- Fragment-Based Restore --

    /// <summary>
    /// Restore from fragment files without an index file. Uses the first
    /// fragment's embedded header to locate all fragments.
    /// </summary>
    public bool RestoreFileFromFragments(
        string filePrefix,
        string outputPath,
        bool allowFssRecovery = true,
        IProgress<RdrfProgressReport>? progress = null)
        => _restore.RestoreFileFromFragments(filePrefix, outputPath, allowFssRecovery, progress);

    /// <summary>
    /// Restore from an in-memory encrypted index (e.g. loaded from a remote
    /// source or from streaming). The index is decrypted with AutoDetect,
    /// fragments are read from storage, decrypted, decoded, and merged.
    /// </summary>
    public bool RestoreFileFromIndexData(
        byte[] encryptedIndex,
        string filePrefix,
        string outputPath,
        bool allowFssRecovery = true,
        IProgress<RdrfProgressReport>? progress = null)
        => _restore.RestoreFileFromIndexData(encryptedIndex, filePrefix, outputPath, allowFssRecovery, progress);

    /// <summary>
    /// Asynchronous fragment-based restore. Cancellation supported.
    /// </summary>
    public Task<bool> RestoreFileFromFragmentsAsync(
        string filePrefix,
        string outputPath,
        bool allowFssRecovery = true,
        IProgress<RdrfProgressReport>? progress = null,
        CancellationToken cancellationToken = default)
        => _restore.RestoreFileFromFragmentsAsync(filePrefix, outputPath, allowFssRecovery, progress, cancellationToken);

    // -- Utility Methods --

    /// <summary>Returns true if an index file exists for the given fingerprint.</summary>
    public bool FileExists(string fileFingerprint) => _storage.IndexExists(fileFingerprint);

    // -- Dispose --

    /// <summary>
    /// Zeroes the rcCode from memory and disposes the orchestrators.
    /// </summary>
    public void Dispose()
    {
        if (_rcCode != null && _rcCode.Length > 0)
            CryptographicOperations.ZeroMemory(_rcCode);
        _backup.Dispose();
        _restore.Dispose();
        GC.SuppressFinalize(this);
    }
}
