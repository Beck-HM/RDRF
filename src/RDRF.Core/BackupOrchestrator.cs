using System.Diagnostics;
using RDRF.Core.Abstractions;
using RDRF.Core.Logging;
using System.Buffers;
using System.IO.Hashing;
using System.Security.Cryptography;
using System.Text.Json;
using RDRF.Core.Compression;
using RDRF.Core.Compression.Ckc;
using RDRF.Core.Encryption;
using RDRF.Core.ETN;
using RDRF.Core.FragmentEngine;
using RDRF.Core.FSS;
using RDRF.Core.FSA;
using RDRF.Core.Index;
using RDRF.Core.Integrity;
using RDRF.Core.Metadata;
using RDRF.Core.DSAA;

namespace RDRF.Core;

/// <summary>
/// Core backup pipeline orchestrator. Manages the full lifecycle of a backup:
///
/// Pipeline:
///   Stream read -> Incremental SHA-256 hash -> Fragment (adaptive size)
///   -> FSS encode (strategy-dependent)
///   -> Compress (FSS6.1/6.2: before ETN; others: after ETN)
///   -> ETN inject (FSS6.x) -> Fountain repair data (FSS6.1/6.2) -> repair trailers
///   -> Encrypt with slim embedded index -> Batch encrypt+write
///   -> Write standalone Index file -> Write RC file -> Save metadata
///
/// Two constructors:
///   (aesKey, rcCode, ...) - callers that already have a derived AES key.
///   (rcCode, storage, salt, ...) - derives AES key via PBKDF2 with salt.
/// </summary>
public class BackupOrchestrator : IDisposable
{
    private readonly byte[] _rcCode;
    private readonly byte[] _aesKey;
    private readonly byte[] _salt;
    private readonly DSAAAdapter _storage;
    private readonly IFSSEngine _fss;
    private readonly IFsaEngine _fsa;
    private readonly IMetadataManager _metadata;
    private readonly IEncryptionLayer _encryption;
    private readonly IIndexManager _indexManager;
    private readonly RdrfLogger _logger;

    /// <summary>
    /// Initializes with a pre-derived AES key. Used by callers that have
    /// already performed key derivation (e.g. RDRFEngine with DeriveKeyLegacy).
    /// </summary>
    public BackupOrchestrator(
        byte[] aesKey,
        byte[] rcCode,
        DSAAAdapter storage,
        IFSSEngine? fssEngine = null,
        IFsaEngine? fsaEngine = null,
        IMetadataManager? metadata = null,
        IEncryptionLayer? encryption = null,
        IIndexManager? indexManager = null,
        RdrfLogger? logger = null)
    {
        _aesKey = aesKey?.Clone() as byte[] ?? throw new ArgumentNullException("AES key required");
        _rcCode = rcCode?.Clone() as byte[] ?? [];
        _salt = [];
        _storage = storage ?? throw new ArgumentNullException(nameof(storage));
        _fss = fssEngine ?? new FSSEngineWrapper();
        _fsa = fsaEngine ?? new FsaEngineWrapper();
        _metadata = metadata ?? new MetadataManagerWrapper();
        _encryption = encryption ?? new EncryptionLayerWrapper();
        _indexManager = indexManager ?? new IndexManagerWrapper();
        _logger = logger ?? new RdrfLogger();
    }

    /// <summary>
    /// Initializes with a raw rcCode and salt. The AES key is derived via
    /// EncryptionLayer.DeriveKey(rcCode, salt) using PBKDF2.
    /// </summary>
    public BackupOrchestrator(
        byte[] rcCode,
        DSAAAdapter storage,
        byte[] salt,
        IFSSEngine? fssEngine = null,
        IFsaEngine? fsaEngine = null,
        IMetadataManager? metadata = null,
        IEncryptionLayer? encryption = null,
        IIndexManager? indexManager = null,
        RdrfLogger? logger = null)
    {
        if (rcCode == null || rcCode.Length == 0)
            throw new ArgumentException("RC code cannot be null or empty", nameof(rcCode));
        _rcCode = (byte[])rcCode.Clone();
        _salt = salt ?? throw new ArgumentNullException(nameof(salt));
        _encryption = encryption ?? new EncryptionLayerWrapper();
        _indexManager = indexManager ?? new IndexManagerWrapper();
        _aesKey = _encryption.DeriveKey(rcCode, salt);
        _storage = storage ?? throw new ArgumentNullException(nameof(storage));
        _fss = fssEngine ?? new FSSEngineWrapper();
        _fsa = fsaEngine ?? new FsaEngineWrapper();
        _metadata = metadata ?? new MetadataManagerWrapper();
        _logger = logger ?? new RdrfLogger();
    }

    /// <summary>
    /// Asynchronous backup entry point.
    /// </summary>
    public Task<string> BackupFileAsync(
        string filePath,
        string fssStrategy = "FSS1",
        List<string>? auxiliaryStrategies = null,
        string? originalFilename = null,
        int fragmentSize = 0,
        string? customName = null,
        IProgress<RdrfProgressReport>? progress = null,
        CancellationToken cancellationToken = default,
        string? compressionMethod = null,
        string? compressionOptions = null)
        => BackupCoreAsync(filePath, fssStrategy, auxiliaryStrategies, originalFilename, fragmentSize, customName, progress, cancellationToken, compressionMethod, compressionOptions);

    /// <summary>
    /// Asynchronous backup with FileInfo.
    /// </summary>
    public Task<string> BackupFileAsync(
        FileInfo filePath,
        string fssStrategy = "FSS1",
        List<string>? auxiliary = null,
        int fragmentSize = 0,
        string? customName = null,
        IProgress<RdrfProgressReport>? progress = null,
        CancellationToken cancellationToken = default)
        => BackupFileAsync(filePath.FullName, fssStrategy, auxiliary, fragmentSize: fragmentSize, customName: customName, progress: progress, cancellationToken: cancellationToken);

    /// <summary>
    /// Core backup pipeline (private, async).
    ///
    /// Pipeline phases:
    ///   Phase 1 - Stream & fragment:
    ///     Open a FileStream, read sequentially, fill 1 MB fragment buffers,
    ///     compute SHA256 incrementally, LZ4-compress each fragment, pad to
    ///     fragment size boundary. Accumulates rawFragments (uncompressed for
    ///     dedup hashing) and originalFragments (LZ4 + padded for encoding).
    ///
    ///   Phase 2 - FSS encode:
    ///     Execute the FSA plan's EncodeSteps. Each step applies an FSS strategy
    ///     (encode or etn_inject) to the fragment list. The number of fragments
    ///     may grow (parity fragments) or stay the same.
    ///
    ///   Phase 3 - ETN + fountain repair:
    ///     If FSS6.x is active, inject ETN cross-validation block maps into
    ///     Index, fragments, and RC. For FSS6.1/6.2, generate fountain code
    ///     repair data (LT or Duip) and append repair trailers to fragments.
    ///
    ///   Phase 4 - Encrypt & write:
    ///     Each fragment is prepended with an encrypted header containing an
    ///     embedded (stripped) Index. Fragments are encrypted with AES-CTR
    ///     via FragmentFileHeader.EncryptWithEmbeddedIndex. Written in batches
    ///     of 8 with Parallel.ForEachAsync and retry logic.
    ///
    ///   Phase 5 - Index + RC write:
    ///     The standalone Index file (with full ETN block maps) is AES-CTR
    ///     encrypted and written. If salt-based key derivation is active, the
    ///     salt is prepended. The RC file (recovery container) is encrypted
    ///     and written separately.
    ///
    /// Call chain:
    ///   RDRFEngine.BackupFileAsync
    ///   -> BackupOrchestrator.BackupCoreAsync
    ///     -> FsaEngine.Compute (plan)
    ///     -> FileStream + IncrementalHash (Phase 1)
    ///     -> FSSEngine.Encode (Phase 2)
    ///     -> Fss6Etn.InjectCrossValidation (Phase 3)
    ///     -> FssRepairService.Generate61/62 (Phase 3)
    ///     -> FragmentFileHeader.EncryptWithEmbeddedIndex (Phase 4)
    ///     -> DSAAAdapter.WriteFragmentAsync (Phase 4)
    ///     -> EncryptionLayer.EncryptIndexWithKey/SaltPrefix (Phase 5)
    ///     -> DSAAAdapter.WriteIndexAsync / WriteRcAsync (Phase 5)
    ///     -> MetadataManager.SaveBackup
    /// </summary>
    private async Task<string> BackupCoreAsync(
        string filePath,
        string fssStrategy,
        List<string>? auxiliaryStrategies,
        string? originalFilename,
        int fragmentSize,
        string? customName,
        IProgress<RdrfProgressReport>? progress,
        CancellationToken cancellationToken,
        string? compressionMethod = null,
        string? compressionOptions = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var fileInfo = new FileInfo(filePath);
        string filename = originalFilename ?? fileInfo.Name;
        long fileSize = fileInfo.Length;

        const long maxFileSize = 16L * 1024 * 1024 * 1024; // 16 GB
        if (fileSize > maxFileSize)
            throw new RdrfException(ErrorCode.FileTooLarge, $"File too large ({fileSize:N0} bytes). Maximum supported size is {maxFileSize:N0} bytes.");

        _logger.Info("BackupOrchestrator", $"Backing up: {filename} ({fileSize:N0} bytes)");

        int fragSize = Constants.ComputeFragmentSize(fileSize, fragmentSize > 0 ? fragmentSize : null);
        string cm = compressionMethod ?? Constants.CompressionLz4;
        string originalHash;
        string fileFingerprint;

        // Multi-strategy (auxiliary) temporarily disabled; single-strategy only.
        var plan = _fsa.Compute(fssStrategy, null);
        var phaseSw = Stopwatch.StartNew();

        // Fast path: pure FSS1 + non-CKC → O(window) two-pass pipeline (no full encoded set in RAM).
        if (BackupPhases.Fss1WindowedPipeline.IsEligible(plan, cm))
        {
            return await BackupFss1WindowedAsync(
                filePath, fragSize, fileSize, filename, customName, plan, cm, compressionOptions,
                progress, cancellationToken).ConfigureAwait(false);
        }

        // Phase 1: Stream file -> hash -> split raw
        var readResult = await BackupPhases.BackupReadPhase.ExecuteAsync(
            filePath, fragSize, progress, cancellationToken,
            compressionMethod, compressionOptions).ConfigureAwait(false);
        fileFingerprint = readResult.FileFingerprint;
        originalHash = readResult.OriginalHash;
        long msRead = phaseSw.ElapsedMilliseconds;

        progress?.Report(new RdrfProgressReport { Stage = "Read", CurrentBytes = fileSize, TotalBytes = fileSize,
            CurrentItem = readResult.OriginalFragmentCount, TotalItems = readResult.OriginalFragmentCount });

        _logger.Info("BackupOrchestrator",
            $"Phase 1: Read {fileSize:N0} bytes, {readResult.OriginalFragmentCount} raw fragments in {msRead} ms");

        // Phase 2: FSS encode all fragments
        progress?.Report(new RdrfProgressReport { Stage = "Encode", CurrentItem = 0, TotalItems = 1 });
        phaseSw.Restart();
        // Own the raw list so FSS1 can null slots as it window-releases neighbors.
        var workRaw = new List<byte[]>(readResult.OriginalFragments);
        var fragments = EncodeViaPlan(workRaw, plan);
        // Drop raw aliases for GC: FSS1/2 zeroed raw during encode; others release unreferenced.
        ReleaseRawAfterEncode(readResult, fragments, plan.EffectivePrimary);
        long msEncode = phaseSw.ElapsedMilliseconds;
        progress?.Report(new RdrfProgressReport { Stage = "Encode", CurrentItem = fragments.Count, TotalItems = fragments.Count });
        _logger.Info("BackupOrchestrator", $"Phase 2: Encode ({plan.EffectivePrimary}) {fragments.Count} frags in {msEncode} ms");

        string filePrefix = customName ?? fileFingerprint;

        // Hash encoded fragments in parallel (fast hex path); only encoded set is resident.
        var fragmentHashes = new string[fragments.Count];
        if (RDRF.Core.Device.GpuContext.IsAvailable)
        {
            var rawHashes = RDRF.Core.Device.GpuHasher.HashSHA256(fragments);
            for (int i = 0; i < fragments.Count; i++)
            {
                var sb = new System.Text.StringBuilder(64);
                for (int j = 0; j < 32; j++) sb.Append(rawHashes[i * 32 + j].ToString("x2"));
                fragmentHashes[i] = sb.ToString();
            }
        }
        else
        {
            await Parallel.ForEachAsync(Enumerable.Range(0, fragments.Count),
                new ParallelOptions { MaxDegreeOfParallelism = Constants.DefaultParallelism, CancellationToken = cancellationToken }, (i, ct) =>
            {
                fragmentHashes[i] = IntegrityChecker.HashBytes(fragments[i]);
                return ValueTask.CompletedTask;
            }).ConfigureAwait(false);
        }

        var embeddedIndex = IndexManager.BuildIndex(
            fileFingerprint: fileFingerprint,
            originalFilename: filename,
            originalSize: fileSize,
            fragmentHashes: fragmentHashes.ToList(),
            originalHash: originalHash,
            fssStrategy: plan.EffectivePrimary,
            originalFragmentSizes: new List<int>(readResult.OriginalFragmentSizes),
            originalFragmentCount: readResult.OriginalFragmentCount,
            fssParams: new Dictionary<string, object>
            {
                ["plan"] = JsonSerializer.SerializeToElement(plan)
            });

        if (!string.IsNullOrEmpty(customName))
            embeddedIndex.CustomName = customName;
        if (_salt.Length > 0)
            embeddedIndex.Salt = Hex.EncodeLower(_salt);
        embeddedIndex.Compression = cm;

        // RawFragmentHashes = XxHash128 of UNCOMPRESSED data (content-addressable dedup key)
        embeddedIndex.RawFragmentHashes = readResult.RawHashes;

        byte[] serializedIndex = _indexManager.SerializeIndex(embeddedIndex);

        Fss61RepairData? repairA = null, repairC = null;
        Fss62RepairData? repair62A = null, repair62C = null;
        byte[] rcBytes;
        byte[] finalSerializedIndex;
        progress?.Report(new RdrfProgressReport { Stage = "Protect", CurrentItem = 0, TotalItems = fragments.Count });
        phaseSw.Restart();
        (fragments, rcBytes, repairA, repairC, repair62A, repair62C, finalSerializedIndex) =
            await RunFssPipelineAsync(fragments, serializedIndex, embeddedIndex,
                filePrefix, fileSize, plan, cm, compressionOptions, cancellationToken);
        long msProtect = phaseSw.ElapsedMilliseconds;
        progress?.Report(new RdrfProgressReport { Stage = "Protect", CurrentItem = fragments.Count, TotalItems = fragments.Count });
        _logger.Info("BackupOrchestrator", $"Phase Protect (compress/ETN/repair): {msProtect} ms");

        // Slim embedded index in fragment headers (standalone Index keeps full BM/history).
        byte[] embeddedIndexBytes = Fss6Etn.StripForEmbeddedHeader(finalSerializedIndex);

        // Phase 3: Encrypt+write per fragment in parallel (pipeline: no second batch of ciphertext residency).
        var writtenFragments = new System.Collections.Concurrent.ConcurrentDictionary<string, byte>();
        bool indexWritten = false, rcWritten = false;

        try
        {
            string fPrefix = filePrefix;
            byte[] eib = embeddedIndexBytes;
            byte[] ak = _aesKey;
            byte[]? slt = _salt.Length > 0 ? _salt : null;
            int nFrags = fragments.Count;
            phaseSw.Restart();

            await Parallel.ForEachAsync(Enumerable.Range(0, nFrags),
                new ParallelOptions { MaxDegreeOfParallelism = Constants.DefaultParallelism, CancellationToken = cancellationToken },
                async (i, ct) =>
                {
                    byte[] plain = fragments[i];
                    string fname = Frags.FragmentFilename(fPrefix, i);
                    for (int retry = 0; ; retry++)
                    {
                        try
                        {
                            // Stream encrypt → temp file → atomic move (no long-lived ciphertext array)
                            await _storage.WriteFragmentViaStreamAsync(fname, async (stream, ct2) =>
                            {
                                await FragmentFileHeader.EncryptWithEmbeddedIndexToStreamAsync(
                                    stream, plain, eib, ak, slt, ct2).ConfigureAwait(false);
                            }, ct).ConfigureAwait(false);
                            CryptographicOperations.ZeroMemory(plain);
                            fragments[i] = null!;
                            writtenFragments.TryAdd(fname, 0);
                            break;
                        }
                        catch when (retry < 2)
                        {
                            await Task.Delay(100 * (retry + 1), ct).ConfigureAwait(false);
                        }
                    }
                }).ConfigureAwait(false);

            long msWrite = phaseSw.ElapsedMilliseconds;
            progress?.Report(new RdrfProgressReport { Stage = "Write", CurrentItem = nFrags, TotalItems = nFrags });
            _logger.Info("BackupOrchestrator",
                $"Phase Write: encrypt+store {nFrags} frags in {msWrite} ms (read={msRead} encode={msEncode} protect={msProtect} write={msWrite})");

            byte[] indexBytes = finalSerializedIndex;
            if (_salt.Length > 0)
            {
                byte[] salted = _encryption.EncryptIndexWithSaltPrefix(indexBytes, _rcCode, _salt);
                await _storage.WriteIndexAsync(filePrefix, salted, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                byte[] encryptedIndex = _encryption.EncryptIndexWithKey(indexBytes, _aesKey);
                await _storage.WriteIndexAsync(filePrefix, encryptedIndex, cancellationToken).ConfigureAwait(false);
            }
            indexWritten = true;

            if (rcBytes.Length > 0)
            {
                byte[] encryptedRc = _encryption.EncryptFragmentWithKey(rcBytes, _aesKey);
                await _storage.WriteRcAsync(filePrefix, encryptedRc, cancellationToken).ConfigureAwait(false);
                rcWritten = true;
            }
        }
        catch (OperationCanceledException)
        {
            foreach (var f in writtenFragments.Keys)
            {
                try { _storage.DeleteFragment(f); }
                catch (Exception ex) { Debug.WriteLine($"[BackupOrchestrator] Cleanup failed for {f}: {ex.Message}"); }
            }
            if (indexWritten)
            {
                try { _storage.DeleteIndex(filePrefix); }
                catch (Exception ex) { Debug.WriteLine($"[BackupOrchestrator] Index cleanup failed: {ex.Message}"); }
            }
            if (rcWritten)
            {
                try { _storage.DeleteRc(filePrefix); }
                catch (Exception ex) { Debug.WriteLine($"[BackupOrchestrator] RC cleanup failed: {ex.Message}"); }
            }
            throw;
        }

        _metadata.SaveBackup(
            fileFingerprint: fileFingerprint,
            originalFilename: filename,
            originalSize: fileSize,
            originalHash: originalHash,
            fssStrategy: fssStrategy,
            fragmentHashes: fragmentHashes.ToList());

        _logger.Info("BackupOrchestrator", "Backup complete!");
        return fileFingerprint;
    }

    /// <summary>
    /// FSS1-only O(window) backup: pass1 hash metadata, pass2 encode/compress/write without
    /// holding the full encoded fragment set.
    /// </summary>
    private async Task<string> BackupFss1WindowedAsync(
        string filePath, int fragSize, long fileSize, string filename, string? customName,
        FsaPlan plan, string compressionMethod, string? compressionOptions,
        IProgress<RdrfProgressReport>? progress, CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        progress?.Report(new RdrfProgressReport { Stage = "Read", TotalBytes = fileSize });
        var pass1 = await BackupPhases.Fss1WindowedPipeline.ScanHashAsync(
            filePath, fragSize, progress, cancellationToken).ConfigureAwait(false);
        long msPass1 = sw.ElapsedMilliseconds;
        _logger.Info("BackupOrchestrator",
            $"FSS1-window pass1: {pass1.FragmentCount} frags, fingerprint scan in {msPass1} ms");

        string fileFingerprint = pass1.FileFingerprint;
        string originalHash = pass1.OriginalHash;
        string filePrefix = customName ?? fileFingerprint;

        var embeddedIndex = IndexManager.BuildIndex(
            fileFingerprint: fileFingerprint,
            originalFilename: filename,
            originalSize: fileSize,
            fragmentHashes: pass1.EncodedFragmentHashes,
            originalHash: originalHash,
            fssStrategy: Constants.FssLevel1,
            originalFragmentSizes: pass1.OriginalFragmentSizes,
            originalFragmentCount: pass1.FragmentCount,
            fssParams: new Dictionary<string, object>
            {
                ["plan"] = JsonSerializer.SerializeToElement(plan),
                ["windowed"] = true
            });

        if (!string.IsNullOrEmpty(customName))
            embeddedIndex.CustomName = customName;
        if (_salt.Length > 0)
            embeddedIndex.Salt = Hex.EncodeLower(_salt);
        embeddedIndex.Compression = compressionMethod;
        embeddedIndex.RawFragmentHashes = pass1.RawFragmentHashes;

        byte[] finalSerializedIndex = _indexManager.SerializeIndex(embeddedIndex);
        byte[] embeddedIndexBytes = Fss6Etn.StripForEmbeddedHeader(finalSerializedIndex);

        var writtenFragments = new System.Collections.Concurrent.ConcurrentDictionary<string, byte>();
        bool indexWritten = false;
        try
        {
            sw.Restart();
            progress?.Report(new RdrfProgressReport
            {
                Stage = "Write", CurrentItem = 0, TotalItems = pass1.FragmentCount
            });
            byte[]? salt = _salt.Length > 0 ? _salt : null;
            await BackupPhases.Fss1WindowedPipeline.WriteFragmentsAsync(
                filePath, fragSize, filePrefix, embeddedIndexBytes, _aesKey, salt,
                compressionMethod, compressionOptions, _storage, progress, cancellationToken,
                writtenFragments).ConfigureAwait(false);
            long msWrite = sw.ElapsedMilliseconds;
            _logger.Info("BackupOrchestrator",
                $"FSS1-window pass2: write {pass1.FragmentCount} frags in {msWrite} ms (pass1={msPass1} ms)");

            if (_salt.Length > 0)
            {
                byte[] salted = _encryption.EncryptIndexWithSaltPrefix(finalSerializedIndex, _rcCode, _salt);
                await _storage.WriteIndexAsync(filePrefix, salted, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                byte[] encryptedIndex = _encryption.EncryptIndexWithKey(finalSerializedIndex, _aesKey);
                await _storage.WriteIndexAsync(filePrefix, encryptedIndex, cancellationToken).ConfigureAwait(false);
            }
            indexWritten = true;
        }
        catch (OperationCanceledException)
        {
            foreach (var f in writtenFragments.Keys)
            {
                try { _storage.DeleteFragment(f); }
                catch (Exception ex) { Debug.WriteLine($"[BackupOrchestrator] Cleanup failed for {f}: {ex.Message}"); }
            }
            if (indexWritten)
            {
                try { _storage.DeleteIndex(filePrefix); }
                catch (Exception ex) { Debug.WriteLine($"[BackupOrchestrator] Index cleanup failed: {ex.Message}"); }
            }
            throw;
        }

        _metadata.SaveBackup(
            fileFingerprint: fileFingerprint,
            originalFilename: filename,
            originalSize: fileSize,
            originalHash: originalHash,
            fssStrategy: Constants.FssLevel1,
            fragmentHashes: pass1.EncodedFragmentHashes);

        _logger.Info("BackupOrchestrator", "Backup complete (FSS1 windowed)!");
        return fileFingerprint;
    }

    /// <summary>
    /// Builds a complete index for changed fragments during an incremental
    /// (versioned) backup. Only fragments that differ from the previous version
    /// are written; unchanged fragments reference the previous version's data
    /// via SourceVersion.
    ///
    /// Pipeline (subset of BackupCoreAsync):
    ///   FSA plan -> FSS encode -> ETN inject -> FSS6.1 repair -> embed in headers
    ///   -> Encrypt & write changed fragments -> Write Index -> Write RC
    ///
    /// Called from VersionedBackup.BackupAsync.
    /// </summary>
    public async Task<RdrfIndex> BuildChangedFragmentsIndex(
        List<byte[]> allRawFragments,
        List<byte[]> changedRawFragments,
        List<int> changedIndices,
        bool[] changedFlags,
        string fileFingerprint,
        string originalHash,
        string originalFilename,
        long fileSize,
        string fssStrategy,
        int fragmentSize,
        string? customName,
        string? prevFingerprint,
        List<byte[]>? prevRawHashes,
        IProgress<RdrfProgressReport>? progress,
        CancellationToken ct,
        string? compressionMethod = null,
        List<int>? rawFragmentSizes = null)
    {
        int fragSize = Constants.ComputeFragmentSize(fileSize, fragmentSize > 0 ? fragmentSize : null);
        string filePrefix = customName ?? fileFingerprint;
        var plan = _fsa.Compute(fssStrategy, null);

        // Raw sizes + XxHash BEFORE FSS1 windowed encode zeros/releases raw buffers.
        int originalFragmentCount = allRawFragments.Count;
        var originalFragmentSizes = rawFragmentSizes ?? allRawFragments.Select(f => f.Length).ToList();
        var rawXxHashes = new List<byte[]>(allRawFragments.Count);
        foreach (var f in allRawFragments)
            rawXxHashes.Add(System.IO.Hashing.XxHash128.Hash(f.AsSpan()));

        var workRaw = new List<byte[]>(allRawFragments);
        var fragments = EncodeViaPlan(workRaw, plan);
        // Drop caller raw aliases when FSS1 family released them (same array refs).
        if (plan.EffectivePrimary is Constants.FssLevel1 or Constants.FssLevel2)
        {
            for (int i = 0; i < allRawFragments.Count; i++)
                allRawFragments[i] = null!;
        }

        var fragmentHashes = new string[fragments.Count];
        if (RDRF.Core.Device.GpuContext.IsAvailable)
        {
            var rawHashes = RDRF.Core.Device.GpuHasher.HashSHA256(fragments);
            for (int i = 0; i < fragments.Count; i++)
            {
                var sb = new System.Text.StringBuilder(64);
                for (int j = 0; j < 32; j++) sb.Append(rawHashes[i * 32 + j].ToString("x2"));
                fragmentHashes[i] = sb.ToString();
            }
        }
        else
        {
            Parallel.For(0, fragments.Count, new ParallelOptions { MaxDegreeOfParallelism = Constants.DefaultParallelism }, i =>
            {
                fragmentHashes[i] = IntegrityChecker.HashBytes(fragments[i]);
            });
        }

        var index = IndexManager.BuildIndex(
            fileFingerprint: fileFingerprint,
            originalFilename: originalFilename,
            originalSize: fileSize,
            fragmentHashes: fragmentHashes.ToList(),
            originalHash: originalHash,
            fssStrategy: plan.EffectivePrimary,
            originalFragmentSizes: originalFragmentSizes,
            originalFragmentCount: originalFragmentCount,
            fssParams: new Dictionary<string, object>
            {
                ["plan"] = JsonSerializer.SerializeToElement(plan)
            });

        if (!string.IsNullOrEmpty(customName))
            index.CustomName = customName;
        if (_salt.Length > 0)
            index.Salt = Hex.EncodeLower(_salt);

        if (compressionMethod != null)
            index.Compression = compressionMethod;

        index.RawFragmentHashes = rawXxHashes;

        byte[] serializedIndex = _indexManager.SerializeIndex(index);

        string cm = compressionMethod ?? Constants.CompressionLz4;
        byte[] rcBytes;
        Fss61RepairData? repairA2 = null, repairC2 = null;
        Fss62RepairData? repair62A2 = null, repair62C2 = null;
        (fragments, rcBytes, repairA2, repairC2, repair62A2, repair62C2, _) =
            await RunFssPipelineAsync(fragments, serializedIndex, index,
                filePrefix, fileSize, plan, cm, null, ct);

        // Add FssParams and SourceVersion references, then serialize once
        index.FssParams = new Dictionary<string, object>
        {
            ["plan"] = JsonSerializer.SerializeToElement(plan)
        };
        if (index.Fragments != null)
        {
            for (int i = 0; i < index.Fragments.Count; i++)
            {
                if (i < changedFlags.Length && !changedFlags[i] && prevFingerprint != null)
                    index.Fragments[i].SourceVersion = prevFingerprint;
            }
        }

        byte[] indexBytes = _indexManager.SerializeIndex(index);
        byte[] embeddedIndexBytes = Fss6Etn.StripEtnFieldsFromIndexJson(indexBytes);
        long totalBytes = fragments.Sum(f => f.Length);
        long processedBytes = 0;

        // Collect indices of fragments to write (skip unchanged)
        var writeIndices = new List<int>();
        for (int i = 0; i < fragments.Count; i++)
        {
            if (index.Fragments?.Count > i && index.Fragments[i].SourceVersion != null)
            {
                processedBytes += fragments[i].Length;
                continue;
            }
            writeIndices.Add(i);
        }

        // Parallel stream encrypt+write (no full ciphertext array residency across all frags)
        string fPrefix = filePrefix;
        byte[] eib = embeddedIndexBytes;
        byte[] ak = _aesKey;
        byte[] slt = _salt;
        int done = 0;
        await Parallel.ForEachAsync(Enumerable.Range(0, writeIndices.Count),
            new ParallelOptions { MaxDegreeOfParallelism = Constants.DefaultParallelism, CancellationToken = ct },
            async (j, ctInner) =>
            {
                int i = writeIndices[j];
                byte[] plain = fragments[i];
                string fname = Frags.FragmentFilename(fPrefix, i);
                long plainLen = plain.Length;
                await _storage.WriteFragmentViaStreamAsync(fname, async (stream, ct2) =>
                {
                    await FragmentFileHeader.EncryptWithEmbeddedIndexToStreamAsync(
                        stream, plain, eib, ak, slt, ct2).ConfigureAwait(false);
                }, ctInner).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(plain);
                fragments[i] = null!;
                long cur = Interlocked.Add(ref processedBytes, plainLen);
                int item = Interlocked.Increment(ref done);
                progress?.Report(new RdrfProgressReport
                {
                    Stage = "Encrypting",
                    CurrentItem = item,
                    TotalItems = writeIndices.Count,
                    CurrentBytes = cur,
                    TotalBytes = totalBytes
                });
            });

        if (_salt.Length > 0)
        {
            byte[] salted = _encryption.EncryptIndexWithSaltPrefix(indexBytes, _rcCode, _salt);
            await _storage.WriteIndexAsync(filePrefix, salted, ct).ConfigureAwait(false);
        }
        else
        {
            byte[] encryptedIndex = _encryption.EncryptIndexWithKey(indexBytes, _aesKey);
            await _storage.WriteIndexAsync(filePrefix, encryptedIndex, ct).ConfigureAwait(false);
        }

        if (rcBytes.Length > 0)
        {
            byte[] encryptedRc = _encryption.EncryptFragmentWithKey(rcBytes, _aesKey);
            await _storage.WriteRcAsync(filePrefix, encryptedRc, ct).ConfigureAwait(false);
        }

        _metadata.SaveBackup(
            fileFingerprint: fileFingerprint,
            originalFilename: originalFilename,
            originalSize: fileSize,
            originalHash: originalHash,
            fssStrategy: fssStrategy,
            fragmentHashes: fragmentHashes.ToList());

        return index;
    }

    /// <summary>
    /// Shared FSS pipeline: ETN inject → repair generate → compress → append trailers.
    /// Called by both BackupCoreAsync and BuildChangedFragmentsIndex.
    /// </summary>
    private async Task<(List<byte[]> Fragments, byte[] RcBytes, Fss61RepairData? RepairA,
        Fss61RepairData? RepairC, Fss62RepairData? Repair62A, Fss62RepairData? Repair62C, byte[] FinalSerializedIndex)>
        RunFssPipelineAsync(List<byte[]> fragments, byte[] serializedIndex, RdrfIndex index,
        string filePrefix, long fileSize, FsaPlan plan, string compressionMethod,
        string? compressionOptions, CancellationToken ct)
    {
        byte[] rcBytes = [];

        bool hasFss6 = plan.ActiveStrategies.Contains(Constants.FssLevel6)
                     || plan.ActiveStrategies.Contains(Constants.FssLevel61)
                     || plan.ActiveStrategies.Contains(Constants.FssLevel62);
        bool hasFss61 = plan.ActiveStrategies.Contains(Constants.FssLevel61);
        bool hasFss62 = plan.ActiveStrategies.Contains(Constants.FssLevel62);

        // Compression stage:
        //   FSS1–5 / pure FSS6: compress AFTER ETN (trailers may be inside compressed payload).
        //   FSS6.1/6.2: compress BEFORE ETN so block maps + fountain cover compressed body;
        //   repair trailers are always appended last (never compressed).
        // Index.Compression must match the bytes ETN hashed (re-serialize after setting it).
        bool compressBeforeEtn = hasFss61 || hasFss62;
        if (compressBeforeEtn)
        {
            await CompressFragmentsInPlaceAsync(fragments, compressionMethod, compressionOptions, ct).ConfigureAwait(false);
            index.Compression = string.IsNullOrEmpty(compressionMethod) ? Constants.CompressionLz4 : compressionMethod;
            serializedIndex = _indexManager.SerializeIndex(index);
        }

        if (hasFss6)
        {
            var (etnFrags, etnRcJson) = Fss6Etn.InjectCrossValidation(
                fragments, serializedIndex, index, filePrefix, fileSize, plan.EffectivePrimary);
            fragments = etnFrags;
            rcBytes = etnRcJson;
        }

        Fss61RepairData? repairA = null, repairC = null;
        if (hasFss61)
        {
            int bs = EtnBlockMap.GetBlockSize(fileSize, plan.EffectivePrimary);
            var (ra, rb, rc) = await FssRepairService.Generate61Async(serializedIndex, fragments, rcBytes, bs);
            repairA = ra; repairC = rc;
            if (rb != null) index.Fss61RepairB = rb;
            if (rc != null) index.Fss61RepairC = rc;
            var rcFile61 = RcFile.FromCbor(rcBytes);
            if (ra != null) rcFile61.RepairA = ra;
            if (rb != null) rcFile61.RepairB = rb;
            rcBytes = rcFile61.ToCborBytes();
        }

        Fss62RepairData? repair62A = null, repair62C = null;
        if (hasFss62)
        {
            int bs2 = EtnBlockMap.GetBlockSize(fileSize, plan.EffectivePrimary);
            var (ra, rb, rc) = await FssRepairService.Generate62Async(serializedIndex, fragments, rcBytes, bs2);
            repair62A = ra; repair62C = rc;
            if (rb != null) index.Fss62RepairB = rb;
            if (rc != null) index.Fss62RepairC = rc;
            var rcFile62 = RcFile.FromCbor(rcBytes);
            if (ra != null) rcFile62.Repair62A = ra;
            if (rb != null) rcFile62.Repair62B = rb;
            rcBytes = rcFile62.ToCborBytes();
        }

        // Non-6.1/6.2: compress after ETN, before repair trailers (FSS6 trailers go inside compress).
        if (!compressBeforeEtn)
        {
            await CompressFragmentsInPlaceAsync(fragments, compressionMethod, compressionOptions, ct).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(compressionMethod))
                index.Compression = compressionMethod;
        }

        // Append repair trailers AFTER any compression
        if (hasFss61)
            FssRepairService.Append61Trailers(fragments, filePrefix, repairA, repairC);
        if (hasFss62)
            FssRepairService.Append62Trailers(fragments, filePrefix, repair62A, repair62C);

        byte[] final = _indexManager.SerializeIndex(index);
        return (fragments, rcBytes, repairA, repairC, repair62A, repair62C, final);
    }

    /// <summary>
    /// Zeroes all sensitive key material from memory and disposes
    /// the metadata manager. Suppresses finalization.
    /// </summary>
    private List<byte[]> EncodeViaPlan(List<byte[]> fragments, FsaPlan plan)
    {
        foreach (var step in plan.EncodeSteps)
        {
            if (step.Step == "encode")
            {
                fragments = _fss.Encode(fragments, step.Strategy);
                _logger.Info("BackupOrchestrator", $"Encode ({step.Strategy}): {fragments.Count} fragments");
            }
            else if (step.Step == "etn_inject")
            {
                fragments = _fss.Encode(fragments, Constants.FssLevel6);
                _logger.Info("BackupOrchestrator", $"ETN inject: {fragments.Count} fragments");
            }
        }
        return fragments;
    }

    /// <summary>
    /// After FSS encode, drop raw fragment buffers so GC can reclaim peak RAM.
    /// FSS1/FSS2 already zero raw during windowed encode — only clear aliases.
    /// Other strategies: zero unreferenced raw then clear.
    /// </summary>
    private static void ReleaseRawAfterEncode(
        BackupPhases.BackupReadResult readResult, List<byte[]> encoded, string primaryStrategy)
    {
        bool fss1Family = primaryStrategy is Constants.FssLevel1 or Constants.FssLevel2;
        if (!fss1Family)
        {
            var keep = new HashSet<byte[]>(encoded.Count, ReferenceEqualityComparer.Instance);
            foreach (var f in encoded)
                if (f != null) keep.Add(f);

            for (int i = 0; i < readResult.RawFragments.Count; i++)
            {
                byte[]? r = readResult.RawFragments[i];
                if (r != null && !keep.Contains(r))
                    CryptographicOperations.ZeroMemory(r);
            }
        }

        readResult.RawFragments.Clear();
        if (readResult.OriginalFragments != null)
        {
            for (int i = 0; i < readResult.OriginalFragments.Length; i++)
                readResult.OriginalFragments[i] = null!;
        }
    }

    /// <summary>
    /// After FSS encode, drop raw fragment buffers that are no longer referenced so GC can reclaim peak RAM.
    /// </summary>
    private static void ReleaseUnreferencedRaw(BackupPhases.BackupReadResult readResult, List<byte[]> encoded)
        => ReleaseRawAfterEncode(readResult, encoded, primaryStrategy: "");

    private static async Task CompressFragmentsInPlaceAsync(
        List<byte[]> fragments, string? compressionMethod, string? compressionOptions, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(compressionMethod))
            compressionMethod = Constants.CompressionLz4;
        if (string.Equals(compressionMethod, Constants.CompressionCkc, StringComparison.OrdinalIgnoreCase))
        {
            CkcEngine.CompressInPlace(fragments);
            return;
        }
        string cm = compressionMethod;
        string? co = compressionOptions;
        await Parallel.ForEachAsync(Enumerable.Range(0, fragments.Count),
            new ParallelOptions { MaxDegreeOfParallelism = Constants.DefaultParallelism, CancellationToken = ct },
            (i, ctInner) =>
            {
                byte[] plain = fragments[i];
                byte[] c = Compressor.AlwaysCompress(plain, cm, co);
                if (c.Length < plain.Length)
                    fragments[i] = c;
                // else keep plain; let short-lived larger compress buffer be GC'd
                return ValueTask.CompletedTask;
            }).ConfigureAwait(false);
    }

    public void Dispose()
    {
        if (_rcCode != null && _rcCode.Length > 0)
            CryptographicOperations.ZeroMemory(_rcCode);
        if (_aesKey != null && _aesKey.Length > 0)
            CryptographicOperations.ZeroMemory(_aesKey);
        if (_salt != null && _salt.Length > 0)
            CryptographicOperations.ZeroMemory(_salt);
        (_metadata as IDisposable)?.Dispose();
        GC.SuppressFinalize(this);
    }

}



