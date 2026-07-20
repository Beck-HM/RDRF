using RDRF.Core.Abstractions;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Hashing;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Channels;
using RDRF.Core.Compression;
using RDRF.Core.Compression.Ckc;
using RDRF.Core.Encryption;
using RDRF.Core.ETN;
using RDRF.Core.FragmentEngine;
using RDRF.Core.Logging;
using RDRF.Core.FSS;
using RDRF.Core.FSA;
using RDRF.Core.Index;
using RDRF.Core.Integrity;
using RDRF.Core.Metadata;
using RDRF.Core.DSAA;

namespace RDRF.Core;

/// <summary>
/// Core restore pipeline orchestrator. Reverses the backup pipeline:
///
/// Pipeline:
///   Read encrypted fragments -> AES-CTR decrypt -> Strip FSS/ETN headers
///   -> ETN cross-validation (FSS6.x) -> Fragment recovery (if missing)
///   -> FSS decode -> LZ4 decompress -> Merge into output file
///
/// Two restore paths:
///   Standard: loads all fragments, decrypts, validates, recovers, decodes
///     (required when fragments missing or FSS repair / multi-fragment decode needed).
///   Streaming: when every fragment is present, processes one fragment at a time
///     (read → decrypt → strip trailers → decompress → FSS StripSingle → write),
///     keeping O(1) fragment buffers in RAM (except CKC multi-frag shared tables,
///     which must load all compressed fragments first by design).
///
/// Call chain:
///   RDRFEngine.RestoreFileAsync
///   -> RestoreOrchestrator.RestoreFileAsync -> RestoreCoreAsync
///     -> TryStreamingRestoreCoreAsync (fast path)
///       or DownloadAndDecryptFragmentsAsync -> RunEtnCrossValidateAsync
///       -> RecoveryExecutor.ExecuteRecoveryAsync -> FSSEngine.Decode
///       -> Write output file
/// </summary>
public class RestoreOrchestrator : IDisposable
{
    private readonly byte[] _rcCode;
    private readonly DSAAAdapter _storage;
    private readonly IFSSEngine _fss;
    private readonly IMetadataManager _metadata;
    private readonly IRecoveryExecutor _recoveryExecutor;
    private readonly IEncryptionLayer _encryption;
    private readonly IIndexManager _indexManager;
    private readonly RdrfLogger _logger;

    public RestoreOrchestrator(
        byte[] aesKey,
        byte[] rcCode,
        DSAAAdapter storage,
        IFSSEngine? fssEngine = null,
        IMetadataManager? metadata = null,
        IRecoveryExecutor? recoveryExecutor = null,
        IEncryptionLayer? encryption = null,
        IIndexManager? indexManager = null,
        RdrfLogger? logger = null)
    {
        _rcCode = rcCode?.Clone() as byte[] ?? [];
        _storage = storage ?? throw new ArgumentNullException(nameof(storage));
        _fss = fssEngine ?? new FSSEngineWrapper();
        _metadata = metadata ?? new MetadataManagerWrapper();
        _recoveryExecutor = recoveryExecutor ?? new RecoveryExecutor(_fss);
        _encryption = encryption ?? new EncryptionLayerWrapper();
        _indexManager = indexManager ?? new IndexManagerWrapper();
        _logger = logger ?? new RdrfLogger();
    }

    // --- Public Restore Methods ---

    public bool RestoreFile(
        string fileFingerprint,
        string outputPath,
        bool allowFssRecovery = true,
        string? filePrefix = null,
        IProgress<RdrfProgressReport>? progress = null)
    {
        if (!_storage.IndexExists(fileFingerprint))
            throw new FileNotFoundException($"Index not found for fingerprint: {fileFingerprint}");

        byte[] encryptedIndex = _storage.ReadIndex(fileFingerprint);
        (byte[] aesKey, byte[] cbor) = _encryption.DecryptIndexWithAutoDetect(encryptedIndex, _rcCode);
        var index = _indexManager.DeserializeIndex(cbor);
        string prefix = filePrefix ?? fileFingerprint;
        return RestoreCore(index, aesKey, prefix, outputPath, allowFssRecovery, progress);
    }

    public bool RestoreFile(string fileFingerprint, FileInfo outputPath, bool allowFssRecovery = true, string? filePrefix = null, IProgress<RdrfProgressReport>? progress = null)
        => RestoreFile(fileFingerprint, outputPath.FullName, allowFssRecovery, filePrefix, progress);

    // --- Restore From Fragments ---

    public bool RestoreFileFromFragments(
        string filePrefix,
        string outputPath,
        bool allowFssRecovery = true,
        IProgress<RdrfProgressReport>? progress = null)
    {
        string frag0Path = Frags.FragmentFilename(filePrefix, 0);
        if (!_storage.FragmentExists(frag0Path))
            throw new FileNotFoundException($"No fragments found with prefix '{filePrefix}'");

        byte[] fragData = _storage.ReadFragment(frag0Path);
        if (!FragmentFileHeader.HasHeader(fragData))
            throw new InvalidDataException("Fragment does not contain an embedded index.");

        byte[] aesKey;
        byte[] idxBytes;
        if (FragmentFileHeader.GetTotalHeaderSize(fragData) > FragmentFileHeader.HeaderSize)
        {
            var (embeddedIdx, _, salt) = FragmentFileHeader.DecryptWithEmbeddedIndex(fragData,
                _encryption.DeriveKeyLegacy(_rcCode));
            if (salt != null && salt.Length == Constants.SaltPrefixLength)
                aesKey = _encryption.DeriveKey(_rcCode, salt);
            else
                aesKey = _encryption.DeriveKeyLegacy(_rcCode);
            var (reDecrypted, _, _) = FragmentFileHeader.DecryptWithEmbeddedIndex(fragData, aesKey);
            idxBytes = reDecrypted ?? embeddedIdx;
        }
        else
        {
            aesKey = _encryption.DeriveKeyLegacy(_rcCode);
            var (idx, _, _) = FragmentFileHeader.DecryptWithEmbeddedIndex(fragData, aesKey);
            idxBytes = idx;
        }
        if (idxBytes == null)
            throw new InvalidDataException("Failed to extract embedded index from fragment");
        var index = _indexManager.DeserializeIndex(idxBytes);
        return RestoreCore(index, aesKey, filePrefix, outputPath, allowFssRecovery, progress);
    }

    // --- Async Restore ---

    public async Task<bool> RestoreFileAsync(
        string fileFingerprint,
        string outputPath,
        bool allowFssRecovery = true,
        string? filePrefix = null,
        IProgress<RdrfProgressReport>? progress = null,
        CancellationToken cancellationToken = default)
    {
        string lookupKey = filePrefix ?? fileFingerprint;
        if (!_storage.IndexExists(lookupKey))
            throw new FileNotFoundException($"Index not found: {lookupKey}");

        byte[] encryptedIndex = await _storage.ReadIndexAsync(lookupKey, cancellationToken).ConfigureAwait(false);
        (byte[] aesKey, byte[] cbor) = _encryption.DecryptIndexWithAutoDetect(encryptedIndex, _rcCode);
        var index = _indexManager.DeserializeIndex(cbor);
        string prefix = filePrefix ?? fileFingerprint;
        return await RestoreCoreAsync(index, aesKey, prefix, outputPath, allowFssRecovery, progress, cancellationToken).ConfigureAwait(false);
    }

    public Task<bool> RestoreFileAsync(string fileFingerprint, FileInfo outputPath, bool allowFssRecovery = true, string? filePrefix = null, IProgress<RdrfProgressReport>? progress = null, CancellationToken cancellationToken = default)
        => RestoreFileAsync(fileFingerprint, outputPath.FullName, allowFssRecovery, filePrefix, progress, cancellationToken);

    public async Task<bool> RestoreFileFromFragmentsAsync(
        string filePrefix,
        string outputPath,
        bool allowFssRecovery = true,
        IProgress<RdrfProgressReport>? progress = null,
        CancellationToken cancellationToken = default)
    {
        string frag0Path = Frags.FragmentFilename(filePrefix, 0);
        if (!_storage.FragmentExists(frag0Path))
            throw new FileNotFoundException($"No fragments found with prefix '{filePrefix}'");

        byte[] fragData = await _storage.ReadFragmentAsync(frag0Path, cancellationToken).ConfigureAwait(false);
        if (!FragmentFileHeader.HasHeader(fragData))
            throw new InvalidDataException("Fragment does not contain an embedded index.");

        byte[] aesKey;
        byte[] idxBytes;
        if (FragmentFileHeader.GetTotalHeaderSize(fragData) > FragmentFileHeader.HeaderSize)
        {
            var (embeddedIdx, _, salt) = FragmentFileHeader.DecryptWithEmbeddedIndex(fragData,
                _encryption.DeriveKeyLegacy(_rcCode));
            if (salt != null && salt.Length == Constants.SaltPrefixLength)
                aesKey = _encryption.DeriveKey(_rcCode, salt);
            else
                aesKey = _encryption.DeriveKeyLegacy(_rcCode);
            var (reDecrypted, _, _) = FragmentFileHeader.DecryptWithEmbeddedIndex(fragData, aesKey);
            idxBytes = reDecrypted ?? embeddedIdx;
        }
        else
        {
            aesKey = _encryption.DeriveKeyLegacy(_rcCode);
            var (idx, _, _) = FragmentFileHeader.DecryptWithEmbeddedIndex(fragData, aesKey);
            idxBytes = idx;
        }
        if (idxBytes == null)
            throw new InvalidDataException("Failed to extract embedded index from fragment");
        var index = _indexManager.DeserializeIndex(idxBytes);
        return await RestoreCoreAsync(index, aesKey, filePrefix, outputPath, allowFssRecovery, progress, cancellationToken).ConfigureAwait(false);
    }

    // --- Restore From Index Data (pre-loaded encrypted index) ---

    public bool RestoreFileFromIndexData(
        byte[] encryptedIndex,
        string filePrefix,
        string outputPath,
        bool allowFssRecovery = true,
        IProgress<RdrfProgressReport>? progress = null)
    {
        (byte[] aesKey, byte[] cbor) = _encryption.DecryptIndexWithAutoDetect(encryptedIndex, _rcCode);
        var index = _indexManager.DeserializeIndex(cbor);
        return RestoreCore(index, aesKey, filePrefix, outputPath, allowFssRecovery, progress);
    }

    // --- Synchronous Core ---

    private bool RestoreCore(
        RdrfIndex index,
        byte[] aesKey,
        string filePrefix,
        string outputPath,
        bool allowFssRecovery = true,
        IProgress<RdrfProgressReport>? progress = null)
    {
        var task = Task.Run(() => RestoreCoreAsync(index, aesKey, filePrefix, outputPath,
            allowFssRecovery, progress, CancellationToken.None));
        if (task.Wait(TimeSpan.FromMinutes(30)))
            return task.Result;
        throw new TimeoutException($"Restore timed out after 30 minutes: {outputPath}");
    }

    // --- Async Core ---

    private async Task<bool> RestoreCoreAsync(
        RdrfIndex index,
        byte[] aesKey,
        string filePrefix,
        string outputPath,
        bool allowFssRecovery = true,
        IProgress<RdrfProgressReport>? progress = null,
        CancellationToken ct = default)
    {
        int fragmentCount = index.FragmentCount;
        string fssStrategy = index.FssStrategy;
        var originalSizes = index.OriginalFragmentSizes;
        int? originalCount = index.OriginalFragmentCount > 0 ? index.OriginalFragmentCount : null;
        string fileFingerprint = index.FileFingerprint;

        FsaPlan? plan = null;
        if (index.FssParams != null && index.FssParams.TryGetValue("plan", out var planObj))
        {
            if (planObj is JsonElement jsonElement)
            {
                plan = JsonSerializer.Deserialize<FsaPlan>(
                    jsonElement.GetRawText(),
                    new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower });
            }
        }

        bool hasFss6 = index.HasFss6EtnData;
        string? restoredHash = null;

        // Try streaming restore when all fragments are on disk (no recovery needed)
        if (await TryStreamingRestoreCoreAsync(index, aesKey, filePrefix, outputPath,
                progress, ct).ConfigureAwait(false))
        {
            return true;
        }

        var decryptedFragments = await DownloadAndDecryptFragmentsAsync(
                aesKey, filePrefix, fragmentCount, fileFingerprint, progress, ct, index).ConfigureAwait(false);

            // Unified order with streaming / backup inverse:
            //   For pure FSS6 (+compress after ETN): decompress first so trailers reappear, then ETN, then strip.
            //   For FSS6.1/6.2 (no compress historically; or pre-ETN compress): trailers outer → strip after ETN.
            // Heuristic: if compression is set and FSS6 BM present, try trailer-aware path:
            //   1) If data starts as known compressed frame, decompress first; else strip trailers then decompress.
            bool isCkc = string.Equals(index.Compression, Constants.CompressionCkc, StringComparison.OrdinalIgnoreCase);

            // ETN cross-validation needs trailers still attached (post-decrypt body).
            var etnActual = false;
            _logger.Info("RestoreOrchestrator", $"  [DICT] hasFss6={hasFss6} fragCount={decryptedFragments.Count} BM={index.Fss6FragmentBlockMaps?.Count} RcBM={index.Fss6RcBlockMap?.Count}");
            if (hasFss6)
            {
                ct.ThrowIfCancellationRequested();
                // Pure FSS6 may have compressed(body+trailer). Detect LZ4/Zstd magic and decompress before CV.
                if (!string.IsNullOrEmpty(index.Compression) && !isCkc)
                {
                    foreach (var idx in decryptedFragments.Keys.ToList())
                    {
                        byte[] d = decryptedFragments[idx];
                        if (LooksCompressedFrame(d, index.Compression))
                            decryptedFragments[idx] = Compressor.Decompress(d, index.Compression);
                    }
                }
                etnActual = await RunEtnCrossValidateAsync(index, decryptedFragments,
                    fileFingerprint, aesKey, ct).ConfigureAwait(false);
            }

            // Strip ETN / repair trailers, then decompress remaining payloads.
            foreach (var idx in decryptedFragments.Keys.ToList())
            {
                byte[] d = decryptedFragments[idx];
                if (hasFss6)
                {
                    bool isFss61 = fssStrategy is Constants.FssLevel61 or Constants.FssLevel62;
                    d = isFss61
                        ? StripAnyTrailer(d)
                        : ((Fss6Etn)_fss.GetStrategy(Constants.FssLevel6)).Strip(d);
                }
                if (!string.IsNullOrEmpty(index.Compression))
                {
                    if (isCkc)
                    {
                        // CKC multi-frag handled in batch below
                    }
                    else if (LooksCompressedFrame(d, index.Compression) || !hasFss6)
                    {
                        // FSS1–5: compress wraps full fragment; FSS6.1 pre-ETN compress: body is compressed after strip
                        d = Compressor.Decompress(d, index.Compression);
                    }
                }
                decryptedFragments[idx] = d;
            }
            if (isCkc && !string.IsNullOrEmpty(index.Compression))
            {
                var list = new List<byte[]>(fragmentCount);
                for (int i = 0; i < fragmentCount; i++)
                    list.Add(decryptedFragments.TryGetValue(i, out var x) ? x : Array.Empty<byte>());
                CkcEngine.DecompressInPlace(list);
                for (int i = 0; i < fragmentCount; i++)
                    decryptedFragments[i] = list[i];
            }

            if (allowFssRecovery && !isCkc)
            {
                var recoveryResult = await _recoveryExecutor.ExecuteRecoveryAsync(
                    index, decryptedFragments, _metadata).ConfigureAwait(false);
                foreach (var kvp in recoveryResult.RecoveredFragments)
                    decryptedFragments[kvp.Key] = kvp.Value;
                var stillMissing = new List<int>();
                for (int i = 0; i < fragmentCount; i++)
                    if (!decryptedFragments.ContainsKey(i)) stillMissing.Add(i);
                if (stillMissing.Count > 0)
                {
                    _logger.Info("RestoreOrchestrator", $"  Restore failed: {stillMissing.Count} fragments still missing");
                    return false;
                }
            }
            else
            {
                var missing = new List<int>();
                for (int i = 0; i < fragmentCount; i++)
                    if (!decryptedFragments.ContainsKey(i)) missing.Add(i);
                if (missing.Count > 0)
                {
                    _logger.Info("RestoreOrchestrator", $"  Restore failed: {missing.Count} fragments missing (recovery disabled)");
                    return false;
                }
            }

            int origCount2 = originalCount ?? fragmentCount;
            restoredHash = StripFssEncodingToStream(decryptedFragments, fssStrategy, originalSizes, origCount2, outputPath);

        // Trim restored file to original size (removes FSS1 padding zeros)
        if (File.Exists(outputPath) && new FileInfo(outputPath).Length > index.FileSize)
        {
            using var fs = new FileStream(outputPath, FileMode.Open, FileAccess.ReadWrite);
            fs.SetLength(index.FileSize);
        }

        long outSize = File.Exists(outputPath) ? new FileInfo(outputPath).Length : -1;
        bool valid = IntegrityChecker.VerifyHash(restoredHash, index.OriginalHash);
        _logger.Info("RestoreOrchestrator",$"  Integrity check: {(valid ? "PASS" : "FAIL")}");

        if (valid)
        {
            return true;
        }
        _logger.Info("RestoreOrchestrator",$"  [RESTORE FAIL] hash={restoredHash} expected={index.OriginalHash} size={outSize}");
        return false;
    }

    // --- Download and Decrypt Fragments ---
    //
    // This is the fallback path (path B) used when fragments are missing or
    // corrupted. All fragments are loaded into memory simultaneously to allow
    // FSS recovery and ETN cross-validation. For the common case where all
    // fragments are intact, TryStreamingRestoreCoreAsync (path A) handles the
    // restore with O(1) memory by streaming fragments one at a time.

    private Task<Dictionary<int, byte[]>> DownloadAndDecryptFragmentsAsync(
        byte[] aesKey, string filePrefix, int fragmentCount, string fileFingerprint,
        IProgress<RdrfProgressReport>? progress, CancellationToken ct,
        RdrfIndex? index = null)
        => BackupPhases.RestoreFragmentReader.DownloadAndDecryptFragmentsAsync(
            aesKey, _rcCode, filePrefix, fragmentCount, fileFingerprint,
            _storage, _encryption, _indexManager, progress, ct, index);

    // --- ETN Cross-Validate ---

    private async Task<bool> RunEtnCrossValidateAsync(
        RdrfIndex index, Dictionary<int, byte[]> decryptedFragments,
        string fileFingerprint, byte[] aesKey, CancellationToken ct)
    {
        _logger.Info("RestoreOrchestrator",$"  [ETN] entered fp={fileFingerprint.Substring(0, 16)}...");
        bool validationActual = false;
        try
        {
            bool rcExists = await _storage.RcExistsAsync(fileFingerprint, ct).ConfigureAwait(false);
            _logger.Info("RestoreOrchestrator",$"  [ETN] rcExists={rcExists}");
            if (rcExists)
            {
                byte[] encryptedRc = await _storage.ReadRcAsync(fileFingerprint, ct).ConfigureAwait(false);
                byte[] rcBytes = _encryption.DecryptFragmentWithKey(encryptedRc, aesKey);
                byte[] indexBytes = _indexManager.SerializeIndex(index);

                var cvResult = Fss6Etn.CrossValidate(
                    indexBytes,
                    decryptedFragments.OrderBy(k => k.Key).Select(k => k.Value).ToList(),
                    rcBytes);

                int totalCvBlocks = 0;
                foreach (var kv in cvResult.CorruptedFragmentBlocks) totalCvBlocks += kv.Value.Count;
                _logger.Info("RestoreOrchestrator",$"  [CV] IsValid={cvResult.IsValid} BadFrags={cvResult.CorruptedFragments.Count} BadBlocks={totalCvBlocks} IndexBad={cvResult.IndexCorrupted} RcBad={cvResult.RcCorrupted}");

                if (!cvResult.IsValid)
                {
                    _logger.Info("RestoreOrchestrator",$"  ETN cross-validation found corruption:");
                    if (cvResult.IndexCorrupted)
                        _logger.Info("RestoreOrchestrator",$"    - Index corrupted ({cvResult.IndexCorruptedBlocks.Count} blocks)");
                    if (cvResult.RcCorrupted)
                        _logger.Info("RestoreOrchestrator",$"    - RC file corrupted ({cvResult.RcCorruptedBlocks.Count} blocks)");
                    if (cvResult.CorruptedFragments.Count > 0)
                        _logger.Info("RestoreOrchestrator",$"    - Corrupted fragments: {string.Join(", ", cvResult.CorruptedFragments)}");

                    if (!cvResult.IsValid)
                    {
                        if (FssRepairService.TryRepair61(index, ref rcBytes, decryptedFragments, cvResult))
                            validationActual = true;
                        if (!validationActual && FssRepairService.TryRepair62(index, ref rcBytes, decryptedFragments, cvResult))
                            validationActual = true;
                    }
                }
                else
                {
                    _logger.Info("RestoreOrchestrator",$"  ETN cross-validation passed");
                    validationActual = true;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error("RestoreOrchestrator", "RC file read/validation failed", ex);
            validationActual = false;
        }

        return validationActual;
    }

    private static byte[] StripAnyTrailer(byte[] frag)
    {
        var (raw62, _, _, _, _) = FSS.Fss62RepairTrailer.Parse(frag);
        if (raw62.Length < frag.Length) {
            var (raw61b, _, _, _, _) = FSS.Fss61RepairTrailer.Parse(raw62);
            return raw61b.Length < raw62.Length ? StripEtnOnly(raw61b) : StripEtnOnly(raw62);
        }
        var (raw61, _, _, _, _) = FSS.Fss61RepairTrailer.Parse(frag);
        if (raw61.Length < frag.Length) return StripEtnOnly(raw61);
        return StripEtnOnly(frag);
    }

    private static byte[] StripEtnOnly(byte[] frag)
        => EtnTrailer.Parse(frag).RawData;

    // --- Strip FSS Encoding ---

    private string StripFssEncodingToStream(
        Dictionary<int, byte[]> decryptedFragments,
        string fssStrategy,
        List<int>? originalSizes, int originalCount,
        string outputPath)
    {
        using var fs = new FileStream(outputPath, FileMode.Create, FileAccess.Write);
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        StripFssEncodingToStream(decryptedFragments, fssStrategy, originalSizes, originalCount, fs, hasher);
        return Hex.EncodeLower(hasher.GetHashAndReset());
    }

    private void StripFssEncodingToStream(
        Dictionary<int, byte[]> decryptedFragments,
        string fssStrategy,
        List<int>? originalSizes, int originalCount,
        Stream output,
        IncrementalHash? hasher = null)
    {
        var strategy = _fss.GetStrategy(fssStrategy);

        if (fssStrategy is Constants.FssLevel1 or Constants.FssLevel2)
        {
            var stripped = strategy.Strip(decryptedFragments, originalCount, originalSizes);
            foreach (var frag in stripped)
            {
                output.Write(frag, 0, frag.Length);
                hasher?.AppendData(frag, 0, frag.Length);
            }
            return;
        }

        bool alreadyStripped = fssStrategy is Constants.FssLevel61 or Constants.FssLevel62;
        for (int i = 0; i < originalCount; i++)
        {
            if (!decryptedFragments.TryGetValue(i, out var data)) continue;
            byte[] original = alreadyStripped
                ? data
                : strategy.StripSingle(data, i, originalSizes);
            output.Write(original, 0, original.Length);
            hasher?.AppendData(original, 0, original.Length);
            CryptographicOperations.ZeroMemory(decryptedFragments[i]);
            decryptedFragments[i] = null!;
        }
    }

    // --- Streaming Restore ---

    private async Task<bool> TryStreamingRestoreCoreAsync(
        RdrfIndex index, byte[] aesKey, string filePrefix, string outputPath,
        IProgress<RdrfProgressReport>? progress, CancellationToken ct)
    {
        int fragmentCount = index.FragmentCount;
        int origCount = index.OriginalFragmentCount > 0 ? index.OriginalFragmentCount : fragmentCount;

        // Check all fragments exist (accounting for SourceVersion references)
        for (int i = 0; i < fragmentCount; i++)
        {
            string svFp = filePrefix;
            int svIdx = i;
            if (index.Fragments?.Count > i && index.Fragments[i].SourceVersion != null)
            {
                svFp = index.Fragments[i].SourceVersion;
                svIdx = index.Fragments[i].SourceIndex ?? i;
            }
            if (!_storage.FragmentExists(Frags.FragmentFilename(svFp, svIdx)))
                return false;
        }

        var strategy = _fss.GetStrategy(index.FssStrategy);
        bool hasEtn = index.HasFss6EtnData;
        var etn = hasEtn ? (Fss6Etn)_fss.GetStrategy(Constants.FssLevel6) : null;

        // Pre-read SourceVersion index keys and prefixes
        var sourceKeys = new Dictionary<string, byte[]>();
        var sourcePrefixes = new Dictionary<string, string>();
        if (index.Fragments != null)
        {
            for (int i = 0; i < fragmentCount && i < index.Fragments.Count; i++)
            {
                string? sv = index.Fragments[i].SourceVersion;
                if (sv != null && !sourceKeys.ContainsKey(sv))
                {
                    byte[] srcIdx = await _storage.ReadIndexAsync(sv, ct).ConfigureAwait(false);
                    (byte[] srcKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(srcIdx, _rcCode);
                    sourceKeys[sv] = srcKey;
                    var srcIndex = _indexManager.DeserializeIndex(cbor);
                    sourcePrefixes[sv] = srcIndex.CustomName ?? sv;
                }
            }
        }

        try
        {
            bool isCkc = string.Equals(index.Compression, Constants.CompressionCkc, StringComparison.OrdinalIgnoreCase);
            // When ETN/FSS6.x trailers were removed by StripAnyTrailer, skip StripSingle
            // (Fss61/62 trailer Parse can false-positive on raw payload).
            bool alreadyStripped = hasEtn
                || index.FssStrategy is Constants.FssLevel61 or Constants.FssLevel62;

            progress?.Report(new RdrfProgressReport { Stage = "Downloading", TotalItems = fragmentCount });

            // CKC multi-fragment: shared TANS tables require all compressed bodies first.
            if (isCkc)
            {
                return await StreamingRestoreCkcAsync(
                    index, aesKey, filePrefix, outputPath, etn, alreadyStripped,
                    origCount, fragmentCount, sourceKeys, sourcePrefixes, progress, ct).ConfigureAwait(false);
            }

            // Pipelined streaming: bounded concurrent decrypt/decompress, ordered strip+write.
            // Peak ≈ prefetch fragments (not full set); wall-clock much better than pure serial.
            int prefetch = Math.Clamp(Constants.DefaultParallelism, 2, 8);
            if (fragmentCount < 2) prefetch = 1;

            using var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write,
                FileShare.None, 256 * 1024, FileOptions.SequentialScan | FileOptions.Asynchronous);
            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

            // Kick off bounded-parallel prepare tasks; await in order for sequential write.
            var prepare = new Task<byte[]>[fragmentCount];
            using var gate = new SemaphoreSlim(prefetch, prefetch);
            for (int i = 0; i < fragmentCount; i++)
            {
                int idx = i;
                prepare[idx] = PrepareFragmentGatedAsync(
                    index, aesKey, filePrefix, idx, etn,
                    sourceKeys, sourcePrefixes, gate, ct);
            }

            for (int i = 0; i < fragmentCount; i++)
            {
                ct.ThrowIfCancellationRequested();
                byte[] data = await prepare[i].ConfigureAwait(false);
                prepare[i] = null!; // allow GC of completed task

                if (i < origCount)
                {
                    byte[] original = alreadyStripped
                        ? data
                        : strategy.StripSingle(data, i, index.OriginalFragmentSizes);
                    int writeLen = original.Length;
                    if (index.OriginalFragmentSizes != null && i < index.OriginalFragmentSizes.Count)
                    {
                        int want = index.OriginalFragmentSizes[i];
                        if (want >= 0 && want < writeLen)
                            writeLen = want;
                    }
                    // Write span without ToArray when trimming tail padding.
                    await output.WriteAsync(original.AsMemory(0, writeLen), ct).ConfigureAwait(false);
                    hasher.AppendData(original.AsSpan(0, writeLen));
                }

                progress?.Report(new RdrfProgressReport
                {
                    Stage = "Downloading", CurrentItem = i + 1, TotalItems = fragmentCount
                });
            }

            if (output.Length > index.FileSize && index.FileSize >= 0)
                output.SetLength(index.FileSize);

            await output.FlushAsync(ct).ConfigureAwait(false);
            string restoredHash = Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
            bool valid = IntegrityChecker.VerifyHash(restoredHash, index.OriginalHash);
            _logger.Info("RestoreOrchestrator", $"  Integrity check (stream): {(valid ? "PASS" : "FAIL")}");
            if (!valid && File.Exists(outputPath))
                File.Delete(outputPath);
            return valid;
        }
        catch (Exception ex)
        {
            _logger.Warn("RestoreOrchestrator", $"Streaming restore failed: {ex.GetType().Name}: {ex.Message}");
            if (File.Exists(outputPath)) File.Delete(outputPath);
            return false;
        }
    }

    private async Task<byte[]> PrepareFragmentGatedAsync(
        RdrfIndex index, byte[] aesKey, string filePrefix, int i, Fss6Etn? etn,
        Dictionary<string, byte[]> sourceKeys, Dictionary<string, string> sourcePrefixes,
        SemaphoreSlim gate, CancellationToken ct)
    {
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            return await LoadDecryptPrepareFragmentAsync(
                index, aesKey, filePrefix, i, etn, sourceKeys, sourcePrefixes, ct)
                .ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>
    /// Open fragment stream and AES-CTR decrypt+strip without a full encrypted byte[] buffer.
    /// Falls back to ReadFragmentAsync when stream open is unavailable.
    /// </summary>
    private async Task<byte[]> DecryptFragmentStreamingAsync(string filename, byte[] key, CancellationToken ct)
    {
        try
        {
            await using var stream = await _storage.OpenReadFragmentAsync(filename, ct).ConfigureAwait(false);
            return await EncryptionLayer.DecryptAndStripFragmentFromStreamAsync(stream, key, ct)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not CryptographicException and not OperationCanceledException)
        {
            // Fallback for non-local / non-stream backends
            byte[] encrypted = await _storage.ReadFragmentAsync(filename, ct).ConfigureAwait(false);
            return _encryption.DecryptAndStripFragment(encrypted, key);
        }
    }

    /// <summary>
    /// Load one fragment: resolve SourceVersion, decrypt, strip ETN/repair trailers, decompress.
    /// Does not perform FSS StripSingle (caller does).
    /// </summary>
    private async Task<byte[]> LoadDecryptPrepareFragmentAsync(
        RdrfIndex index, byte[] aesKey, string filePrefix, int i, Fss6Etn? etn,
        Dictionary<string, byte[]> sourceKeys, Dictionary<string, string> sourcePrefixes,
        CancellationToken ct)
    {
        string svFp = filePrefix;
        int svIdx = i;
        byte[] key = aesKey;
        if (index.Fragments?.Count > i && index.Fragments[i].SourceVersion != null)
        {
            string sv = index.Fragments[i].SourceVersion!;
            svFp = sourcePrefixes.TryGetValue(sv, out var sp) ? sp : sv;
            svIdx = index.Fragments[i].SourceIndex ?? i;
            if (sourceKeys.TryGetValue(sv, out var cachedKey))
                key = cachedKey;
        }

        byte[] data = await DecryptFragmentStreamingAsync(
            Frags.FragmentFilename(svFp, svIdx), key, ct).ConfigureAwait(false);

        // Pure FSS6 may compress(body+trailer) → decompress before strip.
        // FSS6.1/6.2 compress pre-ETN → trailers outer → strip then decompress.
        bool pureFss6Compress = etn != null
            && index.FssStrategy is Constants.FssLevel6
            && !string.IsNullOrEmpty(index.Compression)
            && LooksCompressedFrame(data, index.Compression);
        if (pureFss6Compress)
            data = Compressor.Decompress(data, index.Compression!);
        if (etn != null)
            data = StripAnyTrailer(data);
        else if (!string.IsNullOrEmpty(index.Compression))
            data = Compressor.Decompress(data, index.Compression!);
        if (etn != null && !string.IsNullOrEmpty(index.Compression) && !pureFss6Compress)
            data = Compressor.Decompress(data, index.Compression!);
        return data;
    }

    /// <summary>
    /// CKC multi-frag path: must materialize all compressed fragments for shared-table decompress,
    /// then stream strip+write (algorithm constraint on shared TANS tables from frag0).
    /// </summary>
    private async Task<bool> StreamingRestoreCkcAsync(
        RdrfIndex index, byte[] aesKey, string filePrefix, string outputPath,
        Fss6Etn? etn, bool alreadyStripped,
        int origCount, int fragmentCount,
        Dictionary<string, byte[]> sourceKeys, Dictionary<string, string> sourcePrefixes,
        IProgress<RdrfProgressReport>? progress, CancellationToken ct)
    {
        var strategy = _fss.GetStrategy(index.FssStrategy);
        var list = new List<byte[]>(fragmentCount);
        for (int i = 0; i < fragmentCount; i++)
        {
            ct.ThrowIfCancellationRequested();
            string svFp = filePrefix;
            int svIdx = i;
            byte[] key = aesKey;
            if (index.Fragments?.Count > i && index.Fragments[i].SourceVersion != null)
            {
                string sv = index.Fragments[i].SourceVersion!;
                svFp = sourcePrefixes.TryGetValue(sv, out var sp) ? sp : sv;
                svIdx = index.Fragments[i].SourceIndex ?? i;
                if (sourceKeys.TryGetValue(sv, out var cachedKey))
                    key = cachedKey;
            }
            byte[] data = await DecryptFragmentStreamingAsync(
                Frags.FragmentFilename(svFp, svIdx), key, ct).ConfigureAwait(false);
            if (etn != null)
                data = StripAnyTrailer(data);
            list.Add(data);
            progress?.Report(new RdrfProgressReport
            {
                Stage = "Downloading", CurrentItem = i + 1, TotalItems = fragmentCount
            });
        }

        CkcEngine.DecompressInPlace(list);

        using var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write,
            FileShare.None, 256 * 1024, FileOptions.SequentialScan | FileOptions.Asynchronous);
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        for (int i = 0; i < origCount && i < list.Count; i++)
        {
            byte[] original = alreadyStripped
                ? list[i]
                : strategy.StripSingle(list[i], i, index.OriginalFragmentSizes);
            int writeLen = original.Length;
            if (index.OriginalFragmentSizes != null && i < index.OriginalFragmentSizes.Count)
            {
                int want = index.OriginalFragmentSizes[i];
                if (want >= 0 && want < writeLen)
                    writeLen = want;
            }
            await output.WriteAsync(original.AsMemory(0, writeLen), ct).ConfigureAwait(false);
            hasher.AppendData(original.AsSpan(0, writeLen));
            list[i] = null!;
        }
        if (output.Length > index.FileSize && index.FileSize >= 0)
            output.SetLength(index.FileSize);
        await output.FlushAsync(ct).ConfigureAwait(false);
        string restoredHash = Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
        bool valid = IntegrityChecker.VerifyHash(restoredHash, index.OriginalHash);
        _logger.Info("RestoreOrchestrator", $"  Integrity check (stream/ckc): {(valid ? "PASS" : "FAIL")}");
        if (!valid && File.Exists(outputPath))
            File.Delete(outputPath);
        return valid;
    }

    /// <summary>
    /// True when the leading bytes look like a compressed frame for the named codec
    /// (used to decide decompress-before-trailer vs trailer-before-decompress).
    /// </summary>
    private static bool LooksCompressedFrame(byte[] data, string? method)
    {
        if (data == null || data.Length < 4 || string.IsNullOrEmpty(method))
            return false;
        // LZ4 frame magic 04 22 4D 18
        if (method.Equals(Constants.CompressionLz4, StringComparison.OrdinalIgnoreCase)
            || method.Equals(Constants.CompressionLz4Hc, StringComparison.OrdinalIgnoreCase))
            return data[0] == 0x04 && data[1] == 0x22 && data[2] == 0x4D && data[3] == 0x18;
        // Zstd magic 28 B5 2F FD
        if (method.Equals(Constants.CompressionZstd, StringComparison.OrdinalIgnoreCase))
            return data[0] == 0x28 && data[1] == 0xB5 && data[2] == 0x2F && data[3] == 0xFD;
        // Gzip 1F 8B
        if (method.Equals(Constants.CompressionGzip, StringComparison.OrdinalIgnoreCase))
            return data[0] == 0x1F && data[1] == 0x8B;
        // Brotli has no stable magic; try decompress path via CanHandle
        if (method.Equals(Constants.CompressionBrotli, StringComparison.OrdinalIgnoreCase))
            return true;
        if (method.Equals(Constants.CompressionCkc, StringComparison.OrdinalIgnoreCase))
            return data.Length >= 4 && data[0] == (byte)'C' && data[1] == (byte)'K' && data[2] == (byte)'C';
        return false;
    }

    // --- Dispose ---

    public void Dispose()
    {
        if (_rcCode != null && _rcCode.Length > 0)
            CryptographicOperations.ZeroMemory(_rcCode);
        GC.SuppressFinalize(this);
    }
}




