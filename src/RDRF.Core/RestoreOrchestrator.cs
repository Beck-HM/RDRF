using RDRF.Core.Abstractions;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Hashing;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Channels;
using RDRF.Core.Compression;
using RDRF.Core.Encryption;
using RDRF.Core.ETN;
using RDRF.Core.FragmentEngine;
using RDRF.Core.Logging;using RDRF.Core.FSS;
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
///   Standard: loads all fragments, decrypts, validates, recovers, decodes.
///   Streaming: sequentially reads, decrypts, strips, decompresses fragments
///     and concatenates them directly (fast path, no recovery, no FSS decode).
///     Only works when:
///       - All fragments are present (no missing fragments)
///       - FSS strategy <= FSS2R (no cross-fragment dependency)
///       - FSS6 is not active
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

        bool hasFss6 = index.Fss6FragmentBlockMaps != null || index.Fss6RcBlockMap != null;

        // Try streaming restore when all fragments are on disk (no recovery needed)
        bool streamingPath = false;
        if (await TryStreamingRestoreCoreAsync(index, aesKey, filePrefix, outputPath,
                progress, ct).ConfigureAwait(false))
        {
            streamingPath = true;
        }

        if (!streamingPath)
        {
            var decryptedFragments = await DownloadAndDecryptFragmentsAsync(
                aesKey, filePrefix, fragmentCount, fileFingerprint, progress, ct, index).ConfigureAwait(false);

            // ETN cross-validation (only if BM data available in the Index)
            // Must run BEFORE stripping trailers, as cross-validation needs them
            var etnActual = false;
            _logger.Info("RestoreOrchestrator",$"  [DICT] hasFss6={hasFss6} fragCount={decryptedFragments.Count} BM={index.Fss6FragmentBlockMaps?.Count} RcBM={index.Fss6RcBlockMap?.Count}");
            if (hasFss6)
            {
                ct.ThrowIfCancellationRequested();
                etnActual = await RunEtnCrossValidateAsync(index, decryptedFragments,
                    fileFingerprint, aesKey, ct).ConfigureAwait(false);
            }

            // Strip ETN/FSS6.1 trailers (parallel, only if ETN data exists)
            if (hasFss6)
            {
                bool isFss61 = fssStrategy is Constants.FssLevel61 or Constants.FssLevel62;
                var keys = decryptedFragments.Keys.ToList();
                Parallel.ForEach(keys, idx =>
                {
                    decryptedFragments[idx] = isFss61
                        ? StripAnyTrailer(decryptedFragments[idx])
                        : ((Fss6Etn)_fss.GetStrategy(Constants.FssLevel6)).Strip(decryptedFragments[idx]);
                });
            }

                if (allowFssRecovery)
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
                        _logger.Info("RestoreOrchestrator",$"  Restore failed: {stillMissing.Count} fragments still missing");
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
                    _logger.Info("RestoreOrchestrator",$"  Restore failed: {missing.Count} fragments missing (recovery disabled)");
                    return false;
                }
            }

            int origCount2 = originalCount ?? fragmentCount;
            if (index.Compression == Constants.CompressionLz4)
            {
                // FSS decode all fragments first (Strip handles full decode)
                var strategy = _fss.GetStrategy(fssStrategy);
                bool alreadyStripped = fssStrategy is Constants.FssLevel61 or Constants.FssLevel62;
                var stripped = alreadyStripped
                    ? decryptedFragments.OrderBy(k => k.Key).Select(k => k.Value).ToList()
                    : strategy.Strip(decryptedFragments, origCount2, originalSizes);

                // Strip padding + LZ4 decompress per fragment
                var rawFragments = new List<byte[]>(stripped.Count);
                for (int i = 0; i < stripped.Count; i++)
                {
                    byte[] frag = stripped[i];
                    int storedSize = (originalSizes != null && i < originalSizes.Count) ? originalSizes[i] : frag.Length;
                    byte[] stored = frag.AsSpan(0, Math.Min(storedSize, frag.Length)).ToArray();
                    byte[] decompressed = RDRF.Core.Compression.Compressor.IsLz4Frame(stored)
                        ? RDRF.Core.Compression.Compressor.Decompress(stored, Constants.CompressionLz4)
                        : stored;
                    rawFragments.Add(decompressed);
                }

                using var ms = new MemoryStream(rawFragments.Sum(f => f.Length));
                foreach (var frag in rawFragments)
                    ms.Write(frag, 0, frag.Length);
                File.WriteAllBytes(outputPath, ms.ToArray());
            }
            else
            {
                StripFssEncodingToStream(decryptedFragments, fssStrategy, originalSizes, origCount2, outputPath);
            }
        }

        // Trim restored file to original size (removes FSS1 padding zeros)
        if (File.Exists(outputPath) && new FileInfo(outputPath).Length > index.FileSize)
        {
            using var fs = new FileStream(outputPath, FileMode.Open, FileAccess.ReadWrite);
            fs.SetLength(index.FileSize);
        }

        long outSize = File.Exists(outputPath) ? new FileInfo(outputPath).Length : -1;
        string restoredHash = IntegrityChecker.HashFile(outputPath);
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

    private Dictionary<int, byte[]> DownloadAndDecryptFragments(
        byte[] aesKey, string filePrefix, int fragmentCount, string fileFingerprint,
        IProgress<RdrfProgressReport>? progress)
    {
        var task = Task.Run(() => DownloadAndDecryptFragmentsAsync(aesKey, filePrefix, fragmentCount,
            fileFingerprint, progress, CancellationToken.None, null));
        if (task.Wait(TimeSpan.FromMinutes(30)))
            return task.Result;
        throw new TimeoutException($"Fragment download timed out after 30 minutes: {filePrefix}");
    }

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

    private List<byte[]> StripFssEncoding(
        Dictionary<int, byte[]> decryptedFragments,
        string fssStrategy, int fragmentCount,
        List<int>? originalSizes, int originalCount)
    {
        var strategy = _fss.GetStrategy(fssStrategy);
        return strategy.Strip(decryptedFragments, originalCount, originalSizes);
    }

    private void StripFssEncodingToStream(
        Dictionary<int, byte[]> decryptedFragments,
        string fssStrategy,
        List<int>? originalSizes, int originalCount,
        string outputPath)
    {
        using var fs = new FileStream(outputPath, FileMode.Create, FileAccess.Write);
        StripFssEncodingToStream(decryptedFragments, fssStrategy, originalSizes, originalCount, fs);
    }

    private void StripFssEncodingToStream(
        Dictionary<int, byte[]> decryptedFragments,
        string fssStrategy,
        List<int>? originalSizes, int originalCount,
        Stream output)
    {
        var strategy = _fss.GetStrategy(fssStrategy);

        if (fssStrategy is Constants.FssLevel1 or Constants.FssLevel2)
        {
            var stripped = strategy.Strip(decryptedFragments, originalCount, originalSizes);
            foreach (var frag in stripped)
                output.Write(frag, 0, frag.Length);
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
        bool hasEtn = index.Fss6FragmentBlockMaps != null || index.Fss6RcBlockMap != null;
        var etn = hasEtn ? (Fss6Etn)_fss.GetStrategy(Constants.FssLevel6) : null;

        // Pre-read SourceVersion index keys
        var sourceKeys = new Dictionary<string, byte[]>();
        if (index.Fragments != null)
        {
            for (int i = 0; i < fragmentCount && i < index.Fragments.Count; i++)
            {
                string? sv = index.Fragments[i].SourceVersion;
                if (sv != null && !sourceKeys.ContainsKey(sv))
                {
                    byte[] srcIdx = await _storage.ReadIndexAsync(sv, ct).ConfigureAwait(false);
                    byte[] salt = srcIdx.AsSpan(0, Constants.SaltPrefixLength).ToArray();
                    sourceKeys[sv] = _encryption.DeriveKey(_rcCode, salt);
                }
            }
        }

        try
        {
            using var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write);
            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

            // Phase 1: Parallel download + decrypt + strip
            var decrypted = new System.Collections.Concurrent.ConcurrentDictionary<int, byte[]>();
            await Parallel.ForEachAsync(Enumerable.Range(0, fragmentCount),
                new ParallelOptions { MaxDegreeOfParallelism = Constants.DefaultParallelism, CancellationToken = ct },
                async (i, ct2) =>
                {
                    string svFp = filePrefix;
                    int svIdx = i;
                    byte[] key = aesKey;
                    if (index.Fragments?.Count > i && index.Fragments[i].SourceVersion != null)
                    {
                        svFp = index.Fragments[i].SourceVersion;
                        svIdx = index.Fragments[i].SourceIndex ?? i;
                        if (sourceKeys.TryGetValue(svFp, out var cachedKey))
                            key = cachedKey;
                    }
                    byte[] encrypted = await _storage.ReadFragmentAsync(
                        Frags.FragmentFilename(svFp, svIdx), ct2).ConfigureAwait(false);
                    byte[] data = _encryption.DecryptAndStripFragment(encrypted, key);
                    if (etn != null)
                        data = StripAnyTrailer(data);
                    decrypted[i] = data;
                }).ConfigureAwait(false);

            // Phase 2: Serial write + hash (per-fragment LZ4 decompress)
            bool isLz4 = index.Compression == Constants.CompressionLz4;
            for (int i = 0; i < fragmentCount; i++)
            {
                if (!decrypted.TryGetValue(i, out var data) || i >= origCount) continue;
                byte[] original = strategy.StripSingle(data, i, index.OriginalFragmentSizes);
                if (isLz4)
                {
                    int storedSize = (index.OriginalFragmentSizes != null && i < index.OriginalFragmentSizes.Count)
                        ? index.OriginalFragmentSizes[i] : original.Length;
                    byte[] stored = original.AsSpan(0, Math.Min(storedSize, original.Length)).ToArray();
                    original = RDRF.Core.Compression.Compressor.IsLz4Frame(stored)
                        ? RDRF.Core.Compression.Compressor.Decompress(stored, Constants.CompressionLz4)
                        : stored;
                }
                output.Write(original, 0, original.Length);
                hasher.AppendData(original.AsSpan(0, original.Length));
            }

            byte[] hashBytes = hasher.GetHashAndReset();
            string restoredHash = Hex.EncodeLower(hashBytes);
            bool valid = IntegrityChecker.VerifyHash(restoredHash, index.OriginalHash);
            _logger.Info("RestoreOrchestrator",$"  Integrity check: {(valid ? "PASS" : "FAIL")}");
            return valid;
        }
        catch
        {
            if (File.Exists(outputPath)) File.Delete(outputPath);
            return false;
        }
    }

    // --- Dispose ---

    public void Dispose()
    {
        if (_rcCode != null && _rcCode.Length > 0)
            CryptographicOperations.ZeroMemory(_rcCode);
        GC.SuppressFinalize(this);
    }
}




