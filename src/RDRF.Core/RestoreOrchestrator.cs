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
using RDRF.Core.FSS;
using RDRF.Core.FSA;
using RDRF.Core.Index;
using RDRF.Core.Integrity;
using RDRF.Core.Metadata;
using RDRF.Core.Dssa;

namespace RDRF.Core;

public class RestoreOrchestrator : IDisposable
{
    private readonly byte[] _rcCode;
    private byte[] _aesKey;
    private readonly DssaAdapter _storage;
    private readonly FSSEngine _fss;
    private readonly MetadataManager _metadata;
    private readonly RecoveryExecutor _recoveryExecutor;

    public RestoreOrchestrator(
        byte[] aesKey,
        byte[] rcCode,
        DssaAdapter storage,
        FSSEngine? fssEngine = null,
        MetadataManager? metadata = null)
    {
        _aesKey = aesKey?.Clone() as byte[] ?? throw new ArgumentNullException("AES key required");
        _rcCode = rcCode?.Clone() as byte[] ?? [];
        _storage = storage ?? throw new ArgumentNullException(nameof(storage));
        _fss = fssEngine ?? new FSSEngine();
        _metadata = metadata ?? new MetadataManager(null, skipLoad: true);
        _recoveryExecutor = new RecoveryExecutor(_fss);
    }

    // 鈹€鈹€ Public Restore Methods 鈹€鈹€

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
        (_aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, _rcCode);
        var index = IndexManager.DeserializeIndex(cbor);
        string prefix = filePrefix ?? fileFingerprint;
        return RestoreCore(index, prefix, outputPath, allowFssRecovery, progress);
    }

    public bool RestoreFile(string fileFingerprint, FileInfo outputPath, bool allowFssRecovery = true, string? filePrefix = null, IProgress<RdrfProgressReport>? progress = null)
        => RestoreFile(fileFingerprint, outputPath.FullName, allowFssRecovery, filePrefix, progress);

    // 鈹€鈹€ Restore From Fragments 鈹€鈹€

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

        if (FragmentFileHeader.GetTotalHeaderSize(fragData) > FragmentFileHeader.HeaderSize)
        {
            var (embeddedIndexBytes, _, salt) = FragmentFileHeader.DecryptWithEmbeddedIndex(fragData, _aesKey);
            if (salt != null && salt.Length == Constants.SaltPrefixLength)
            {
                _aesKey = EncryptionLayer.DeriveKey(_rcCode, salt);
                var (reDecrypted, _, _) = FragmentFileHeader.DecryptWithEmbeddedIndex(fragData, _aesKey);
                if (reDecrypted != null)
                    embeddedIndexBytes = reDecrypted;
            }
            if (embeddedIndexBytes == null)
                throw new InvalidDataException("Failed to extract embedded index from fragment");
            var index = IndexManager.DeserializeIndex(embeddedIndexBytes);
            return RestoreCore(index, filePrefix, outputPath, allowFssRecovery, progress);
        }
    
        var (idxBytes, _, _) = FragmentFileHeader.DecryptWithEmbeddedIndex(fragData, _aesKey);
        if (idxBytes == null)
            throw new InvalidDataException("Failed to extract embedded index from fragment");
        var idx = IndexManager.DeserializeIndex(idxBytes);
        return RestoreCore(idx, filePrefix, outputPath, allowFssRecovery, progress);
    }

    // 鈹€鈹€ Async Restore 鈹€鈹€

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
        (_aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, _rcCode);
        var index = IndexManager.DeserializeIndex(cbor);
        string prefix = filePrefix ?? fileFingerprint;
        return await RestoreCoreAsync(index, prefix, outputPath, allowFssRecovery, progress, cancellationToken).ConfigureAwait(false);
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

        if (FragmentFileHeader.GetTotalHeaderSize(fragData) > FragmentFileHeader.HeaderSize)
        {
            var (embeddedIndexBytes, _, salt) = FragmentFileHeader.DecryptWithEmbeddedIndex(fragData, _aesKey);
            if (salt != null && salt.Length == Constants.SaltPrefixLength)
            {
                _aesKey = EncryptionLayer.DeriveKey(_rcCode, salt);
                var (reDecrypted, _, _) = FragmentFileHeader.DecryptWithEmbeddedIndex(fragData, _aesKey);
                if (reDecrypted != null)
                    embeddedIndexBytes = reDecrypted;
            }
            if (embeddedIndexBytes == null)
                throw new InvalidDataException("Failed to extract embedded index from fragment");
            var index = IndexManager.DeserializeIndex(embeddedIndexBytes);
            return await RestoreCoreAsync(index, filePrefix, outputPath, allowFssRecovery, progress, cancellationToken).ConfigureAwait(false);
        }

        var (idxBytes, _, _) = FragmentFileHeader.DecryptWithEmbeddedIndex(fragData, _aesKey);
        if (idxBytes == null)
            throw new InvalidDataException("Failed to extract embedded index from fragment");
        var idx = IndexManager.DeserializeIndex(idxBytes);
        return await RestoreCoreAsync(idx, filePrefix, outputPath, allowFssRecovery, progress, cancellationToken).ConfigureAwait(false);
    }

    // 鈹€鈹€ Restore From Index Data (pre-loaded encrypted index) 鈹€鈹€

    public bool RestoreFileFromIndexData(
        byte[] encryptedIndex,
        string filePrefix,
        string outputPath,
        bool allowFssRecovery = true,
        IProgress<RdrfProgressReport>? progress = null)
    {
        (_aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, _rcCode);
        var index = IndexManager.DeserializeIndex(cbor);
        return RestoreCore(index, filePrefix, outputPath, allowFssRecovery, progress);
    }

    // 鈹€鈹€ Synchronous Core 鈹€鈹€

    private bool RestoreCore(
        RdrfIndex index,
        string filePrefix,
        string outputPath,
        bool allowFssRecovery = true,
        IProgress<RdrfProgressReport>? progress = null)
    {
        return Task.Run(() => RestoreCoreAsync(index, filePrefix, outputPath,
            allowFssRecovery, progress, CancellationToken.None))
            .GetAwaiter().GetResult();
    }

    // 鈹€鈹€ Async Core 鈹€鈹€

    private async Task<bool> RestoreCoreAsync(
        RdrfIndex index,
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
        if (await TryStreamingRestoreCoreAsync(index, filePrefix, outputPath,
                progress, ct).ConfigureAwait(false))
        {
            streamingPath = true;
        }

        if (!streamingPath)
        {
            var decryptedFragments = await DownloadAndDecryptFragmentsAsync(
                filePrefix, fragmentCount, fileFingerprint, progress, ct, index).ConfigureAwait(false);

            // ETN cross-validation (only if BM data available in the Index)
            // Must run BEFORE stripping trailers, as cross-validation needs them
            var etnActual = false;
            Debug.WriteLine($"  [DICT] hasFss6={hasFss6} fragCount={decryptedFragments.Count} BM={index.Fss6FragmentBlockMaps?.Count} RcBM={index.Fss6RcBlockMap?.Count}");
            if (hasFss6)
            {
                ct.ThrowIfCancellationRequested();
                etnActual = await RunEtnCrossValidateAsync(index, decryptedFragments,
                    fileFingerprint, ct).ConfigureAwait(false);
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
                        index, decryptedFragments, _metadata, skipVerification: etnActual).ConfigureAwait(false);
                    foreach (var kvp in recoveryResult.RecoveredFragments)
                        decryptedFragments[kvp.Key] = kvp.Value;
                    var stillMissing = new List<int>();
                    for (int i = 0; i < fragmentCount; i++)
                        if (!decryptedFragments.ContainsKey(i)) stillMissing.Add(i);
                    if (stillMissing.Count > 0)
                    {
                        Debug.WriteLine($"  Restore failed: {stillMissing.Count} fragments still missing");
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
                    Debug.WriteLine($"  Restore failed: {missing.Count} fragments missing (recovery disabled)");
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
        Debug.WriteLine($"  Integrity check: {(valid ? "PASS" : "FAIL")}");

        if (valid)
        {
            return true;
        }
        Debug.WriteLine($"  [RESTORE FAIL] hash={restoredHash} expected={index.OriginalHash} size={outSize}");
        return false;
    }

    // 鈹€鈹€ Download and Decrypt Fragments 鈹€鈹€
    //
    // This is the fallback path (path B) used when fragments are missing or
    // corrupted. All fragments are loaded into memory simultaneously to allow
    // FSS recovery and ETN cross-validation. For the common case where all
    // fragments are intact, TryStreamingRestoreCoreAsync (path A) handles the
    // restore with O(1) memory by streaming fragments one at a time.

    private Dictionary<int, byte[]> DownloadAndDecryptFragments(
        string filePrefix, int fragmentCount, string fileFingerprint,
        IProgress<RdrfProgressReport>? progress)
    {
        return Task.Run(() => DownloadAndDecryptFragmentsAsync(filePrefix, fragmentCount,
            fileFingerprint, progress, CancellationToken.None, null))
            .GetAwaiter().GetResult();
    }

    private async Task<Dictionary<int, byte[]>> DownloadAndDecryptFragmentsAsync(
        string filePrefix, int fragmentCount, string fileFingerprint,
        IProgress<RdrfProgressReport>? progress, CancellationToken ct,
        RdrfIndex? index = null)
    {
        var result = new ConcurrentDictionary<int, byte[]>();
        int decryptErrors = 0;

        // Pre-read all unique SourceVersion index files for salt + derive keys once per version
        var sourceKeys = new Dictionary<string, byte[]>();
        if (index?.Fragments != null)
        {
            for (int i = 0; i < fragmentCount && i < index.Fragments.Count; i++)
            {
                string? sv = index.Fragments[i].SourceVersion;
                if (sv != null && !sourceKeys.ContainsKey(sv))
                {
                    byte[] srcIdx = await _storage.ReadIndexAsync(sv, ct).ConfigureAwait(false);
                    byte[] salt = srcIdx.AsSpan(0, Constants.SaltPrefixLength).ToArray();
                    sourceKeys[sv] = EncryptionLayer.DeriveKey(_rcCode, salt);
                }
            }
        }

        await Parallel.ForEachAsync(
            Enumerable.Range(0, fragmentCount),
            new ParallelOptions { MaxDegreeOfParallelism = Constants.DefaultParallelism },
            async (i, ct2) =>
            {
                ct2.ThrowIfCancellationRequested();
                try
                {
                    string sourceFp = fileFingerprint;
                    string sourcePrefix = filePrefix;
                    byte[] key = _aesKey;

                    if (index?.Fragments?.Count > i && index.Fragments[i].SourceVersion != null)
                    {
                        sourceFp = index.Fragments[i].SourceVersion;
                        sourcePrefix = sourceFp;
                        if (sourceKeys.TryGetValue(sourceFp, out var cachedKey))
                            key = cachedKey;
                    }

                    int sourceIdx = i;
                    if (index?.Fragments?.Count > i && index.Fragments[i].SourceIndex.HasValue)
                        sourceIdx = index.Fragments[i].SourceIndex.Value;

                    string fname = Frags.FragmentFilename(sourcePrefix, sourceIdx);
                    byte[] encrypted = await _storage.ReadFragmentAsync(fname, ct2)
                        .ConfigureAwait(false);
                    byte[] raw = EncryptionLayer.DecryptAndStripFragment(encrypted, key);
                    result[i] = raw;
                }
                catch (CryptographicException)
                {
                    Interlocked.Increment(ref decryptErrors);
                }
                catch
                {
                    Interlocked.Increment(ref decryptErrors);
                }
            });

        if (decryptErrors > 0 && result.Count == 0)
            throw new CryptographicException("All fragments failed to decrypt.");

        return new Dictionary<int, byte[]>(result);
    }

    // 鈹€鈹€ ETN Cross-Validate 鈹€鈹€

    private async Task<bool> RunEtnCrossValidateAsync(
        RdrfIndex index, Dictionary<int, byte[]> decryptedFragments,
        string fileFingerprint, CancellationToken ct)
    {
        Debug.WriteLine($"  [ETN] entered fp={fileFingerprint.Substring(0, 16)}...");
        bool validationActual = false;
        try
        {
            bool rcExists = await _storage.RcExistsAsync(fileFingerprint, ct).ConfigureAwait(false);
            Debug.WriteLine($"  [ETN] rcExists={rcExists}");
            if (rcExists)
            {
                byte[] encryptedRc = await _storage.ReadRcAsync(fileFingerprint, ct).ConfigureAwait(false);
                byte[] rcBytes = EncryptionLayer.DecryptFragmentWithKey(encryptedRc, _aesKey);
                byte[] indexBytes = IndexManager.SerializeIndex(index);

                var cvResult = Fss6Etn.CrossValidate(
                    indexBytes,
                    decryptedFragments.OrderBy(k => k.Key).Select(k => k.Value).ToList(),
                    rcBytes);

                int totalCvBlocks = 0;
                foreach (var kv in cvResult.CorruptedFragmentBlocks) totalCvBlocks += kv.Value.Count;
                Debug.WriteLine($"  [CV] IsValid={cvResult.IsValid} BadFrags={cvResult.CorruptedFragments.Count} BadBlocks={totalCvBlocks} IndexBad={cvResult.IndexCorrupted} RcBad={cvResult.RcCorrupted}");

                if (!cvResult.IsValid)
                {
                    Debug.WriteLine($"  ETN cross-validation found corruption:");
                    if (cvResult.IndexCorrupted)
                        Debug.WriteLine($"    - Index corrupted ({cvResult.IndexCorruptedBlocks.Count} blocks)");
                    if (cvResult.RcCorrupted)
                        Debug.WriteLine($"    - RC file corrupted ({cvResult.RcCorruptedBlocks.Count} blocks)");
                    if (cvResult.CorruptedFragments.Count > 0)
                        Debug.WriteLine($"    - Corrupted fragments: {string.Join(", ", cvResult.CorruptedFragments)}");

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
                    Debug.WriteLine($"  ETN cross-validation passed");
                    validationActual = true;
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"RC file read/validation failed: {ex.Message}");
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

    // 鈹€鈹€ Strip FSS Encoding 鈹€鈹€

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

    // 鈹€鈹€ Streaming Restore 鈹€鈹€

    private async Task<bool> TryStreamingRestoreCoreAsync(
        RdrfIndex index, string filePrefix, string outputPath,
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
                    sourceKeys[sv] = EncryptionLayer.DeriveKey(_rcCode, salt);
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
                    byte[] key = _aesKey;
                    if (index.Fragments?.Count > i && index.Fragments[i].SourceVersion != null)
                    {
                        svFp = index.Fragments[i].SourceVersion;
                        svIdx = index.Fragments[i].SourceIndex ?? i;
                        if (sourceKeys.TryGetValue(svFp, out var cachedKey))
                            key = cachedKey;
                    }
                    byte[] encrypted = await _storage.ReadFragmentAsync(
                        Frags.FragmentFilename(svFp, svIdx), ct2).ConfigureAwait(false);
                    byte[] data = EncryptionLayer.DecryptAndStripFragment(encrypted, key);
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
            string restoredHash = Convert.ToHexString(hashBytes).ToLowerInvariant();
            bool valid = IntegrityChecker.VerifyHash(restoredHash, index.OriginalHash);
            Debug.WriteLine($"  Integrity check: {(valid ? "PASS" : "FAIL")}");
            return valid;
        }
        catch
        {
            if (File.Exists(outputPath)) File.Delete(outputPath);
            return false;
        }
    }

    // 鈹€鈹€ Dispose 鈹€鈹€

    public void Dispose()
    {
        if (_rcCode != null && _rcCode.Length > 0)
            CryptographicOperations.ZeroMemory(_rcCode);
        if (_aesKey != null && _aesKey.Length > 0)
            CryptographicOperations.ZeroMemory(_aesKey);
        GC.SuppressFinalize(this);
    }
}


