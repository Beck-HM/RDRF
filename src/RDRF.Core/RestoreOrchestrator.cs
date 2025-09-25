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
    private readonly bool _preDerived;
    private readonly DssaAdapter _storage;
    private readonly FSSEngine _fss;
    private readonly MetadataManager _metadata;
    private readonly RecoveryExecutor _recoveryExecutor;

    public RestoreOrchestrator(
        byte[] key,
        DssaAdapter storage,
        FSSEngine? fssEngine = null,
        bool preDerived = false,
        byte[]? recoveryCode = null)
    {
        if (key == null || key.Length == 0)
            throw new ArgumentException("Key cannot be null or empty", nameof(key));
        _storage = storage ?? throw new ArgumentNullException(nameof(storage));
        _fss = fssEngine ?? new FSSEngine();
        _metadata = MetadataManager.Default;
        _recoveryExecutor = new RecoveryExecutor(_fss);
        _preDerived = preDerived;

        if (preDerived)
        {
            _rcCode = recoveryCode?.Clone() as byte[] ?? [];
            _aesKey = key?.Clone() as byte[] ?? throw new ArgumentNullException(nameof(key));
        }
        else
        {
            _rcCode = key?.Clone() as byte[] ?? throw new ArgumentNullException(nameof(key));
            _aesKey = EncryptionLayer.DeriveKey(key);
        }
    }

    // ── Public Restore Methods ──

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

    // ── Restore From Fragments ──

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

        if (!_preDerived && FragmentFileHeader.GetTotalHeaderSize(fragData) > FragmentFileHeader.HeaderSize)
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

    // ── Async Restore ──

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

        if (!_preDerived && FragmentFileHeader.GetTotalHeaderSize(fragData) > FragmentFileHeader.HeaderSize)
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

    // ── Restore From Index Data (pre-loaded encrypted index) ──

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

    // ── Synchronous Core ──

    private bool RestoreCore(
        RdrfIndex index,
        string filePrefix,
        string outputPath,
        bool allowFssRecovery = true,
        IProgress<RdrfProgressReport>? progress = null)
    {
        return RestoreCoreAsync(index, filePrefix, outputPath, allowFssRecovery, progress, CancellationToken.None)
            .GetAwaiter().GetResult();
    }

    // ── Async Core ──

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
            Debug.WriteLine("  Falling back to dictionary-based restore (recovery or missing fragments)");

            var decryptedFragments = await DownloadAndDecryptFragmentsAsync(
                filePrefix, fragmentCount, fileFingerprint, progress, ct, index).ConfigureAwait(false);

            // ETN cross-validation (only if BM data available in the Index)
            // Must run BEFORE stripping trailers, as cross-validation needs them
            var etnActual = false;
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
            StripFssEncodingToStream(decryptedFragments, fssStrategy, originalSizes, origCount2, outputPath);
        }

        // Decompress if the backup was compressed
        try
        {
            if (index.Compression == Constants.CompressionLz4)
            {
                byte[] onDisk = File.ReadAllBytes(outputPath);
                byte[] decompressed = RDRF.Core.Compression.Compressor.Decompress(onDisk, index.Compression);
                File.WriteAllBytes(outputPath, decompressed);
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"  Decompression failed: {ex.Message}");
            if (File.Exists(outputPath)) File.Delete(outputPath);
            return false;
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
        Debug.WriteLine($"  Integrity check FAILED");
        return false;
    }

    // ── Download and Decrypt Fragments ──
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
        return DownloadAndDecryptFragmentsAsync(filePrefix, fragmentCount, fileFingerprint, progress, CancellationToken.None, null)
            .GetAwaiter().GetResult();
    }

    private async Task<Dictionary<int, byte[]>> DownloadAndDecryptFragmentsAsync(
        string filePrefix, int fragmentCount, string fileFingerprint,
        IProgress<RdrfProgressReport>? progress, CancellationToken ct,
        RdrfIndex? index = null)
    {
        var result = new ConcurrentDictionary<int, byte[]>();
        int decryptErrors = 0;

        // Pre-read all unique SourceVersion index files for salt (avoids sequential per-fragment reads)
        var sourceSalts = new Dictionary<string, byte[]>();
        if (index?.Fragments != null)
        {
            for (int i = 0; i < fragmentCount && i < index.Fragments.Count; i++)
            {
                string? sv = index.Fragments[i].SourceVersion;
                if (sv != null && !sourceSalts.ContainsKey(sv))
                {
                    byte[] srcIdx = await _storage.ReadIndexAsync(sv, ct).ConfigureAwait(false);
                    sourceSalts[sv] = srcIdx.AsSpan(0, Constants.SaltPrefixLength).ToArray();
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

                    if (sourceSalts.TryGetValue(sourceFp, out var cachedSalt))
                    {
                        key = EncryptionLayer.DeriveKey(_rcCode, cachedSalt);
                    }
                    else if (index?.Fragments?.Count > i && index.Fragments[i].SourceVersion != null)
                    {
                        sourceFp = index.Fragments[i].SourceVersion;
                        sourcePrefix = sourceFp;
                        if (!sourceSalts.TryGetValue(sourceFp, out cachedSalt))
                        {
                            byte[] srcIdx = await _storage.ReadIndexAsync(sourceFp, ct2)
                                .ConfigureAwait(false);
                            cachedSalt = srcIdx.AsSpan(0, Constants.SaltPrefixLength).ToArray();
                            sourceSalts[sourceFp] = cachedSalt;
                        }
                        key = EncryptionLayer.DeriveKey(_rcCode, cachedSalt);
                    }

                    string fname = Frags.FragmentFilename(sourcePrefix, i);
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

    // ── ETN Cross-Validate ──

    private async Task<bool> RunEtnCrossValidateAsync(
        RdrfIndex index, Dictionary<int, byte[]> decryptedFragments,
        string fileFingerprint, CancellationToken ct)
    {
        bool validationActual = false;
        try
        {
            if (await _storage.RcExistsAsync(fileFingerprint, ct).ConfigureAwait(false))
            {
                byte[] encryptedRc = await _storage.ReadRcAsync(fileFingerprint, ct).ConfigureAwait(false);
                byte[] rcBytes = EncryptionLayer.DecryptFragmentWithKey(encryptedRc, _aesKey);
                byte[] indexBytes = IndexManager.SerializeIndex(index);

                var cvResult = Fss6Etn.CrossValidate(
                    indexBytes,
                    decryptedFragments.OrderBy(k => k.Key).Select(k => k.Value).ToList(),
                    rcBytes);

                if (!cvResult.IsValid)
                {
                    Debug.WriteLine($"  ETN cross-validation found corruption:");
                    if (cvResult.IndexCorrupted)
                        Debug.WriteLine($"    - Index corrupted ({cvResult.IndexCorruptedBlocks.Count} blocks)");
                    if (cvResult.RcCorrupted)
                        Debug.WriteLine($"    - RC file corrupted ({cvResult.RcCorruptedBlocks.Count} blocks)");
                    if (cvResult.CorruptedFragments.Count > 0)
                        Debug.WriteLine($"    - Corrupted fragments: {string.Join(", ", cvResult.CorruptedFragments)}");

                    // FSS6.1/6.2: try three-node repair
                    if (!cvResult.IsValid)
                    {
                        if (TryFss61TripleRepair(index, ref rcBytes, decryptedFragments, cvResult))
                            validationActual = true;
                        if (!validationActual && TryFss62TripleRepair(index, ref rcBytes, decryptedFragments, cvResult))
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

    private bool TryFss61TripleRepair(RdrfIndex index, ref byte[] rcBytes,
        Dictionary<int, byte[]> decryptedFragments, FSS.CrossValidationResult cvResult)
    {
        try
        {
            var rcFile = RcFile.FromCbor(rcBytes);
            bool anyRepair = false;

            // Read repair_A and repair_C from first available fragment trailer
            FSS.Fss61RepairData? fragRepairA = null;
            FSS.Fss61RepairData? fragRepairC = null;
            foreach (var kvp in decryptedFragments)
            {
                var (_, _, _, ra, rc) = FSS.Fss61RepairTrailer.Parse(kvp.Value);
                if (ra != null) fragRepairA = ra;
                if (rc != null) fragRepairC = rc;
                if (fragRepairA != null && fragRepairC != null) break;
            }

            // Repair A (Index) from RC.RepairA or fragment trailer
            if (cvResult.IndexCorrupted)
            {
                var ra = rcFile.RepairA ?? fragRepairA;
                if (ra != null)
                {
                    int bs = ra.BlockSize;
                    byte[] idxBytes = IndexManager.SerializeIndex(index);
                    var blocks = SplitToBlocks(idxBytes, bs);
                    var isBad = new bool[blocks.Length];
                    for (int i = 0; i < cvResult.IndexCorruptedBlocks.Count && i < blocks.Length; i++)
                        isBad[cvResult.IndexCorruptedBlocks[i]] = true;

                    bool ok = FSS.LtCode.Decode(blocks, isBad, ra.BlockCount, ra.Seed,
                        ra.Data, blocks.Length, bs);
                    if (ok)
                    {
                        var fixedIndex = IndexManager.DeserializeIndex(MergeBlocks(blocks, idxBytes.Length, bs));
                        if (fixedIndex != null)
                        {
                            index.FileFingerprint = fixedIndex.FileFingerprint;
                            index.OriginalName = fixedIndex.OriginalName;
                            index.OriginalHash = fixedIndex.OriginalHash;
                            anyRepair = true;
                            Debug.WriteLine("  LT repaired Index (A) from repair data");
                        }
                    }
                }
            }

            // Repair B (Fragments) from index.Fss61RepairB or RC.RepairB
            if (cvResult.CorruptedFragments.Count > 0)
            {
                FSS.Fss61RepairData? rb = index.Fss61RepairB ?? rcFile.RepairB;
                if (rb != null)
                {
                    int bs = rb.BlockSize;
                    var sorted = decryptedFragments.OrderBy(k => k.Key).ToList();
                    int totalBlocks = 0;
                    var rawLengths = new List<int>();
                    foreach (var kvp in sorted)
                    {
                        var (rawData, _, _, _, _) = FSS.Fss61RepairTrailer.Parse(kvp.Value);
                        rawLengths.Add(rawData.Length);
                        totalBlocks += (rawData.Length + bs - 1) / bs;
                    }

                    if (totalBlocks == rb.BlockCount)
                    {
                        var allBlocks = new byte[totalBlocks][];
                        var isBad = new bool[totalBlocks];
                        int gIdx = 0;
                        for (int fi = 0; fi < sorted.Count; fi++)
                        {
                            var (rawData, _, _, _, _) = FSS.Fss61RepairTrailer.Parse(sorted[fi].Value);
                            cvResult.CorruptedFragmentBlocks.TryGetValue(fi, out var badBlocks);
                            for (int off = 0; off < rawData.Length; off += bs)
                            {
                                int len = Math.Min(bs, rawData.Length - off);
                                allBlocks[gIdx] = new byte[bs];
                                Buffer.BlockCopy(rawData, off, allBlocks[gIdx], 0, len);
                                int localIdx = off / bs;
                                if (badBlocks != null && badBlocks.Contains(localIdx))
                                    isBad[gIdx] = true;
                                gIdx++;
                            }
                        }

                        bool ok = FSS.LtCode.Decode(allBlocks, isBad, rb.BlockCount,
                            rb.Seed, rb.Data, totalBlocks, bs);
                        if (ok)
                        {
                            gIdx = 0;
                            for (int fi = 0; fi < sorted.Count; fi++)
                            {
                                byte[] frag = sorted[fi].Value;
                                int rawLen = rawLengths[fi];
                                cvResult.CorruptedFragmentBlocks.TryGetValue(fi, out var badBlocks);
                                for (int off = 0; off < rawLen; off += bs)
                                {
                                    int localIdx = off / bs;
                                    if (badBlocks != null && badBlocks.Contains(localIdx))
                                    {
                                        int len = Math.Min(bs, rawLen - off);
                                        Buffer.BlockCopy(allBlocks[gIdx], 0, frag, off, len);
                                    }
                                    gIdx++;
                                }
                            }
                            anyRepair = true;
                            Debug.WriteLine($"  LT repaired Fragments (B) from repair data");
                        }
                    }
                    else
                    {
                        Debug.WriteLine($"  B repair skipped: totalBlocks={totalBlocks} != BlockCount={rb.BlockCount}");
                    }
                }
            }

            // Repair C (RC) from index.Fss61RepairC or fragment trailer
            if (cvResult.RcCorrupted)
            {
                var rc = index.Fss61RepairC ?? fragRepairC;
                if (rc != null)
                {
                    int bs = rc.BlockSize;
                    var blocks = SplitToBlocks(rcBytes, bs);
                    var isBad = new bool[blocks.Length];
                    for (int i = 0; i < cvResult.RcCorruptedBlocks.Count && i < blocks.Length; i++)
                        isBad[cvResult.RcCorruptedBlocks[i]] = true;

                    bool ok = FSS.LtCode.Decode(blocks, isBad, rc.BlockCount, rc.Seed,
                        rc.Data, blocks.Length, bs);
                    if (ok)
                    {
                        rcBytes = MergeBlocks(blocks, rcBytes.Length, bs);
                        anyRepair = true;
                        Debug.WriteLine("  LT repaired RC (C) from repair data");
                    }
                }
            }

            if (!anyRepair)
                Debug.WriteLine("  FSS6.1 triple repair: no applicable repair data found");
            return anyRepair;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"  FSS6.1 triple repair failed: {ex.Message}");
            return false;
        }
    }

    private bool TryFss62TripleRepair(RdrfIndex index, ref byte[] rcBytes,
        Dictionary<int, byte[]> decryptedFragments, FSS.CrossValidationResult cvResult)
    {
        try
        {
            var rcFile = RcFile.FromCbor(rcBytes);
            bool anyRepair = false;

            // Read repair_A and repair_C from first available fragment trailer
            FSS.Fss62RepairData? fragRepair62A = null;
            FSS.Fss62RepairData? fragRepair62C = null;
            foreach (var kvp in decryptedFragments)
            {
                var (_, _, _, ra, rc) = FSS.Fss62RepairTrailer.Parse(kvp.Value);
                if (ra != null) fragRepair62A = ra;
                if (rc != null) fragRepair62C = rc;
                if (fragRepair62A != null && fragRepair62C != null) break;
            }

            // Repair A (Index) from RC.Repair62A or fragment trailer
            if (cvResult.IndexCorrupted)
            {
                var ra = rcFile.Repair62A ?? fragRepair62A;
                if (ra != null)
                {
                    int bs = ra.BlockSize;
                    byte[] idxBytes = IndexManager.SerializeIndex(index);
                    var blocks = SplitToBlocks(idxBytes, bs);
                    var isBad = new bool[blocks.Length];
                    for (int i = 0; i < cvResult.IndexCorruptedBlocks.Count && i < blocks.Length; i++)
                        isBad[cvResult.IndexCorruptedBlocks[i]] = true;

                    int recovered = FSS.DuipCode.Decode(blocks, isBad, ra.Data, ra.EntropySamples,
                        blocks.Length, bs, FSS.DuipCode.DefaultFaceSize, FSS.DuipCode.DefaultEntropyBits);
                    if (recovered >= cvResult.IndexCorruptedBlocks.Count)
                    {
                        var fixedIndex = IndexManager.DeserializeIndex(MergeBlocks(blocks, idxBytes.Length, bs));
                        if (fixedIndex != null)
                        {
                            index.FileFingerprint = fixedIndex.FileFingerprint;
                            index.OriginalName = fixedIndex.OriginalName;
                            index.OriginalHash = fixedIndex.OriginalHash;
                            anyRepair = true;
                            Debug.WriteLine($"  Duip repaired Index (A): {recovered} blocks");
                        }
                    }
                }
            }

            // Repair B (Fragments) from index.Fss62RepairB or RC.Repair62B
            if (cvResult.CorruptedFragments.Count > 0)
            {
                FSS.Fss62RepairData? rb = index.Fss62RepairB ?? rcFile.Repair62B;
                if (rb != null)
                {
                    int bs = rb.BlockSize;
                    var sorted = decryptedFragments.OrderBy(k => k.Key).ToList();
                    int totalBlocks = 0;
                    var rawLengths = new List<int>();
                    foreach (var kvp in sorted)
                    {
                        var (rawData, _, _, _, _) = FSS.Fss62RepairTrailer.Parse(kvp.Value);
                        rawLengths.Add(rawData.Length);
                        totalBlocks += (rawData.Length + bs - 1) / bs;
                    }

                    var allBlocks = new byte[totalBlocks][];
                    var isBad = new bool[totalBlocks];
                    int gIdx = 0;
                    for (int fi = 0; fi < sorted.Count; fi++)
                    {
                        var (rawData, _, _, _, _) = FSS.Fss62RepairTrailer.Parse(sorted[fi].Value);
                        cvResult.CorruptedFragmentBlocks.TryGetValue(fi, out var badBlocks);
                        for (int off = 0; off < rawData.Length; off += bs)
                        {
                            int len = Math.Min(bs, rawData.Length - off);
                            allBlocks[gIdx] = new byte[bs];
                            Buffer.BlockCopy(rawData, off, allBlocks[gIdx], 0, len);
                            int localIdx = off / bs;
                            if (badBlocks != null && badBlocks.Contains(localIdx))
                                isBad[gIdx] = true;
                            gIdx++;
                        }
                    }

                    int recovered = FSS.DuipCode.Decode(allBlocks, isBad, rb.Data, rb.EntropySamples,
                        totalBlocks, bs, FSS.DuipCode.DefaultFaceSize, FSS.DuipCode.DefaultEntropyBits);
                    if (recovered > 0)
                    {
                        gIdx = 0;
                        for (int fi = 0; fi < sorted.Count; fi++)
                        {
                            byte[] frag = sorted[fi].Value;
                            int rawLen = rawLengths[fi];
                            cvResult.CorruptedFragmentBlocks.TryGetValue(fi, out var badBlocks);
                            for (int off = 0; off < rawLen; off += bs)
                            {
                                int localIdx = off / bs;
                                if (badBlocks != null && badBlocks.Contains(localIdx))
                                {
                                    int len = Math.Min(bs, rawLen - off);
                                    Buffer.BlockCopy(allBlocks[gIdx], 0, frag, off, len);
                                }
                                gIdx++;
                            }
                        }
                        anyRepair = true;
                        Debug.WriteLine($"  Duip repaired Fragments (B): {recovered} blocks");
                    }
                }
            }

            // Repair C (RC) from index.Fss62RepairC or fragment trailer
            if (cvResult.RcCorrupted)
            {
                var rc = index.Fss62RepairC ?? fragRepair62C;
                if (rc != null)
                {
                    int bs = rc.BlockSize;
                    var blocks = SplitToBlocks(rcBytes, bs);
                    var isBad = new bool[blocks.Length];
                    for (int i = 0; i < cvResult.RcCorruptedBlocks.Count && i < blocks.Length; i++)
                        isBad[cvResult.RcCorruptedBlocks[i]] = true;

                    int recovered = FSS.DuipCode.Decode(blocks, isBad, rc.Data, rc.EntropySamples,
                        blocks.Length, bs, FSS.DuipCode.DefaultFaceSize, FSS.DuipCode.DefaultEntropyBits);
                    if (recovered > 0)
                    {
                        rcBytes = MergeBlocks(blocks, rcBytes.Length, bs);
                        anyRepair = true;
                        Debug.WriteLine($"  Duip repaired RC (C): {recovered} blocks");
                    }
                }
            }

            if (!anyRepair)
                Debug.WriteLine("  FSS6.2 triple repair: no applicable repair data found");
            return anyRepair;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"  FSS6.2 triple repair failed: {ex.Message}");
            return false;
        }
    }

    private static byte[][] SplitToBlocks(byte[] data, int blockSize)
    {
        int count = (data.Length + blockSize - 1) / blockSize;
        var blocks = new byte[count][];
        for (int i = 0; i < count; i++)
        {
            int off = i * blockSize;
            int len = Math.Min(blockSize, data.Length - off);
            blocks[i] = new byte[blockSize];
            Buffer.BlockCopy(data, off, blocks[i], 0, len);
        }
        return blocks;
    }

    private static byte[] MergeBlocks(byte[][] blocks, int originalLength, int blockSize)
    {
        var data = new byte[originalLength];
        for (int i = 0; i < blocks.Length; i++)
        {
            int off = i * blockSize;
            int len = Math.Min(blockSize, originalLength - off);
            Buffer.BlockCopy(blocks[i], 0, data, off, len);
        }
        return data;
    }

    private static byte[] StripAnyTrailer(byte[] frag)
    {
        var (raw62, _, _, _, _) = FSS.Fss62RepairTrailer.Parse(frag);
        if (raw62.Length < frag.Length) return raw62;
        var (raw61, _, _, _, _) = FSS.Fss61RepairTrailer.Parse(frag);
        if (raw61.Length < frag.Length) return raw61;
        var (rawEtn, _, _, _, _, _, _) = EtnTrailer.Parse(frag);
        return rawEtn;
    }

    // ── Strip FSS Encoding ──

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
        var strategy = _fss.GetStrategy(fssStrategy);

        // FSS1/FSS2 rearrange data across fragments - StripSingle cannot recover independently
        if (fssStrategy is Constants.FssLevel1 or Constants.FssLevel2)
        {
            var stripped = strategy.Strip(decryptedFragments, originalCount, originalSizes);
            using var fssOut = new FileStream(outputPath, FileMode.Create, FileAccess.Write);
            foreach (var frag in stripped)
                fssOut.Write(frag, 0, frag.Length);
            return;
        }

        bool alreadyStripped = fssStrategy is Constants.FssLevel61 or Constants.FssLevel62;
        using var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write);
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

    // ── Streaming Restore ──

    private async Task<bool> TryStreamingRestoreCoreAsync(
        RdrfIndex index, string filePrefix, string outputPath,
        IProgress<RdrfProgressReport>? progress, CancellationToken ct)
    {
        int fragmentCount = index.FragmentCount;
        int origCount = index.OriginalFragmentCount > 0 ? index.OriginalFragmentCount : fragmentCount;

        // FSS1/FSS2 rearrange data across fragments - streaming per-fragment StripSingle isn't possible
        if (index.FssStrategy is Constants.FssLevel1 or Constants.FssLevel2)
            return false;

        for (int i = 0; i < fragmentCount; i++)
            if (!_storage.FragmentExists(Frags.FragmentFilename(filePrefix, i)))
                return false;

        var strategy = _fss.GetStrategy(index.FssStrategy);
        bool hasEtn = index.Fss6FragmentBlockMaps != null || index.Fss6RcBlockMap != null;
        var etn = hasEtn ? (Fss6Etn)_fss.GetStrategy(Constants.FssLevel6) : null;

        try
        {
            using var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write);
            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

            var channel = Channel.CreateBounded<(int idx, byte[] data)>(4);

            var producer = Task.Run(async () =>
            {
                for (int i = 0; i < fragmentCount; i++)
                {
                    ct.ThrowIfCancellationRequested();
                    byte[] encrypted = await _storage.ReadFragmentAsync(
                        Frags.FragmentFilename(filePrefix, i), ct).ConfigureAwait(false);
                    byte[] decrypted = EncryptionLayer.DecryptAndStripFragment(encrypted, _aesKey);
                    if (etn != null && index.FssStrategy != Constants.FssLevel61
                        && index.FssStrategy != Constants.FssLevel62)
                        decrypted = etn.Strip(decrypted);
                    await channel.Writer.WriteAsync((i, decrypted), ct).ConfigureAwait(false);
                }
                channel.Writer.Complete();
            });

            var consumer = Task.Run(async () =>
            {
                await foreach (var (idx, decrypted) in channel.Reader.ReadAllAsync(ct).ConfigureAwait(false))
                {
                    if (idx >= origCount) continue;
                    byte[] original = strategy.StripSingle(decrypted, idx, index.OriginalFragmentSizes);
                    output.Write(original, 0, original.Length);
                    hasher.AppendData(original.AsSpan(0, original.Length));
                }
            });

            await Task.WhenAll(producer, consumer).ConfigureAwait(false);

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

    // ── Dispose ──

    public void Dispose()
    {
        if (_rcCode != null && _rcCode.Length > 0)
            CryptographicOperations.ZeroMemory(_rcCode);
        if (_aesKey != null && _aesKey.Length > 0)
            CryptographicOperations.ZeroMemory(_aesKey);
        GC.SuppressFinalize(this);
    }
}
