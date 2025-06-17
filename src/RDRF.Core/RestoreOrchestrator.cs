using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using RDRF.Core.Encryption;
using RDRF.Core.ETN;
using RDRF.Core.FragmentEngine;
using RDRF.Core.FSS;
using RDRF.Core.FSA;
using RDRF.Core.Index;
using RDRF.Core.Integrity;
using RDRF.Core.Metadata;
using RDRF.Core.Storage;

namespace RDRF.Core;

public class RestoreOrchestrator : IDisposable
{
    private readonly byte[] _rcCode;
    private byte[] _aesKey;
    private readonly bool _preDerived;
    private readonly StorageAdapter _storage;
    private readonly FSSEngine _fss;
    private readonly MetadataManager _metadata;
    private readonly RecoveryExecutor _recoveryExecutor;

    public RestoreOrchestrator(
        byte[] key,
        StorageAdapter storage,
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
        string frag0Path = Frags.FragentFilename(filePrefix, 0);
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
        string frag0Path = Frags.FragentFilename(filePrefix, 0);
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
        int fragmentCount = index.FragentCount;
        string fssStrategy = index.FssStrategy;
        var originalSizes = index.OriginalFragentSizes;
        int? originalCount = index.OriginalFragentCount > 0 ? index.OriginalFragentCount : null;
        string fileFingerprint = index.FileFingerprint;

        // Parse FSA plan
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

        bool hasFss6 = index.Fss6FragentBlockMaps != null || index.Fss6RcBlockMap != null;

        // Try streaming restore when all fragments are on disk (no recovery needed)
        if (await TryStreamingRestoreCoreAsync(index, filePrefix, outputPath,
                progress, ct).ConfigureAwait(false))
        {
            Debug.WriteLine("  Restore complete!");
            return true;
        }
        Debug.WriteLine("  Falling back to dictionary-based restore (recovery or missing fragments)");

        // Download and decrypt fragments
        var decryptedFragments = await DownloadAndDecryptFragmentsAsync(
            filePrefix, fragmentCount, fileFingerprint, progress, ct).ConfigureAwait(false);

        // ETN cross-validation (only if BM data available in the Index)
        // Must run BEFORE stripping trailers, as cross-validation needs them
        var etnActual = false;
        if (hasFss6)
        {
            ct.ThrowIfCancellationRequested();
            etnActual = await RunEtnCrossValidateAsync(index, decryptedFragments,
                fileFingerprint, ct).ConfigureAwait(false);
        }

        // Always strip ETN trailers (safe on non-ETN data)
        var etn = (Fss6Etn)_fss.GetStrategy(Constants.FssLevel6);
        foreach (int idx in decryptedFragments.Keys.ToList())
            decryptedFragments[idx] = etn.Strip(decryptedFragments[idx]);

        // Recovery
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

        // Strip FSS encoding → stream (avoids List<byte[]> intermediate copy)
        int origCount = originalCount ?? fragmentCount;
        StripFssEncodingToStream(decryptedFragments, fssStrategy, originalSizes, origCount, outputPath);

        // Verify integrity
        string restoredHash = IntegrityChecker.HashFile(outputPath);
        bool valid = IntegrityChecker.VerifyHash(restoredHash, index.OriginalHash);
        Debug.WriteLine($"  Integrity check: {(valid ? "PASS" : "FAIL")}");

        if (valid)
        {
            Debug.WriteLine("  Restore complete!");
            return true;
        }
        return false;
    }

    // ── Download and Decrypt Fragments ──

    private Dictionary<int, byte[]> DownloadAndDecryptFragments(
        string filePrefix, int fragmentCount, string fileFingerprint,
        IProgress<RdrfProgressReport>? progress)
    {
        return DownloadAndDecryptFragmentsAsync(filePrefix, fragmentCount, fileFingerprint, progress, CancellationToken.None)
            .GetAwaiter().GetResult();
    }

    private async Task<Dictionary<int, byte[]>> DownloadAndDecryptFragmentsAsync(
        string filePrefix, int fragmentCount, string fileFingerprint,
        IProgress<RdrfProgressReport>? progress, CancellationToken ct)
    {
        var decryptedFragments = new Dictionary<int, byte[]>();
        long totalReadBytes = 0;
        long totalSize = fragmentCount * 1024L * 1024L;

        int decryptErrors = 0;
        for (int i = 0; i < fragmentCount; i++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                string fname = Frags.FragentFilename(filePrefix, i);
                byte[] encrypted = await _storage.ReadFragmentAsync(fname, ct).ConfigureAwait(false);

                bool hasHeader = FragmentFileHeader.HasHeader(encrypted);
                int hdrOff = hasHeader ? FragmentFileHeader.GetTotalHeaderSize(encrypted) : 0;
                byte[] raw = EncryptionLayer.DecryptFragmentCtrWithKey(encrypted, hdrOff, _aesKey);

                if (hasHeader && raw.Length >= 4)
                {
                    int idxLen = BitConverter.ToInt32(raw.AsSpan(0, 4));
                    if (idxLen > 4 && idxLen <= raw.Length - 4)
                        raw = raw[(4 + idxLen)..];
                }

                decryptedFragments[i] = raw;
                totalReadBytes += raw.Length;
            }
            catch (CryptographicException ex)
            {
                Debug.WriteLine($"Fragment {i} decryption failed: {ex.Message}");
                decryptErrors++;
            }
            catch { decryptErrors++; }

            progress?.Report(new RdrfProgressReport
            {
                Stage = "Decrypting",
                CurrentItem = i + 1,
                TotalItems = fragmentCount,
                CurrentBytes = totalReadBytes,
                TotalBytes = totalSize
            });
        }

        if (decryptErrors > 0 && decryptedFragments.Count == 0)
            throw new CryptographicException("All fragments failed to decrypt.");

        return decryptedFragments;
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
                validationActual = true;
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

                    // FSS6.1: try LT repair when fragment corruption detected
                    if (cvResult.CorruptedFragments.Count > 0 && cvResult.CorruptedFragmentBlocks != null)
                        TryFss61BlockRepair(rcBytes, decryptedFragments, cvResult);
                }
                else
                    Debug.WriteLine($"  ETN cross-validation passed");
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"RC file read/validation failed: {ex.Message}");
        }

        return validationActual;
    }

    private void TryFss61BlockRepair(byte[] rcBytes,
        Dictionary<int, byte[]> decryptedFragments, FSS.CrossValidationResult cvResult)
    {
        try
        {
            var rcFile = RcFile.FromCbor(rcBytes);
            if (rcFile.RepairData == null || !rcFile.RepairSeed.HasValue) return;

            int bs = rcFile.RepairBlockSize ?? EtnBlockMap.GetBlockSize(1024 * 1024, "FSS6.1");
            var sorted = decryptedFragments.OrderBy(k => k.Key).ToList();

            int totalBlocks = 0;
            var rawLengths = new List<int>();
            foreach (var kvp in sorted)
            {
                int rawLen = EtnTrailer.Parse(kvp.Value).data.Length;
                rawLengths.Add(rawLen);
                totalBlocks += (rawLen + bs - 1) / bs;
            }

            var allBlocks = new byte[totalBlocks][];
            var isBad = new bool[totalBlocks];
            int globalIdx = 0;

            for (int fi = 0; fi < sorted.Count; fi++)
            {
                byte[] frag = sorted[fi].Value;
                var (rawData, _, _, _, _, _, _) = EtnTrailer.Parse(frag);

                cvResult.CorruptedFragmentBlocks.TryGetValue(fi, out var badBlocks);

                for (int off = 0; off < rawData.Length; off += bs)
                {
                    int len = Math.Min(bs, rawData.Length - off);
                    allBlocks[globalIdx] = new byte[bs];
                    Buffer.BlockCopy(rawData, off, allBlocks[globalIdx], 0, len);
                    if (badBlocks != null && badBlocks.Contains(globalIdx))
                        isBad[globalIdx] = true;
                    globalIdx++;
                }
            }

            int badCount = isBad.Count(b => b);
            if (badCount == 0) return;

            bool recovered = FSS.LtCode.Decode(allBlocks, isBad,
                rcFile.RepairCount.Value, rcFile.RepairSeed.Value,
                rcFile.RepairData, totalBlocks, bs);

            if (!recovered)
            {
                Debug.WriteLine($"  LT repair failed: could only partially recover blocks");
                return;
            }

            Debug.WriteLine($"  LT repair succeeded: recovered {badCount} corrupted blocks");

            // Splice recovered blocks back into fragments
            globalIdx = 0;
            for (int fi = 0; fi < sorted.Count; fi++)
            {
                byte[] frag = sorted[fi].Value;
                int rawLen = rawLengths[fi];
                cvResult.CorruptedFragmentBlocks.TryGetValue(fi, out var badBlocks);

                if (badBlocks == null)
                {
                    globalIdx += (rawLen + bs - 1) / bs;
                    continue;
                }

                for (int off = 0; off < rawLen; off += bs)
                {
                    if (badBlocks.Contains(globalIdx))
                    {
                        int len = Math.Min(bs, rawLen - off);
                        Buffer.BlockCopy(allBlocks[globalIdx], 0, frag, off, len);
                    }
                    globalIdx++;
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"  LT repair failed: {ex.Message}");
        }
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
        using var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write);
        for (int i = 0; i < originalCount; i++)
        {
            if (!decryptedFragments.TryGetValue(i, out var data)) continue;
            byte[] original = strategy.StripSingle(data, i, originalSizes);
            output.Write(original, 0, original.Length);
            decryptedFragments[i] = null!;
        }
    }

    // ── Streaming Restore ──

    private async Task<bool> TryStreamingRestoreCoreAsync(
        RdrfIndex index, string filePrefix, string outputPath,
        IProgress<RdrfProgressReport>? progress, CancellationToken ct)
    {
        int fragmentCount = index.FragentCount;
        int origCount = index.OriginalFragentCount > 0 ? index.OriginalFragentCount : fragmentCount;

        for (int i = 0; i < fragmentCount; i++)
            if (!_storage.FragmentExists(Frags.FragentFilename(filePrefix, i)))
                return false;

        var strategy = _fss.GetStrategy(index.FssStrategy);
        var etn = (Fss6Etn)_fss.GetStrategy(Constants.FssLevel6);

        try
        {
            using var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write);
            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

            for (int i = 0; i < fragmentCount; i++)
            {
                ct.ThrowIfCancellationRequested();

                byte[] encrypted = await _storage.ReadFragmentAsync(
                    Frags.FragentFilename(filePrefix, i), ct).ConfigureAwait(false);

                bool header = FragmentFileHeader.HasHeader(encrypted);
                int headerOffset = header ? FragmentFileHeader.GetTotalHeaderSize(encrypted) : 0;

                byte[] decrypted = EncryptionLayer.DecryptFragmentCtrWithKey(encrypted, headerOffset, _aesKey);

                if (header && decrypted.Length >= 4)
                {
                    int idxLen = BitConverter.ToInt32(decrypted.AsSpan(0, 4));
                    if (idxLen > 4 && idxLen <= decrypted.Length - 4)
                        decrypted = decrypted[(4 + idxLen)..];
                }

                if (etn != null)
                    decrypted = etn.Strip(decrypted);

                if (i >= origCount) continue;

                byte[] original = strategy.StripSingle(decrypted, i, index.OriginalFragentSizes);
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
