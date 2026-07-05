using System.Buffers;
using System.Diagnostics;
using System.IO.Hashing;
using System.Security.Cryptography;
using System.Text.Json;
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

/// <summary>
/// Core backup pipeline orchestrator. Manages the full lifecycle of a backup:
///
/// Pipeline:
///   Stream read → Incremental SHA256 hash → Fragment (1 MB blocks)
///   → LZ4 compress per block → FSS encode (strategy-dependent)
///   → ETN cross-validation inject (FSS6.x) → Fountain code repair (FSS6.1/6.2)
///   → Encrypt with embedded index header → Batch parallel write to storage
///   → Write standalone Index file → Write RC file → Save metadata
///
/// Two constructors:
///   (aesKey, rcCode, ...) — callers that already have a derived AES key.
///   (rcCode, storage, salt, ...) — derives AES key via PBKDF2 with salt.
///
/// All public methods delegate to BackupCoreAsync. The sync wrappers are
/// [Obsolete] and block on the async path via GetAwaiter().GetResult().
/// </summary>
public class BackupOrchestrator : IDisposable
{
    private readonly byte[] _rcCode;
    private readonly byte[] _aesKey;
    private readonly byte[] _salt;
    private readonly DssaAdapter _storage;
    private readonly FSSEngine _fss;
    private readonly FsaEngine _fsa;
    private readonly MetadataManager _metadata;

    /// <summary>
    /// Initializes with a pre-derived AES key. Used by callers that have
    /// already performed key derivation (e.g. RDRFEngine with DeriveKeyLegacy).
    /// </summary>
    public BackupOrchestrator(
        byte[] aesKey,
        byte[] rcCode,
        DssaAdapter storage,
        FSSEngine? fssEngine = null,
        MetadataManager? metadata = null)
    {
        _aesKey = aesKey?.Clone() as byte[] ?? throw new ArgumentNullException("AES key required");
        _rcCode = rcCode?.Clone() as byte[] ?? [];
        _salt = [];
        _storage = storage ?? throw new ArgumentNullException(nameof(storage));
        _fss = fssEngine ?? new FSSEngine();
        _fsa = new FsaEngine();
        _metadata = metadata ?? new MetadataManager(null, skipLoad: true);
    }

    /// <summary>
    /// Initializes with a raw rcCode and salt. The AES key is derived via
    /// EncryptionLayer.DeriveKey(rcCode, salt) using PBKDF2.
    /// </summary>
    public BackupOrchestrator(
        byte[] rcCode,
        DssaAdapter storage,
        byte[] salt,
        FSSEngine? fssEngine = null,
        MetadataManager? metadata = null)
    {
        if (rcCode == null || rcCode.Length == 0)
            throw new ArgumentException("RC code cannot be null or empty", nameof(rcCode));
        _rcCode = (byte[])rcCode.Clone();
        _salt = salt ?? throw new ArgumentNullException(nameof(salt));
        _aesKey = EncryptionLayer.DeriveKey(rcCode, salt);
        _storage = storage ?? throw new ArgumentNullException(nameof(storage));
        _fss = fssEngine ?? new FSSEngine();
        _fsa = new FsaEngine();
        _metadata = metadata ?? new MetadataManager(null, skipLoad: true);
    }

    /// <summary>
    /// Synchronous backup. Blocks on the async pipeline.
    /// </summary>
    [Obsolete("Use BackupFileAsync instead")]
    public string BackupFile(
        string filePath,
        string fssStrategy = "FSS1",
        List<string>? auxiliaryStrategies = null,
        string? originalFilename = null,
        int fragmentSize = 0,
        string? customName = null,
        IProgress<RdrfProgressReport>? progress = null)
    {
        var fileInfo = new FileInfo(filePath);
        return Task.Run(() => BackupCoreAsync(filePath, fssStrategy, auxiliaryStrategies,
            originalFilename, fragmentSize, customName, progress, CancellationToken.None))
            .GetAwaiter().GetResult();
    }

    /// <summary>
    /// Synchronous backup with FileInfo. Blocks on the async pipeline.
    /// </summary>
    [Obsolete("Use BackupFileAsync instead")]
    public string BackupFile(
        FileInfo filePath,
        string fssStrategy = "FSS1",
        List<string>? auxiliary = null,
        int fragmentSize = 0,
        string? customName = null,
        IProgress<RdrfProgressReport>? progress = null)
        => BackupFile(filePath.FullName, fssStrategy, auxiliary, fragmentSize: fragmentSize, customName: customName, progress: progress);

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
        CancellationToken cancellationToken = default)
        => BackupCoreAsync(filePath, fssStrategy, auxiliaryStrategies, originalFilename, fragmentSize, customName, progress, cancellationToken);

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
    ///   Phase 1 — Stream & fragment:
    ///     Open a FileStream, read sequentially, fill 1 MB fragment buffers,
    ///     compute SHA256 incrementally, LZ4-compress each fragment, pad to
    ///     fragment size boundary. Accumulates rawFragments (uncompressed for
    ///     dedup hashing) and originalFragments (LZ4 + padded for encoding).
    ///
    ///   Phase 2 — FSS encode:
    ///     Execute the FSA plan's EncodeSteps. Each step applies an FSS strategy
    ///     (encode or etn_inject) to the fragment list. The number of fragments
    ///     may grow (parity fragments) or stay the same.
    ///
    ///   Phase 3 — ETN + fountain repair:
    ///     If FSS6.x is active, inject ETN cross-validation block maps into
    ///     Index, fragments, and RC. For FSS6.1/6.2, generate fountain code
    ///     repair data (LT or Duip) and append repair trailers to fragments.
    ///
    ///   Phase 4 — Encrypt & write:
    ///     Each fragment is prepended with an encrypted header containing an
    ///     embedded (stripped) Index. Fragments are encrypted with AES-CTR
    ///     via FragmentFileHeader.EncryptWithEmbeddedIndex. Written in batches
    ///     of 8 with Parallel.ForEachAsync and retry logic.
    ///
    ///   Phase 5 — Index + RC write:
    ///     The standalone Index file (with full ETN block maps) is AES-CTR
    ///     encrypted and written. If salt-based key derivation is active, the
    ///     salt is prepended. The RC file (recovery container) is encrypted
    ///     and written separately.
    ///
    /// Call chain:
    ///   RDRFEngine.BackupFileAsync
    ///   → BackupOrchestrator.BackupCoreAsync
    ///     → FsaEngine.Compute (plan)
    ///     → FileStream + IncrementalHash (Phase 1)
    ///     → FSSEngine.Encode (Phase 2)
    ///     → Fss6Etn.InjectCrossValidation (Phase 3)
    ///     → FssRepairService.Generate61/62 (Phase 3)
    ///     → FragmentFileHeader.EncryptWithEmbeddedIndex (Phase 4)
    ///     → DssaAdapter.WriteFragmentAsync (Phase 4)
    ///     → EncryptionLayer.EncryptIndexWithKey/SaltPrefix (Phase 5)
    ///     → DssaAdapter.WriteIndexAsync / WriteRcAsync (Phase 5)
    ///     → MetadataManager.SaveBackup
    /// </summary>
    private async Task<string> BackupCoreAsync(
        string filePath,
        string fssStrategy,
        List<string>? auxiliaryStrategies,
        string? originalFilename,
        int fragmentSize,
        string? customName,
        IProgress<RdrfProgressReport>? progress,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var fileInfo = new FileInfo(filePath);
        string filename = originalFilename ?? fileInfo.Name;
        long fileSize = fileInfo.Length;

        const long maxFileSize = 4L * 1024 * 1024 * 1024; // 4 GB
        if (fileSize > maxFileSize)
            throw new InvalidOperationException($"File too large ({fileSize:N0} bytes). Maximum supported size is {maxFileSize:N0} bytes.");

        Debug.WriteLine($"Backing up: {filename} ({fileSize:N0} bytes)");

        int fragSize = fragmentSize > 0 ? fragmentSize : 1024 * 1024;
        var compressionMethod = Constants.CompressionLz4;
        string originalHash;
        string fileFingerprint;

        // Multi-strategy (auxiliary) temporarily disabled; single-strategy only.
        var plan = _fsa.Compute(fssStrategy, null);

        // Phase 1: Stream file → hash → split raw → LZ4 per block → pad
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, 65536, FileOptions.SequentialScan);
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var rawFragments = new List<byte[]>();
        var originalFragments = new List<byte[]>();
        var originalFragmentSizes = new List<int>();
        long totalRead = 0;
        long nextReport = 0;
        var fragBuf = new byte[fragSize];
        int fragOff = 0;

        int bytesRead;
        while ((bytesRead = await fs.ReadAsync(fragBuf.AsMemory(fragOff, fragSize - fragOff), cancellationToken).ConfigureAwait(false)) > 0)
        {
            hasher.AppendData(fragBuf.AsSpan(fragOff, bytesRead));
            fragOff += bytesRead;
            totalRead += bytesRead;

            if (totalRead >= nextReport)
            {
                progress?.Report(new RdrfProgressReport { Stage = "Read", CurrentBytes = totalRead, TotalBytes = fileSize });
                nextReport = totalRead + Math.Max(65536, fileSize / 100);
            }

            if (fragOff < fragSize)
                continue;

            byte[] raw = new byte[fragSize];
            Buffer.BlockCopy(fragBuf, 0, raw, 0, fragSize);
            rawFragments.Add(raw);
            byte[] compressed = Compressor.AlwaysCompress(raw);
            byte[] stored = compressed.Length < raw.Length ? compressed : raw;
            originalFragmentSizes.Add(stored.Length);
            byte[] padded = new byte[fragSize];
            Buffer.BlockCopy(stored, 0, padded, 0, Math.Min(stored.Length, fragSize));
            originalFragments.Add(padded);
            fragOff = 0;
        }

        // Last partial fragment
        if (fragOff > 0)
        {
            byte[] raw = new byte[fragOff];
            Buffer.BlockCopy(fragBuf, 0, raw, 0, fragOff);
            rawFragments.Add(raw);
            byte[] compressed = Compressor.AlwaysCompress(raw);
            byte[] stored = compressed.Length < raw.Length ? compressed : raw;
            originalFragmentSizes.Add(stored.Length);
            byte[] padded = new byte[fragSize];
            Buffer.BlockCopy(stored, 0, padded, 0, Math.Min(stored.Length, fragSize));
            originalFragments.Add(padded);
        }

        fileFingerprint = Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
        originalHash = fileFingerprint;

        int originalFragmentCount = rawFragments.Count;
        var rawHashes = rawFragments.Select(f => XxHash128.Hash(f.AsSpan())).ToList();

        progress?.Report(new RdrfProgressReport { Stage = "Read", CurrentBytes = fileSize, TotalBytes = fileSize,
            CurrentItem = originalFragmentCount, TotalItems = originalFragmentCount });

        Debug.WriteLine($"  Phase 1: Read {fileSize:N0} bytes, {originalFragmentCount} raw fragments, each LZ4→padded to {fragSize}");

        // Phase 2: FSS encode all fragments
        var fragments = new List<byte[]>(originalFragments);
        foreach (var step in plan.EncodeSteps)
        {
            if (step.Step == "encode")
            {
                fragments = _fss.Encode(fragments, step.Strategy);
                Debug.WriteLine($"  Step 2: Encode ({step.Strategy}): {fragments.Count} fragments");
            }
            else if (step.Step == "etn_inject")
            {
                fragments = _fss.Encode(fragments, Constants.FssLevel6);
                Debug.WriteLine($"  Step 2: ETN inject: {fragments.Count} fragments");
            }
        }

        progress?.Report(new RdrfProgressReport { Stage = "Encode", CurrentItem = fragments.Count, TotalItems = fragments.Count });

        string filePrefix = customName ?? fileFingerprint;

        var fragmentHashes = new string[fragments.Count];
        await Parallel.ForEachAsync(Enumerable.Range(0, fragments.Count),
            new ParallelOptions { CancellationToken = cancellationToken }, (i, ct) =>
        {
            fragmentHashes[i] = IntegrityChecker.HashBytes(fragments[i]);
            return ValueTask.CompletedTask;
        }).ConfigureAwait(false);

        var embeddedIndex = IndexManager.BuildIndex(
            fileFingerprint: fileFingerprint,
            originalFilename: filename,
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
            embeddedIndex.CustomName = customName;
        if (_salt.Length > 0)
            embeddedIndex.Salt = Convert.ToHexString(_salt).ToLowerInvariant();
        embeddedIndex.Compression = compressionMethod;

        // RawFragmentHashes = XxHash128 of UNCOMPRESSED data (content-addressable dedup key)
        embeddedIndex.RawFragmentHashes = rawHashes;

        byte[] serializedIndex = IndexManager.SerializeIndex(embeddedIndex);
        byte[] rcBytes = [];

        bool hasFss6 = plan.ActiveStrategies.Contains(Constants.FssLevel6)
                     || plan.ActiveStrategies.Contains(Constants.FssLevel61)
                     || plan.ActiveStrategies.Contains(Constants.FssLevel62);
        bool hasFss61 = plan.ActiveStrategies.Contains(Constants.FssLevel61);
        bool hasFss62 = plan.ActiveStrategies.Contains(Constants.FssLevel62);
        if (hasFss6)
        {
            var (etnFragments, etnIndexJson, etnRcJson) = Fss6Etn.InjectCrossValidation(
                fragments, serializedIndex, filePrefix, fileSize, plan.EffectivePrimary);
            fragments = etnFragments;
            serializedIndex = etnIndexJson;
            rcBytes = etnRcJson;
        }

        // FSS6.1: three-node independent LT repair generation
        if (hasFss61 && rcBytes.Length > 0)
        {
            try
            {
                int bs = EtnBlockMap.GetBlockSize(fileSize, plan.EffectivePrimary);
                var (repairA, repairB, repairC) = FssRepairService.Generate61(
                    serializedIndex, fragments, rcBytes, bs);

                var rcFile61 = RcFile.FromCbor(rcBytes);
                var indexObj61 = IndexManager.DeserializeIndex(serializedIndex);
                if (repairA != null) rcFile61.RepairA = repairA;
                if (repairB != null) { rcFile61.RepairB = repairB; indexObj61.Fss61RepairB = repairB; }
                if (repairC != null) indexObj61.Fss61RepairC = repairC;

                string fp61 = filePrefix ?? fileFingerprint;
                FssRepairService.Append61Trailers(fragments, fp61, repairA, repairC);

                rcBytes = rcFile61.ToCborBytes();
                serializedIndex = IndexManager.SerializeIndex(indexObj61);
            }
            catch (Exception ex) { Console.Error.WriteLine($"Warning: FSS6.1 repair generation failed — {ex.Message}"); }
        }

        // FSS6.2: three-node independent Duip repair generation
        if (hasFss62 && rcBytes.Length > 0)
        {
            try
            {
                int bs = EtnBlockMap.GetBlockSize(fileSize, plan.EffectivePrimary);
                var (repair62A, repair62B, repair62C) = FssRepairService.Generate62(
                    serializedIndex, fragments, rcBytes, bs);

                var rcFile62 = RcFile.FromCbor(rcBytes);
                var indexObj62 = IndexManager.DeserializeIndex(serializedIndex);
                if (repair62A != null) rcFile62.Repair62A = repair62A;
                if (repair62B != null) { rcFile62.Repair62B = repair62B; indexObj62.Fss62RepairB = repair62B; }
                if (repair62C != null) indexObj62.Fss62RepairC = repair62C;

                string fp62 = filePrefix ?? fileFingerprint;
                FssRepairService.Append62Trailers(fragments, fp62, repair62A, repair62C);

                rcBytes = rcFile62.ToCborBytes();
                serializedIndex = IndexManager.SerializeIndex(indexObj62);
            }
            catch (Exception ex) { Console.Error.WriteLine($"Warning: FSS6.2 repair generation failed — {ex.Message}"); }
        }

        // Strip BM fields from the Index before embedding in fragment headers
        // to save ~20KB/fragment. The standalone Index file retains full BM data.
        byte[] embeddedIndexBytes = Fss6Etn.StripEtnFieldsFromIndexJson(serializedIndex);

        long totalBytes = fragments.Sum(f => f.Length);

        // Phase 3: Batch encrypt + write (8 fragments per batch)
        const int BatchSize = 8;
        var writeBatch = new List<(string path, byte[] data)>(BatchSize);

        for (int i = 0; i < fragments.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            byte[] fileData = FragmentFileHeader.EncryptWithEmbeddedIndex(
                fragments[i], embeddedIndexBytes, _aesKey, _salt.Length > 0 ? _salt : null);
            string fname = Frags.FragmentFilename(filePrefix, i);
            writeBatch.Add((fname, fileData));
            fragments[i] = null!;

            progress?.Report(new RdrfProgressReport { Stage = "Write", CurrentItem = i + 1, TotalItems = fragments.Count });

            if (writeBatch.Count >= BatchSize)
            {
                await Parallel.ForEachAsync(writeBatch, new ParallelOptions
                {
                    MaxDegreeOfParallelism = Constants.DefaultParallelism,
                    CancellationToken = cancellationToken
                }, async (item, ct) =>
                {
                    for (int retry = 0; ; retry++)
                        try { await _storage.WriteFragmentAsync(item.path, item.data, ct).ConfigureAwait(false); break; }
                        catch when (retry < 2) { await Task.Delay(100 * (retry + 1), ct).ConfigureAwait(false); }
                }).ConfigureAwait(false);
                writeBatch.Clear();
            }
        }

        // Flush remaining
        if (writeBatch.Count > 0)
        {
            await Parallel.ForEachAsync(writeBatch, new ParallelOptions
            {
                MaxDegreeOfParallelism = Constants.DefaultParallelism,
                CancellationToken = cancellationToken
            }, async (item, ct) =>
            {
                await _storage.WriteFragmentAsync(item.path, item.data, ct).ConfigureAwait(false);
            }).ConfigureAwait(false);
            writeBatch.Clear();
        }

        byte[] indexBytes = serializedIndex;
        if (_salt.Length > 0)
        {
                byte[] salted = EncryptionLayer.EncryptIndexWithSaltPrefix(indexBytes, _rcCode, _salt);
            await _storage.WriteIndexAsync(filePrefix, salted, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            byte[] encryptedIndex = EncryptionLayer.EncryptIndexWithKey(indexBytes, _aesKey);
            await _storage.WriteIndexAsync(filePrefix, encryptedIndex, cancellationToken).ConfigureAwait(false);
        }

        if (rcBytes.Length > 0)
        {
            byte[] encryptedRc = EncryptionLayer.EncryptFragmentWithKey(rcBytes, _aesKey);
            await _storage.WriteRcAsync(filePrefix, encryptedRc, cancellationToken).ConfigureAwait(false);
        }

        _metadata.SaveBackup(
            fileFingerprint: fileFingerprint,
            originalFilename: filename,
            originalSize: fileSize,
            originalHash: originalHash,
            fssStrategy: fssStrategy,
            fragmentHashes: fragmentHashes.ToList());

        Debug.WriteLine($"Backup complete!");
        return fileFingerprint;
    }

    /// <summary>
    /// Builds a complete index for changed fragments during an incremental
    /// (versioned) backup. Only fragments that differ from the previous version
    /// are written; unchanged fragments reference the previous version's data
    /// via SourceVersion.
    ///
    /// Pipeline (subset of BackupCoreAsync):
    ///   FSA plan → FSS encode → ETN inject → FSS6.1 repair → embed in headers
    ///   → Encrypt & write changed fragments → Write Index → Write RC
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
        string? compressionMethod = null)
    {
        int fragSize = fragmentSize > 0 ? fragmentSize : 1024 * 1024;
        string filePrefix = customName ?? fileFingerprint;
        var plan = _fsa.Compute(fssStrategy, null);

        var fragments = new List<byte[]>(allRawFragments);
        foreach (var step in plan.EncodeSteps)
        {
            if (step.Step == "encode")
                fragments = _fss.Encode(fragments, step.Strategy);
            else if (step.Step == "etn_inject")
                fragments = _fss.Encode(fragments, Constants.FssLevel6);
        }

        var fragmentHashes = new List<string>(fragments.Count);
        foreach (var f in fragments)
            fragmentHashes.Add(IntegrityChecker.HashBytes(f));

        int originalFragmentCount = allRawFragments.Count;
        var originalFragmentSizes = allRawFragments.Select(f => f.Length).ToList();

        var index = IndexManager.BuildIndex(
            fileFingerprint: fileFingerprint,
            originalFilename: originalFilename,
            originalSize: fileSize,
            fragmentHashes: fragmentHashes,
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
            index.Salt = Convert.ToHexString(_salt).ToLowerInvariant();

        if (compressionMethod != null)
            index.Compression = compressionMethod;

        index.RawFragmentHashes = allRawFragments
            .Select(f => System.IO.Hashing.XxHash128.Hash(f.AsSpan()))
            .ToList();

        byte[] serializedIndex = IndexManager.SerializeIndex(index);
        byte[] rcBytes = [];

        bool hasFss6 = plan.ActiveStrategies.Contains(Constants.FssLevel6)
                     || plan.ActiveStrategies.Contains(Constants.FssLevel61);
        bool hasFss61 = plan.ActiveStrategies.Contains(Constants.FssLevel61);
        if (hasFss6)
        {
            var (etnFragments, etnIndexJson, etnRcJson) = Fss6Etn.InjectCrossValidation(
                fragments, serializedIndex, filePrefix, fileSize, plan.EffectivePrimary);
            fragments = etnFragments;
            serializedIndex = etnIndexJson;
            rcBytes = etnRcJson;
        }

        if (hasFss61 && rcBytes.Length > 0)
        {
            try
            {
                int bs = EtnBlockMap.GetBlockSize(fileSize, plan.EffectivePrimary);
                var (repairA, repairB, repairC) = FssRepairService.Generate61(
                    serializedIndex, fragments, rcBytes, bs);

                var rcFile61 = RcFile.FromCbor(rcBytes);
                var indexObj61 = IndexManager.DeserializeIndex(serializedIndex);
                if (repairA != null) rcFile61.RepairA = repairA;
                if (repairB != null) { rcFile61.RepairB = repairB; indexObj61.Fss61RepairB = repairB; }
                if (repairC != null) indexObj61.Fss61RepairC = repairC;

                FssRepairService.Append61Trailers(fragments, filePrefix, repairA, repairC);

                rcBytes = rcFile61.ToCborBytes();
                serializedIndex = IndexManager.SerializeIndex(indexObj61);
            }
            catch (Exception ex) { Debug.WriteLine($"FSS6.1 repair generation failed: {ex.Message}"); }
        }

        byte[] embeddedIndexBytes = Fss6Etn.StripEtnFieldsFromIndexJson(serializedIndex);
        long totalBytes = fragments.Sum(f => f.Length);
        long processedBytes = 0;

        // Initialize all fragments with SourceVersion references
        if (index.Fragments != null)
        {
            for (int i = 0; i < index.Fragments.Count; i++)
            {
                if (i < changedFlags.Length && !changedFlags[i] && prevFingerprint != null)
                    index.Fragments[i].SourceVersion = prevFingerprint;
            }
        }

        for (int i = 0; i < fragments.Count; i++)
        {
            ct.ThrowIfCancellationRequested();

            // Skip write for unchanged fragments (they reference prev version)
            if (index.Fragments?.Count > i && index.Fragments[i].SourceVersion != null)
            {
                processedBytes += fragments[i].Length;
                continue;
            }

            byte[] fileData = FragmentFileHeader.EncryptWithEmbeddedIndex(
                fragments[i], embeddedIndexBytes, _aesKey, _salt);
            string fname = Frags.FragmentFilename(filePrefix, i);
            int rawLen = fragments[i].Length;
            await _storage.WriteFragmentAsync(fname, fileData, ct).ConfigureAwait(false);
            fragments[i] = null!;
            processedBytes += rawLen;

            progress?.Report(new RdrfProgressReport
            {
                Stage = "Encrypting",
                CurrentItem = i + 1,
                TotalItems = fragments.Count,
                CurrentBytes = processedBytes,
                TotalBytes = totalBytes
            });
        }

        var standaloneIndex = IndexManager.DeserializeIndex(serializedIndex);
        standaloneIndex.FssParams = new Dictionary<string, object>
        {
            ["plan"] = JsonSerializer.SerializeToElement(plan)
        };
        // Apply SourceVersion to the standalone index too
        if (standaloneIndex.Fragments != null && index.Fragments != null)
        {
            for (int i = 0; i < Math.Min(standaloneIndex.Fragments.Count, index.Fragments.Count); i++)
                standaloneIndex.Fragments[i].SourceVersion = index.Fragments[i].SourceVersion;
        }

        byte[] indexBytes = IndexManager.SerializeIndex(standaloneIndex);
        if (_salt.Length > 0)
        {
            byte[] salted = EncryptionLayer.EncryptIndexWithSaltPrefix(indexBytes, _rcCode, _salt);
            await _storage.WriteIndexAsync(filePrefix, salted, ct).ConfigureAwait(false);
        }
        else
        {
            byte[] encryptedIndex = EncryptionLayer.EncryptIndexWithKey(indexBytes, _aesKey);
            await _storage.WriteIndexAsync(filePrefix, encryptedIndex, ct).ConfigureAwait(false);
        }

        if (rcBytes.Length > 0)
        {
            byte[] encryptedRc = EncryptionLayer.EncryptFragmentWithKey(rcBytes, _aesKey);
            await _storage.WriteRcAsync(filePrefix, encryptedRc, ct).ConfigureAwait(false);
        }

        _metadata.SaveBackup(
            fileFingerprint: fileFingerprint,
            originalFilename: originalFilename,
            originalSize: fileSize,
            originalHash: originalHash,
            fssStrategy: fssStrategy,
            fragmentHashes: fragmentHashes);

        return index;
    }

    /// <summary>
    /// Zeroes all sensitive key material from memory and disposes
    /// the metadata manager. Suppresses finalization.
    /// </summary>
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
