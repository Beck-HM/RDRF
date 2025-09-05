using System.Buffers;
using System.Diagnostics;
using System.Threading.Channels;
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

public class RdrfProgressReport
{
    public string Stage { get; set; } = string.Empty;
    public int CurrentItem { get; set; }
    public int TotalItems { get; set; }
    public long CurrentBytes { get; set; }
    public long TotalBytes { get; set; }
}

public class BackupOrchestrator : IDisposable
{
    private readonly byte[] _rcCode;
    private readonly byte[] _aesKey;
    private readonly byte[] _salt;
    private readonly DssaAdapter _storage;
    private readonly FSSEngine _fss;
    private readonly FsaEngine _fsa;
    private readonly MetadataManager _metadata;
    private readonly bool _preDerived;

    public BackupOrchestrator(
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
        _fsa = new FsaEngine();
        _metadata = MetadataManager.Default;
        _preDerived = preDerived;

        if (preDerived)
        {
            _rcCode = recoveryCode?.Clone() as byte[] ?? [];
            _salt = _rcCode.Length > 0 ? RandomNumberGenerator.GetBytes(32) : [];
            _aesKey = key?.Clone() as byte[] ?? throw new ArgumentNullException(nameof(key));
        }
        else
        {
            _rcCode = key?.Clone() as byte[] ?? throw new ArgumentNullException(nameof(key));
            _salt = RandomNumberGenerator.GetBytes(32);
            _aesKey = EncryptionLayer.DeriveKey(key, _salt);
        }
    }

    public BackupOrchestrator(
        byte[] key,
        byte[] salt,
        DssaAdapter storage,
        FSSEngine? fssEngine = null)
    {
        _rcCode = key?.Clone() as byte[] ?? throw new ArgumentNullException(nameof(key));
        _salt = salt ?? throw new ArgumentNullException(nameof(salt));
        _aesKey = EncryptionLayer.DeriveKey(key, _salt);
        _storage = storage ?? throw new ArgumentNullException(nameof(storage));
        _fss = fssEngine ?? new FSSEngine();
        _fsa = new FsaEngine();
        _metadata = MetadataManager.Default;
        _preDerived = false;
    }

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
        return BackupCoreAsync(filePath, fssStrategy, auxiliaryStrategies, originalFilename, fragmentSize, customName, progress, CancellationToken.None).GetAwaiter().GetResult();
    }

    public string BackupFile(
        FileInfo filePath,
        string fssStrategy = "FSS1",
        List<string>? auxiliary = null,
        int fragmentSize = 0,
        string? customName = null,
        IProgress<RdrfProgressReport>? progress = null)
        => BackupFile(filePath.FullName, fssStrategy, auxiliary, fragmentSize: fragmentSize, customName: customName, progress: progress);

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

    public Task<string> BackupFileAsync(
        FileInfo filePath,
        string fssStrategy = "FSS1",
        List<string>? auxiliary = null,
        int fragmentSize = 0,
        string? customName = null,
        IProgress<RdrfProgressReport>? progress = null,
        CancellationToken cancellationToken = default)
        => BackupFileAsync(filePath.FullName, fssStrategy, auxiliary, fragmentSize: fragmentSize, customName: customName, progress: progress, cancellationToken: cancellationToken);

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

        Debug.WriteLine($"Backing up: {filename} ({fileSize:N0} bytes)");

        int fragSize = fragmentSize > 0 ? fragmentSize : 1024 * 1024;
        var compressionMethod = Constants.CompressionLz4;
        string originalHash;
        string fileFingerprint;

        // Phase 1: Async read + compress pipeline via Channel
        var rawChannel = Channel.CreateBounded<byte[]>(4);
        var plan = _fsa.Compute(fssStrategy, auxiliaryStrategies);

        // Producer: read + hash + compress per fragment, returns SHA256
        var hashTask = Task.Run(async () =>
        {
            byte[] readBuf = ArrayPool<byte>.Shared.Rent(fragSize);
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                    FileShare.Read, 65536, FileOptions.SequentialScan);
                using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

                int read;
                while ((read = await fs.ReadAsync(readBuf, 0, fragSize).ConfigureAwait(false)) > 0)
                {
                    hasher.AppendData(readBuf.AsSpan(0, read));
                    var fragData = readBuf.AsSpan(0, read).ToArray();
                    byte[] compressed = RDRF.Core.Compression.Compressor
                        .Compress(fragData, compressionMethod);
                    await rawChannel.Writer.WriteAsync(compressed).ConfigureAwait(false);
                }
                rawChannel.Writer.Complete();

                byte[] hashBytes = hasher.GetHashAndReset();
                return Convert.ToHexString(hashBytes).ToLowerInvariant();
            }
            finally { ArrayPool<byte>.Shared.Return(readBuf); }
        });

        // Consumer: collect compressed fragments
        var originalFragments = new List<byte[]>();
        await foreach (var frag in rawChannel.Reader.ReadAllAsync().ConfigureAwait(false))
            originalFragments.Add(frag);

        fileFingerprint = await hashTask.ConfigureAwait(false);
        originalHash = fileFingerprint;

        int originalFragmentCount = originalFragments.Count;
        var originalFragmentSizes = originalFragments.Select(f => f.Length).ToList();

        Debug.WriteLine($"  Step 1: Streamed {fileSize:N0} bytes -> {originalFragmentCount} fragments");

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

        string filePrefix = customName ?? fileFingerprint;

        var fragmentHashes = new string[fragments.Count];
        var nonces = new string[fragments.Count];
        Parallel.For(0, fragments.Count, i =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            fragmentHashes[i] = IntegrityChecker.HashBytes(fragments[i]);
            nonces[i] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(Constants.NonceLength));
        });

        var embeddedIndex = IndexManager.BuildIndex(
            fileFingerprint: fileFingerprint,
            originalFilename: filename,
            originalSize: fileSize,
            fragmentHashes: fragmentHashes.ToList(),
            fragmentNonces: nonces.ToList(),
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

        // Compute raw fragment XxHash128 for incremental comparison (before FSS encoding)
        var rawHashes = new List<byte[]>(originalFragments.Count);
        foreach (var frag in originalFragments)
            rawHashes.Add(XxHash128.Hash(frag.AsSpan()));
        embeddedIndex.RawFragmentHashes = rawHashes;

        byte[] serializedIndex = IndexManager.SerializeIndex(embeddedIndex);
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

        // FSS6.1: three-node independent LT repair generation
        if (hasFss61 && rcBytes.Length > 0)
        {
            try
            {
                var rcFile = RcFile.FromCbor(rcBytes);
                var indexObj = IndexManager.DeserializeIndex(serializedIndex);
                int bs = EtnBlockMap.GetBlockSize(fileSize, plan.EffectivePrimary);

                // A/B/C: parallel FSS6.1 three-node repair generation
                var taskA = Task.Run(() =>
                {
                    var ib = SplitToBlocks(serializedIndex, bs);
                    if (ib.Length > 0)
                    {
                        var (sym, seed) = LtCode.Encode(ib, ib.Length, bs);
                        return new Fss61RepairData
                        {
                            Seed = seed, BlockCount = ib.Length, BlockSize = bs,
                            Data = FlattenSymbols(sym, bs),
                        };
                    }
                    return null;
                });

                var taskB = Task.Run(() =>
                {
                    var fb = new List<byte[]>();
                    foreach (var frag in fragments)
                    {
                        var (rawData, _, _, _, _, _, _) = EtnTrailer.Parse(frag);
                        for (int off = 0; off < rawData.Length; off += bs)
                        {
                            int len = Math.Min(bs, rawData.Length - off);
                            byte[] blk = new byte[bs];
                            Buffer.BlockCopy(rawData, off, blk, 0, len);
                            fb.Add(blk);
                        }
                    }
                    if (fb.Count > 0)
                    {
                        var allFrags = fb.ToArray();
                        var (sym, seed) = LtCode.Encode(allFrags, allFrags.Length, bs);
                        return new Fss61RepairData
                        {
                            Seed = seed, BlockCount = allFrags.Length, BlockSize = bs,
                            Data = FlattenSymbols(sym, bs),
                        };
                    }
                    return null;
                });

                var taskC = Task.Run(() =>
                {
                    var rb = SplitToBlocks(rcBytes, bs);
                    if (rb.Length > 0)
                    {
                        var (sym, seed) = LtCode.Encode(rb, rb.Length, bs);
                        return new Fss61RepairData
                        {
                            Seed = seed, BlockCount = rb.Length, BlockSize = bs,
                            Data = FlattenSymbols(sym, bs),
                        };
                    }
                    return null;
                });

                var repairA = await taskA.ConfigureAwait(false);
                var repairB = await taskB.ConfigureAwait(false);
                var repairC = await taskC.ConfigureAwait(false);

                if (repairA != null) rcFile.RepairA = repairA;
                if (repairB != null) { rcFile.RepairB = repairB; indexObj.Fss61RepairB = repairB; }
                if (repairC != null) indexObj.Fss61RepairC = repairC;

                // D: replace trailers (depends on A + C)
                if (repairA != null && repairC != null)
                {
                    string fp = filePrefix ?? fileFingerprint;
                    for (int i = 0; i < fragments.Count; i++)
                    {
                        var (rawData, _, _, _, _, _, _) = EtnTrailer.Parse(fragments[i]);
                        fragments[i] = Fss61RepairTrailer.Build(rawData, fp, fp, repairA, repairC);
                    }
                }

                rcBytes = rcFile.ToCborBytes();
                serializedIndex = IndexManager.SerializeIndex(indexObj);
            }
            catch (Exception ex) { Debug.WriteLine($"FSS6.1 triple repair generation failed: {ex.Message}"); }
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
                fragments[i], embeddedIndexBytes, _aesKey, _preDerived ? null : _salt);
            string fname = Frags.FragmentFilename(filePrefix, i);
            writeBatch.Add((fname, fileData));
            fragments[i] = null!;

            if (writeBatch.Count >= BatchSize)
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

        // Reuse the serialized index as the standalone index (avoids a second BuildIndex)
        var standaloneIndex = IndexManager.DeserializeIndex(serializedIndex);
        standaloneIndex.FssParams = new Dictionary<string, object>
        {
            ["plan"] = JsonSerializer.SerializeToElement(plan)
        };

        byte[] indexBytes = IndexManager.SerializeIndex(standaloneIndex);
        if (!_preDerived && _salt.Length > 0)
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
        CancellationToken ct)
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
            fragmentNonces: Enumerable.Range(0, fragments.Count)
                .Select(_ => Convert.ToBase64String(RandomNumberGenerator.GetBytes(Constants.NonceLength)))
                .ToList(),
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
                var rcFile = RcFile.FromCbor(rcBytes);
                var indexObj = IndexManager.DeserializeIndex(serializedIndex);
                int bs = EtnBlockMap.GetBlockSize(fileSize, plan.EffectivePrimary);

                var indexBlocks = SplitToBlocks(serializedIndex, bs);
                if (indexBlocks.Length > 0)
                {
                    var (sym, seed) = LtCode.Encode(indexBlocks, indexBlocks.Length, bs);
                    rcFile.RepairA = new Fss61RepairData
                    {
                        Seed = seed, BlockCount = indexBlocks.Length, BlockSize = bs,
                        Data = FlattenSymbols(sym, bs),
                    };
                }

                var fragBlocks = new List<byte[]>();
                foreach (var frag in fragments)
                {
                    var (rawData, _, _, _, _, _, _) = EtnTrailer.Parse(frag);
                    for (int off = 0; off < rawData.Length; off += bs)
                    {
                        int len = Math.Min(bs, rawData.Length - off);
                        byte[] block = new byte[bs];
                        Buffer.BlockCopy(rawData, off, block, 0, len);
                        fragBlocks.Add(block);
                    }
                }
                if (fragBlocks.Count > 0)
                {
                    var allFrags = fragBlocks.ToArray();
                    var (sym, seed) = LtCode.Encode(allFrags, allFrags.Length, bs);
                    rcFile.RepairB = new Fss61RepairData
                    {
                        Seed = seed, BlockCount = allFrags.Length, BlockSize = bs,
                        Data = FlattenSymbols(sym, bs),
                    };
                    indexObj.Fss61RepairB = rcFile.RepairB;
                }

                var rcBlocks = SplitToBlocks(rcBytes, bs);
                if (rcBlocks.Length > 0)
                {
                    var (sym, seed) = LtCode.Encode(rcBlocks, rcBlocks.Length, bs);
                    indexObj.Fss61RepairC = new Fss61RepairData
                    {
                        Seed = seed, BlockCount = rcBlocks.Length, BlockSize = bs,
                        Data = FlattenSymbols(sym, bs),
                    };
                }

                if (rcFile.RepairA != null && indexObj.Fss61RepairC != null)
                {
                    for (int i = 0; i < fragments.Count; i++)
                    {
                        var (rawData, _, _, _, _, _, _) = EtnTrailer.Parse(fragments[i]);
                        fragments[i] = Fss61RepairTrailer.Build(rawData, filePrefix, filePrefix,
                            rcFile.RepairA, indexObj.Fss61RepairC);
                    }
                }

                rcBytes = rcFile.ToCborBytes();
                serializedIndex = IndexManager.SerializeIndex(indexObj);
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

    private static byte[] FlattenSymbols(List<byte[]> symbols, int blockSize)
    {
        var data = new byte[symbols.Count * blockSize];
        for (int i = 0; i < symbols.Count; i++)
            Buffer.BlockCopy(symbols[i], 0, data, i * blockSize, blockSize);
        return data;
    }
}
