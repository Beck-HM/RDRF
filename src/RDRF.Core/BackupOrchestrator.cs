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
    private readonly StorageAdapter _storage;
    private readonly FSSEngine _fss;
    private readonly FsaEngine _fsa;
    private readonly MetadataManager _metadata;
    private readonly bool _preDerived;

    public BackupOrchestrator(
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
        StorageAdapter storage,
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
        var originalFragments = new List<byte[]>();
        string originalHash;
        string fileFingerprint;

        using (var fs = new FileStream(fileInfo.FullName, FileMode.Open, FileAccess.Read,
            FileShare.Read, 65536, FileOptions.SequentialScan))
        using (var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            byte[] buf = new byte[fragSize];
            int read;
            while ((read = fs.Read(buf, 0, fragSize)) > 0)
            {
                hasher.AppendData(buf.AsSpan(0, read));
                if (read == fragSize)
                {
                    originalFragments.Add(buf);
                    buf = new byte[fragSize];
                }
                else
                {
                    var last = new byte[read];
                    Buffer.BlockCopy(buf, 0, last, 0, read);
                    originalFragments.Add(last);
                }
            }
            byte[] hashBytes = hasher.GetHashAndReset();
            fileFingerprint = Convert.ToHexString(hashBytes).ToLowerInvariant();
            originalHash = fileFingerprint;
        }

        int originalFragentCount = originalFragments.Count;
        var originalFragentSizes = originalFragments.Select(f => f.Length).ToList();

        Debug.WriteLine($"  Step 1: Split into {originalFragentCount} fragments");

        var plan = _fsa.Compute(fssStrategy, auxiliaryStrategies);
        var fragments = new List<byte[]>(originalFragments);

        foreach (var step in plan.EncodeSteps)
        {
            if (step.Step == "encode")
            {
                fragments = _fss.Encode(fragments, step.Strategy);
                Debug.WriteLine($"  Step 3a: Encode ({step.Strategy}): {fragments.Count} fragments");
            }
            else if (step.Step == "etn_inject")
            {
                fragments = _fss.Encode(fragments, Constants.FssLevel6);
                Debug.WriteLine($"  Step 3b: ETN inject: {fragments.Count} fragments");
            }
        }

        string filePrefix = customName ?? fileFingerprint;

        var fragmentHashes = new List<string>(fragments.Count);
        for (int i = 0; i < fragments.Count; i++)
        {
            if ((i & 3) == 0) cancellationToken.ThrowIfCancellationRequested();
            fragmentHashes.Add(IntegrityChecker.HashBytes(fragments[i]));
        }

        var nonces = new List<string>(fragments.Count);
        for (int i = 0; i < fragments.Count; i++)
        {
            byte[] n = RandomNumberGenerator.GetBytes(Constants.NonceLength);
            nonces.Add(Convert.ToBase64String(n));
        }

        var embeddedIndex = IndexManager.BuildIndex(
            fileFingerprint: fileFingerprint,
            originalFilename: filename,
            originalSize: fileSize,
            fragmentHashes: fragmentHashes,
            fragmentNonces: nonces,
            originalHash: originalHash,
            fssStrategy: plan.EffectivePrimary,
            originalFragentSizes: originalFragentSizes,
            originalFragentCount: originalFragentCount,
            fssParams: new Dictionary<string, object>
            {
                ["plan"] = JsonSerializer.SerializeToElement(plan)
            });

        if (!string.IsNullOrEmpty(customName))
            embeddedIndex.CustomName = customName;
        if (_salt.Length > 0)
            embeddedIndex.Salt = Convert.ToHexString(_salt).ToLowerInvariant();

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

        // FSS6.1: generate LT repair symbols from fragments and embed in RC file
        if (hasFss61 && rcBytes.Length > 0)
        {
            try
            {
                var rcFile = RcFile.FromCbor(rcBytes);
                int blockCount = 0;
                foreach (var fm in rcFile.FragentBlockMaps)
                    blockCount += fm.Count;

                if (blockCount > 0)
                {
                    int bs = EtnBlockMap.GetBlockSize(fileSize, plan.EffectivePrimary);
                    int repairCount = Math.Max(1, blockCount / 20); // 5% repair symbols
                    var allBlocks = new List<byte[]>();
                    foreach (var frag in fragments)
                    {
                        var (rawData, _, _, _, _, _, _) = EtnTrailer.Parse(frag);

                        for (int off = 0; off < rawData.Length; off += bs)
                        {
                            int len = Math.Min(bs, rawData.Length - off);
                            byte[] block = new byte[bs];
                            Buffer.BlockCopy(rawData, off, block, 0, len);
                            allBlocks.Add(block);
                        }
                    }

                    if (allBlocks.Count >= blockCount)
                    {
                        var (symbols, seed) = LtCode.Encode(allBlocks.ToArray(), repairCount, bs);
                        var repairData = new byte[symbols.Count * bs];
                        for (int i = 0; i < symbols.Count; i++)
                            Buffer.BlockCopy(symbols[i], 0, repairData, i * bs, bs);

                        rcFile.RepairSeed = seed;
                        rcFile.RepairCount = symbols.Count;
                        rcFile.RepairBlockSize = bs;
                        rcFile.RepairData = repairData;
                        rcBytes = rcFile.ToCborBytes();
                    }
                }
            }
            catch { /* LT generation failed silently — proceed without repair data */ }
        }

        // Strip BM fields from the Index before embedding in fragment headers
        // to save ~20KB/fragment. The standalone Index file retains full BM data.
        byte[] embeddedIndexBytes = Fss6Etn.StripEtnFieldsFromIndexJson(serializedIndex);

        long totalBytes = fragments.Sum(f => f.Length);
        long processedBytes = 0;

        for (int i = 0; i < fragments.Count; i++)
        {
            if ((i & 3) == 0) cancellationToken.ThrowIfCancellationRequested();

            byte[] fileData = FragmentFileHeader.EncryptWithEmbeddedIndex(
                fragments[i], embeddedIndexBytes, _aesKey, _preDerived ? null : _salt);

            string fname = Frags.FragentFilename(filePrefix, i);
            int rawLen = fragments[i].Length;
            await _storage.WriteFragmentAsync(fname, fileData, cancellationToken).ConfigureAwait(false);
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
            fragmentHashes: fragmentHashes);

        Debug.WriteLine($"Backup complete!");
        return fileFingerprint;
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
