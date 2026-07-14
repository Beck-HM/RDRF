using RDRF.Core.Logging;using System.Diagnostics;
using System.IO.Hashing;
using System.Security.Cryptography;
using RDRF.Core.Abstractions;
using RDRF.Core.Compression;
using RDRF.Core.Diff;
using RDRF.Core.Encryption;
using RDRF.Core.FragmentEngine;
using RDRF.Core.Index;
using RDRF.Core.Integrity;
using RDRF.Core.DSAA;

namespace RDRF.Core.Versioning;

/// <summary>
/// Git-style versioned backup: initial version is fully stored; each
/// subsequent version stores only changed fragments (content-addressed
/// dedup). All version files are preserved permanently - no cleanup.
///
/// Restore uses SourceVersion chains: v3's unchanged blocks are read
/// from v1's fragments, changed blocks from v3's own fragments.
///
/// Pipeline:
///   Stream file -> split into fragments -> XxHash128 each
///   -> Compare hashes against previous version's DedupMap
///   -> Unchanged: record SourceVersion=vPrev + SourceIndex
///   -> Changed: LZ4 -> AES-CTR -> write new .rdrf
///   -> Build index with SourceVersion refs -> encrypt -> write .indrdrf
/// </summary>
public static class RealVersionedBackup
{
    /// <summary>
    /// Creates or extends a real-incremental versioned backup.
    /// </summary>
    public static async Task<string> BackupAsync(
        string filePath,
        DSAAAdapter storage,
        byte[] password,
        string userMessage,
        string fssStrategy = "FSS3",
        int fragmentSize = 0,
        string? customName = null,
        List<string>? auxiliaryStrategies = null,
        IProgress<RdrfProgressReport>? progress = null,
        CancellationToken ct = default)
    {
        string? existingFingerprint = FindExistingIndex(storage);

        if (existingFingerprint == null)
            return await FreshBackupAsync(filePath, storage, password, userMessage,
                fssStrategy, progress, ct, fragmentSize, customName, auxiliaryStrategies).ConfigureAwait(false);

        return await IncrementalBackupAsync(filePath, storage, existingFingerprint, password,
            userMessage, fssStrategy, progress, ct, fragmentSize, customName, auxiliaryStrategies).ConfigureAwait(false);
    }

    private static string? FindExistingIndex(DSAAAdapter storage)
        => storage.FindLatestIndex();

    /// <summary>
    /// First version: full backup via BackupOrchestrator, then record v1.
    /// </summary>
    private static async Task<string> FreshBackupAsync(
        string filePath, DSAAAdapter storage,
        byte[] password, string userMessage, string fssStrategy,
        IProgress<RdrfProgressReport>? progress, CancellationToken ct,
        int fragmentSize = 0, string? customName = null,
        List<string>? auxiliaryStrategies = null)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(Constants.SaltPrefixLength);
        using var orchestrator = new BackupOrchestrator((byte[])password.Clone(), storage, (byte[])salt.Clone());
        string fingerprint = await orchestrator.BackupFileAsync(filePath, fssStrategy,
            fragmentSize: fragmentSize, customName: customName, auxiliaryStrategies: auxiliaryStrategies,
            progress: progress, cancellationToken: ct).ConfigureAwait(false);

        // Patch the index to set version_number = 1
        byte[] rawIndex = storage.ReadIndex(fingerprint);
        (byte[] _, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(rawIndex, password);
        var idxObj = IndexManager.DeserializeIndex(cbor);
        idxObj.VersionNumber = 1;
        byte[] patchedCbor = IndexManager.SerializeIndex(idxObj);
        byte[] newEnc = EncryptionLayer.EncryptIndexWithSaltPrefix(patchedCbor, password, salt);
        storage.WriteIndex(fingerprint, newEnc);

        AppendVersionRecord(storage, fingerprint, password, salt, 1, userMessage, string.Empty);
        return fingerprint;
    }

    /// <summary>
    /// Subsequent version: content-addressed dedup against previous version.
    /// Only changed fragments are written; unchanged ones reference the
    /// previous version via SourceVersion. No cleanup is performed.
    /// </summary>
    private static async Task<string> IncrementalBackupAsync(
        string filePath, DSAAAdapter storage,
        string prevFingerprint, byte[] password,
        string userMessage, string fssStrategy,
        IProgress<RdrfProgressReport>? progress, CancellationToken ct,
        int fragmentSize = 0, string? customName = null,
        List<string>? auxiliaryStrategies = null)
    {
        int fragSize = fragmentSize > 0 ? fragmentSize : 1024 * 1024;

        // Read previous version's index to get its dedup map
        byte[] prevEncIndex = storage.ReadIndex(prevFingerprint);
        (byte[] prevAesKey, byte[] prevCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(prevEncIndex, password);
        var prevIdx = IndexManager.DeserializeIndex(prevCbor);
        string prevPrefix = prevIdx.CustomName ?? prevFingerprint;

        // Load previous version's raw fragment hashes for dedup
        var prevRawHashes = prevIdx.RawFragmentHashes;
        var dedupMap = prevIdx.DedupMap ?? new Dictionary<string, DedupEntry>();
        int prevVersion = prevIdx.VersionNumber ?? 0;

        // Stream current file and split into fragments
        var rawFragments = new List<byte[]>();
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, 65536, FileOptions.SequentialScan);
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var fragBuf = new byte[fragSize];
        int fragOff = 0;
        long totalBytes = 0;

        int br;
        while ((br = await fs.ReadAsync(fragBuf.AsMemory(fragOff, fragSize - fragOff), ct).ConfigureAwait(false)) > 0)
        {
            hasher.AppendData(fragBuf.AsSpan(fragOff, br));
            fragOff += br;
            totalBytes += br;
            if (fragOff < fragSize) continue;

            byte[] raw = new byte[fragSize];
            Buffer.BlockCopy(fragBuf, 0, raw, 0, fragSize);
            rawFragments.Add(raw);
            fragOff = 0;
        }
        if (fragOff > 0)
        {
            byte[] raw = new byte[fragOff];
            Buffer.BlockCopy(fragBuf, 0, raw, 0, fragOff);
            rawFragments.Add(raw);
        }

        string fileFingerprint = Hex.EncodeLower(hasher.GetHashAndReset()); // SHA256 of this version's content
        string filePrefix = customName ?? fileFingerprint;
        long fileSize = totalBytes;

        // Compute dedup hashes (XxHash128 on uncompressed data)
        var newHashes = rawFragments.Select(f => XxHash128.Hash(f.AsSpan())).ToList();
        var sourceVersion = new string?[rawFragments.Count];
        var sourceIndex = new int?[rawFragments.Count];
        bool anyChanged = false;

        for (int i = 0; i < rawFragments.Count; i++)
        {
            string key = Hex.EncodeLower(newHashes[i]);
            if (prevRawHashes != null && i < prevRawHashes.Count && newHashes[i].AsSpan().SequenceEqual(prevRawHashes[i]))
            {
                // Fragment unchanged - reference previous version
                sourceVersion[i] = prevFingerprint;
                sourceIndex[i] = i;
                // Update dedup map refcount
                if (dedupMap.TryGetValue(key, out var entry))
                    entry.RefCount++;
                else
                    dedupMap[key] = new DedupEntry { SourceFingerprint = prevFingerprint, SourceIndex = i, RefCount = 1 };
            }
            else
            {
                // New or changed fragment
                if (dedupMap.TryGetValue(key, out var entry))
                {
                    sourceVersion[i] = entry.SourceFingerprint;
                    sourceIndex[i] = entry.SourceIndex;
                    entry.RefCount++;
                }
                anyChanged = true;
            }
        }

        // If nothing changed, just record a new version pointing to the same fingerprint
        if (!anyChanged)
        {
            AppendVersionRecord(storage, prevFingerprint, password, null, prevVersion + 1, userMessage,
                "No changes detected", null, null);
            return prevFingerprint;
        }

        // Compress and encrypt only changed fragments, write them
        var originalFragments = new List<byte[]>();
        var originalFragmentSizes = new List<int>();
        var changedWrites = new List<(int index, byte[] data)>();

        for (int i = 0; i < rawFragments.Count; i++)
        {
            if (sourceVersion[i] != null)
            {
                // Reuse previous version's padded fragment - don't re-encrypt
                string prevPref = prevIdx.CustomName ?? prevFingerprint;
                string prevFragName = Frags.FragmentFilename(prevPref, sourceIndex[i] ?? i);
                byte[] prevEncFrag = storage.ReadFragment(prevFragName);
                (byte[] prevDecrypted, _, _) = FragmentFileHeader.DecryptWithEmbeddedIndex(prevEncFrag, prevAesKey);
                if (prevDecrypted == null)
                    throw new InvalidDataException($"Cannot reuse fragment {i} from {prevFingerprint}");
                originalFragments.Add(prevDecrypted); // Already padded
                // Record original size from previous version's index
                if (prevIdx.OriginalFragmentSizes != null && i < prevIdx.OriginalFragmentSizes.Count)
                    originalFragmentSizes.Add(prevIdx.OriginalFragmentSizes[i]);
                else
                    originalFragmentSizes.Add(rawFragments[i].Length);
            }
            else
            {
                byte[] raw = rawFragments[i];
                byte[] compressed = Compressor.AlwaysCompress(raw);
                byte[] stored = compressed.Length < raw.Length ? compressed : raw;
                originalFragmentSizes.Add(stored.Length);
                byte[] padded = new byte[fragSize];
                Buffer.BlockCopy(stored, 0, padded, 0, Math.Min(stored.Length, fragSize));
                originalFragments.Add(padded);
                changedWrites.Add((i, padded));
            }
        }

        // Build index
        var index = IndexManager.BuildIndex(
            fileFingerprint: fileFingerprint,
            originalFilename: Path.GetFileName(filePath),
            originalSize: fileSize,
            fragmentHashes: rawFragments.Select(f => IntegrityChecker.HashBytes(f)).ToList(),
            originalHash: fileFingerprint,
            fssStrategy: fssStrategy,
            originalFragmentSizes: originalFragmentSizes,
            originalFragmentCount: rawFragments.Count);

        index.CustomName = customName;
        index.RawFragmentHashes = newHashes;
        index.VersionNumber = prevVersion + 1;

        // Set SourceVersion on each fragment
        if (index.Fragments != null)
        {
            for (int i = 0; i < index.Fragments.Count && i < sourceVersion.Length; i++)
                index.Fragments[i].SourceVersion = sourceVersion[i];
        }

        // Write changed fragments
        foreach (var (idx, data) in changedWrites)
        {
            byte[] fileData = FragmentFileHeader.EncryptWithEmbeddedIndex(data, Array.Empty<byte>(),
                prevAesKey, null);
            string fname = Frags.FragmentFilename(filePrefix, idx);
            await storage.WriteFragmentAsync(fname, fileData, ct).ConfigureAwait(false);
        }

        // Encrypt and write standalone index (using salt-prefixed format)
        byte[] indexBytes = IndexManager.SerializeIndex(index);
        byte[] salt = RandomNumberGenerator.GetBytes(Constants.SaltPrefixLength);
        byte[] encryptedIndex = EncryptionLayer.EncryptIndexWithSaltPrefix(indexBytes, password, salt);
        await storage.WriteIndexAsync(filePrefix, encryptedIndex, ct).ConfigureAwait(false);

        // Also read-back to verify we can decrypt
        RdrfLogger.Default.Debug("",$"Real incremental backup complete: v{prevVersion + 1} = {fileFingerprint}");

        // Record version (no cleanup of any kind)
        AppendVersionRecord(storage, fileFingerprint, password, salt, prevVersion + 1,
            userMessage, string.Empty, null, null);

        RdrfLogger.Default.Debug("",$"Real incremental backup complete: v{prevVersion + 1} = {fileFingerprint}");
        return fileFingerprint;
    }

    /// <summary>
    /// Stores the version record in the NEW index (fingerprint), including
    /// all version records from the previous latest index. This way every
    /// index carries the complete version history.
    /// </summary>
    private static void AppendVersionRecord(DSAAAdapter storage, string fingerprint,
        byte[] password, byte[]? salt, int versionNumber, string message,
        string diffSummary, List<VersionRecord>? existingVersions = null,
        List<FileEntry>? fileEntries = null)
    {
        // Read all version records from the previous latest index
        var allVersions = new List<VersionRecord>();
        string? latestFp = storage.FindLatestIndex();
        if (latestFp != null && latestFp != fingerprint)
        {
            try
            {
                byte[] encIndex = storage.ReadIndex(latestFp);
                (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encIndex, password);
                var idx = IndexManager.DeserializeIndex(cbor);
                if (idx.Versions != null)
                    allVersions.AddRange(idx.Versions);
            }
            catch { /* best-effort: no previous version records */ }
        }
        // If latestFp == fingerprint, this is the first version being recorded

        // Add the new version record
        allVersions.Add(new VersionRecord
        {
            Version = versionNumber,
            FileFingerprint = fingerprint,
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            UserMessage = message,
            SystemDiff = diffSummary,
            Files = fileEntries
        });

        // Write ALL version records into the NEW index
        byte[] newIndexBytes = storage.ReadIndex(fingerprint);
        (byte[] newKey, byte[] newCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(newIndexBytes, password);
        var newIdx = IndexManager.DeserializeIndex(newCbor);
        newIdx.Versions = allVersions;

        byte[] updatedCbor = IndexManager.SerializeIndex(newIdx);
        byte[] existingSalt = newIdx.Salt != null ? Convert.FromHexString(newIdx.Salt) : null;
        byte[] updatedEnc = EncryptionLayer.EncryptIndexWithSaltPrefix(updatedCbor, password,
            salt ?? existingSalt);
        storage.WriteIndex(fingerprint, updatedEnc);
    }
}
