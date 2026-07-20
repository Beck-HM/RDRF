using System.IO.Hashing;
using System.Security.Cryptography;
using RDRF.Core.Abstractions;
using RDRF.Core.Compression;
using RDRF.Core.DSAA;
using RDRF.Core.FragmentEngine;
using RDRF.Core.FSA;
using RDRF.Core.Integrity;

namespace RDRF.Core.BackupPhases;

/// <summary>
/// True O(window) FSS1 backup: two sequential file passes without materializing
/// all raw or all encoded fragments in RAM.
/// <list type="number">
/// <item>Pass 1: stream raw → FSS1 encode → SHA256 fragment hash → free; keep only hashes/sizes.</item>
/// <item>Build index (caller) from pass-1 metadata.</item>
/// <item>Pass 2: stream raw → encode → compress → encrypt+write → free each fragment.</item>
/// </list>
/// Eligible only for pure FSS1 + per-fragment compression (not CKC / ETN / multi-strategy).
/// </summary>
public static class Fss1WindowedPipeline
{
    public static bool IsEligible(FsaPlan plan, string? compressionMethod)
    {
        if (!string.Equals(plan.EffectivePrimary, Constants.FssLevel1, StringComparison.OrdinalIgnoreCase))
            return false;
        if (plan.EncodeSteps.Count != 1
            || !string.Equals(plan.EncodeSteps[0].Strategy, Constants.FssLevel1, StringComparison.OrdinalIgnoreCase)
            || plan.EncodeSteps[0].Step != "encode")
            return false;
        foreach (var s in plan.ActiveStrategies)
        {
            if (s is Constants.FssLevel6 or Constants.FssLevel61 or Constants.FssLevel62
                or Constants.FssLevel2 or Constants.FssLevel2R or Constants.FssLevel3
                or Constants.FssLevel5 or Constants.FssLevel5P)
                return false;
        }
        if (string.Equals(compressionMethod, Constants.CompressionCkc, StringComparison.OrdinalIgnoreCase))
            return false;
        return true;
    }

    public sealed class Pass1Result
    {
        public required string FileFingerprint { get; init; }
        public required string OriginalHash { get; init; }
        public required int FragmentCount { get; init; }
        public required List<int> OriginalFragmentSizes { get; init; }
        public required List<string> EncodedFragmentHashes { get; init; }
        public required List<byte[]> RawFragmentHashes { get; init; }
    }

    /// <summary>
    /// Pass 1: stream file, compute fingerprint + per-raw XxHash + FSS1 encoded SHA256.
    /// Peak ≈ 2–3 raw fragments + one short-lived encoded buffer.
    /// </summary>
    public static async Task<Pass1Result> ScanHashAsync(
        string filePath, int fragSize,
        IProgress<RdrfProgressReport>? progress, CancellationToken ct)
    {
        long fileSize = new FileInfo(filePath).Length;
        int ioBuf = Math.Clamp(fragSize, 256 * 1024, 1024 * 1024);
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read,
            ioBuf, FileOptions.SequentialScan | FileOptions.Asynchronous);
        using var fileHasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        var sizes = new List<int>();
        var rawHashes = new List<byte[]>();
        var encHashes = new List<string>();

        byte[]? first = null;
        byte[]? hold = null;
        int count = 0;
        long totalRead = 0;
        long nextReport = 0;
        var fragBuf = new byte[fragSize];
        int fragOff = 0;

        int bytesRead;
        while ((bytesRead = await fs.ReadAsync(fragBuf.AsMemory(fragOff, fragSize - fragOff), ct).ConfigureAwait(false)) > 0)
        {
            fileHasher.AppendData(fragBuf.AsSpan(fragOff, bytesRead));
            fragOff += bytesRead;
            totalRead += bytesRead;
            if (totalRead >= nextReport)
            {
                progress?.Report(new RdrfProgressReport
                {
                    Stage = "Read", CurrentBytes = totalRead, TotalBytes = fileSize
                });
                nextReport = totalRead + Math.Max(65536, fileSize / 100);
            }

            if (fragOff < fragSize) continue;

            byte[] raw = new byte[fragSize];
            Buffer.BlockCopy(fragBuf, 0, raw, 0, fragSize);
            fragOff = 0;
            AcceptRaw(raw, sizes, rawHashes, encHashes, ref first, ref hold, ref count);
        }

        if (fragOff > 0)
        {
            byte[] raw = new byte[fragOff];
            Buffer.BlockCopy(fragBuf, 0, raw, 0, fragOff);
            AcceptRaw(raw, sizes, rawHashes, encHashes, ref first, ref hold, ref count);
        }

        // Finish ring / single-fragment case
        if (count == 0)
        {
            // Empty file: one empty fragment convention matches BackupReadPhase (0 frags or 1 empty?)
            // BackupReadPhase with empty file: rawFragments empty, count 0.
            string emptyFp = Hex.EncodeLower(fileHasher.GetHashAndReset());
            return new Pass1Result
            {
                FileFingerprint = emptyFp,
                OriginalHash = emptyFp,
                FragmentCount = 0,
                OriginalFragmentSizes = sizes,
                EncodedFragmentHashes = encHashes,
                RawFragmentHashes = rawHashes,
            };
        }

        if (count == 1)
        {
            // self || self
            byte[] only = hold!;
            byte[] enc = Concat(only, only);
            encHashes.Add(IntegrityChecker.HashBytes(enc));
            CryptographicOperations.ZeroMemory(enc);
            CryptographicOperations.ZeroMemory(only);
            first = null;
            hold = null;
        }
        else
        {
            // last: hold || first
            byte[] enc = Concat(hold!, first!);
            encHashes.Add(IntegrityChecker.HashBytes(enc));
            CryptographicOperations.ZeroMemory(enc);
            CryptographicOperations.ZeroMemory(hold!);
            CryptographicOperations.ZeroMemory(first!);
            hold = null;
            first = null;
        }

        string fp = Hex.EncodeLower(fileHasher.GetHashAndReset());
        progress?.Report(new RdrfProgressReport
        {
            Stage = "Read", CurrentBytes = fileSize, TotalBytes = fileSize,
            CurrentItem = count, TotalItems = count
        });

        return new Pass1Result
        {
            FileFingerprint = fp,
            OriginalHash = fp,
            FragmentCount = count,
            OriginalFragmentSizes = sizes,
            EncodedFragmentHashes = encHashes,
            RawFragmentHashes = rawHashes,
        };
    }

    private static void AcceptRaw(
        byte[] raw, List<int> sizes, List<byte[]> rawHashes, List<string> encHashes,
        ref byte[]? first, ref byte[]? hold, ref int count)
    {
        sizes.Add(raw.Length);
        rawHashes.Add(XxHash128.Hash(raw.AsSpan()));
        count++;

        if (hold == null)
        {
            hold = raw;
            first = raw;
            return;
        }

        // Encode previous hold with this raw as next
        byte[] enc = Concat(hold, raw);
        encHashes.Add(IntegrityChecker.HashBytes(enc));
        CryptographicOperations.ZeroMemory(enc);

        if (!ReferenceEquals(hold, first))
            CryptographicOperations.ZeroMemory(hold);
        // else keep first for ring wrap

        hold = raw;
    }

    /// <summary>
    /// Pass 2: re-stream file, FSS1 encode → bounded-parallel compress+encrypt write.
    /// Peak ≈ (2–3 raw) + prefetch×(encoded/compressed) — not the full file set.
    /// </summary>
    public static async Task WriteFragmentsAsync(
        string filePath, int fragSize,
        string filePrefix, byte[] embeddedIndexBytes, byte[] aesKey, byte[]? salt,
        string compressionMethod, string? compressionOptions,
        DSAAAdapter storage,
        IProgress<RdrfProgressReport>? progress, CancellationToken ct,
        System.Collections.Concurrent.ConcurrentDictionary<string, byte>? writtenNames = null)
    {
        int ioBuf = Math.Clamp(fragSize, 256 * 1024, 1024 * 1024);
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read,
            ioBuf, FileOptions.SequentialScan | FileOptions.Asynchronous);

        byte[]? first = null;
        byte[]? hold = null;
        int index = 0; // index of `hold`
        int written = 0;
        var fragBuf = new byte[fragSize];
        int fragOff = 0;
        string cm = string.IsNullOrEmpty(compressionMethod) ? Constants.CompressionLz4 : compressionMethod;

        // Bound in-flight compress+write so slow codecs (lz4hc/xz) still parallelize
        // without materializing all fragments.
        int prefetch = Math.Clamp(Constants.DefaultParallelism, 2, 6);
        using var gate = new SemaphoreSlim(prefetch, prefetch);
        var inflight = new List<Task>();

        async Task EmitAsync(byte[] self, byte[] next, int fragIndex)
        {
            // Copy self/next into encoded before releasing raw slots (hold may be freed by caller).
            byte[] enc = Concat(self, next);
            await gate.WaitAsync(ct).ConfigureAwait(false);
            var task = Task.Run(async () =>
            {
                try
                {
                    byte[] payload = enc;
                    byte[] compressed = Compressor.AlwaysCompress(enc, cm, compressionOptions);
                    if (compressed.Length < enc.Length)
                    {
                        CryptographicOperations.ZeroMemory(enc);
                        payload = compressed;
                    }

                    string fname = Frags.FragmentFilename(filePrefix, fragIndex);
                    await storage.WriteFragmentViaStreamAsync(fname, async (stream, ct2) =>
                    {
                        await FragmentFileHeader.EncryptWithEmbeddedIndexToStreamAsync(
                            stream, payload, embeddedIndexBytes, aesKey, salt, ct2).ConfigureAwait(false);
                    }, ct).ConfigureAwait(false);

                    CryptographicOperations.ZeroMemory(payload);
                    writtenNames?.TryAdd(fname, 0);
                    int done = Interlocked.Increment(ref written);
                    progress?.Report(new RdrfProgressReport
                    {
                        Stage = "Write", CurrentItem = done, TotalItems = 0
                    });
                }
                finally
                {
                    gate.Release();
                }
            }, ct);
            inflight.Add(task);
            // Prune completed tasks to avoid unbounded list growth
            if (inflight.Count > prefetch * 2)
                inflight.RemoveAll(t => t.IsCompleted);
        }

        int bytesRead;
        while ((bytesRead = await fs.ReadAsync(fragBuf.AsMemory(fragOff, fragSize - fragOff), ct).ConfigureAwait(false)) > 0)
        {
            fragOff += bytesRead;
            if (fragOff < fragSize) continue;

            byte[] raw = new byte[fragSize];
            Buffer.BlockCopy(fragBuf, 0, raw, 0, fragSize);
            fragOff = 0;

            if (hold == null)
            {
                hold = raw;
                first = raw;
                index = 0;
                continue;
            }

            await EmitAsync(hold, raw, index).ConfigureAwait(false);
            if (!ReferenceEquals(hold, first))
                CryptographicOperations.ZeroMemory(hold);
            hold = raw;
            index++;
        }

        if (fragOff > 0)
        {
            byte[] raw = new byte[fragOff];
            Buffer.BlockCopy(fragBuf, 0, raw, 0, fragOff);

            if (hold == null)
            {
                hold = raw;
                first = raw;
                index = 0;
            }
            else
            {
                await EmitAsync(hold, raw, index).ConfigureAwait(false);
                if (!ReferenceEquals(hold, first))
                    CryptographicOperations.ZeroMemory(hold);
                hold = raw;
                index++;
            }
        }

        if (hold != null)
        {
            if (ReferenceEquals(hold, first) && index == 0)
            {
                await EmitAsync(hold, hold, 0).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(hold);
            }
            else
            {
                await EmitAsync(hold, first!, index).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(hold);
                CryptographicOperations.ZeroMemory(first!);
            }
        }

        await Task.WhenAll(inflight).ConfigureAwait(false);
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        byte[] c = new byte[checked(a.Length + b.Length)];
        Buffer.BlockCopy(a, 0, c, 0, a.Length);
        Buffer.BlockCopy(b, 0, c, a.Length, b.Length);
        return c;
    }
}
