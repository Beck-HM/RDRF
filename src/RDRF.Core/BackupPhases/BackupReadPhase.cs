using System.Buffers;
using System.IO.Hashing;
using System.Security.Cryptography;
using RDRF.Core.Abstractions;

namespace RDRF.Core.BackupPhases;

public readonly record struct BackupReadResult(
    List<byte[]> RawFragments,
    byte[][] OriginalFragments,
    int[] OriginalFragmentSizes,
    int OriginalFragmentCount,
    List<byte[]> RawHashes,
    string FileFingerprint,
    string OriginalHash);

public static class BackupReadPhase
{
    public static async Task<BackupReadResult> ExecuteAsync(
        string filePath, int fragSize,
        IProgress<RdrfProgressReport>? progress,
        CancellationToken cancellationToken,
        string? compressionMethod = null,
        string? compressionOptions = null)
    {
        int ioBuf = Math.Clamp(fragSize * 2, 256 * 1024, 2 * 1024 * 1024);
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, ioBuf, FileOptions.SequentialScan | FileOptions.Asynchronous);
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var rawFragments = new List<byte[]>();
        long totalRead = 0;
        long nextReport = 0;
        long fileSize = new FileInfo(filePath).Length;
        var fragBuf = ArrayPool<byte>.Shared.Rent(fragSize);
        int fragOff = 0;

        try
        {
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
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(fragBuf);
        }

        string fileFingerprint = Hex.EncodeLower(hasher.GetHashAndReset());
        int count = rawFragments.Count;
        var sizes = new int[count];
        // Single ownership: OriginalFragments aliases the same arrays as RawFragments (no second copy).
        var original = new byte[count][];
        var rawHashes = new List<byte[]>(count);
        for (int i = 0; i < count; i++)
        {
            sizes[i] = rawFragments[i].Length;
            original[i] = rawFragments[i];
            rawHashes.Add(null!);
        }

        if (RDRF.Core.Device.GpuContext.IsAvailable)
        {
            rawHashes = RDRF.Core.Device.GpuHasher.HashXXH128(rawFragments);
        }
        else
        {
            Parallel.For(0, count, new ParallelOptions
            {
                MaxDegreeOfParallelism = Constants.DefaultParallelism,
                CancellationToken = cancellationToken,
            }, i =>
            {
                rawHashes[i] = XxHash128.Hash(rawFragments[i].AsSpan());
            });
        }

        return new BackupReadResult(rawFragments, original, sizes, count, rawHashes,
            fileFingerprint, fileFingerprint);
    }
}
