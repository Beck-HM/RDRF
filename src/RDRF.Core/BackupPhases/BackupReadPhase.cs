using System.IO.Hashing;
using System.Security.Cryptography;
using RDRF.Core.Abstractions;
using RDRF.Core.Compression;
using RDRF.Core.Index;

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
        CancellationToken cancellationToken)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, 65536, FileOptions.SequentialScan);
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var rawFragments = new List<byte[]>();
        long totalRead = 0;
        long nextReport = 0;
        long fileSize = new FileInfo(filePath).Length;
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

        string fileFingerprint = Hex.EncodeLower(hasher.GetHashAndReset());
        int count = rawFragments.Count;
        var compressed = new byte[count][];
        var sizes = new int[count];
        Parallel.For(0, count, i =>
        {
            byte[] c = Compressor.AlwaysCompress(rawFragments[i]);
            byte[] stored = c.Length < rawFragments[i].Length ? c : rawFragments[i];
            sizes[i] = stored.Length;
            byte[] padded = new byte[fragSize];
            Buffer.BlockCopy(stored, 0, padded, 0, Math.Min(stored.Length, fragSize));
            compressed[i] = padded;
        });

        var rawHashes = rawFragments.Select(f => XxHash128.Hash(f.AsSpan())).ToList();

        return new BackupReadResult(rawFragments, compressed, sizes, count, rawHashes,
            fileFingerprint, fileFingerprint);
    }
}
