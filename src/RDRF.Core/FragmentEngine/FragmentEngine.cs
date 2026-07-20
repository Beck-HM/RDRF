using RDRF.Core.Abstractions;
using System.Security.Cryptography;
using System.Text;

namespace RDRF.Core.FragmentEngine;

/// <summary>
/// Static Frags utility: split/merge files, fragment naming, fingerprint computation.
/// </summary>

public static class Frags
{
    private const int DefaultFragmentSize = 1024 * 1024;

    /// <summary>
    /// Stream-split a file into fragments while computing fingerprint (no full-file double buffer).
    /// Peak memory is still O(file) for the returned fragment list (callers that need all parts),
    /// but avoids holding a separate full-file byte[] alongside the list.
    /// </summary>
    public static (List<byte[]> fragments, string fingerprint) SplitFile(string filePath, int fragmentSize = 0)
    {
        long fileLen = new FileInfo(filePath).Length;
        if (fragmentSize <= 0) fragmentSize = Constants.ComputeFragmentSize(fileLen, null);

        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, Math.Clamp(fragmentSize, 64 * 1024, 1024 * 1024), FileOptions.SequentialScan);
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var fragments = new List<byte[]>();
        var buf = new byte[fragmentSize];
        int read;
        while ((read = fs.Read(buf, 0, fragmentSize)) > 0)
        {
            hasher.AppendData(buf.AsSpan(0, read));
            var frag = new byte[read];
            Buffer.BlockCopy(buf, 0, frag, 0, read);
            fragments.Add(frag);
        }
        string fingerprint = Hex.EncodeLower(hasher.GetHashAndReset());
        return (fragments, fingerprint);
    }

    public static IEnumerable<byte[]> EnumerateFragments(string filePath, int fragmentSize = 0)
    {
        if (fragmentSize <= 0) fragmentSize = DefaultFragmentSize;
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, 65536, FileOptions.SequentialScan);
        byte[] buf = new byte[fragmentSize];
        int read;
        while ((read = fs.Read(buf, 0, fragmentSize)) > 0)
        {
            if (read == fragmentSize)
            {
                yield return buf;
                buf = new byte[fragmentSize];
            }
            else
            {
                var last = new byte[read];
                Buffer.BlockCopy(buf, 0, last, 0, read);
                yield return last;
            }
        }
    }

    public static List<byte[]> SplitData(byte[] data, int fragmentSize = 0)
    {
        if (fragmentSize <= 0) fragmentSize = Constants.ComputeFragmentSize(data.Length, null);

        var fragments = new List<byte[]>();
        for (int offset = 0; offset < data.Length; offset += fragmentSize)
        {
            int len = Math.Min(fragmentSize, data.Length - offset);
            byte[] fragment = new byte[len];
            Buffer.BlockCopy(data, offset, fragment, 0, len);
            fragments.Add(fragment);
        }
        return fragments;
    }

    public static void MergeFragments(List<byte[]> fragments, string outputPath)
    {
        using var stream = new FileStream(outputPath, FileMode.Create, FileAccess.Write);
        foreach (var fragment in fragments)
            stream.Write(fragment, 0, fragment.Length);
    }

    public static byte[] MergeFragments(List<byte[]> fragments)
    {
        long totalSize = 0;
        foreach (var f in fragments) totalSize += f.Length;
        if (totalSize > int.MaxValue)
            throw new RdrfException(ErrorCode.FileTooLarge, $"Merged fragment size {totalSize} exceeds maximum array size.");
        byte[] result = new byte[totalSize];
        int offset = 0;
        foreach (var f in fragments)
        {
            Buffer.BlockCopy(f, 0, result, offset, f.Length);
            offset += f.Length;
        }
        return result;
    }

    public static string FragmentFilename(string filePrefix, int index)
    {
        if (string.IsNullOrEmpty(filePrefix) || filePrefix.Contains("..") || filePrefix.Contains('/') || filePrefix.Contains('\\'))
            throw new ArgumentException("Invalid file prefix: path traversal not allowed.", nameof(filePrefix));
        if (filePrefix.Length == 64 && !System.Text.RegularExpressions.Regex.IsMatch(filePrefix, "^[0-9a-fA-F]{64}$"))
            throw new ArgumentException("File prefix must be a valid SHA256 hex fingerprint.", nameof(filePrefix));
        return string.Format(Constants.FragmentFilePattern, filePrefix, index);
    }

    public static int GetFragmentCount(long fileSize, int fragmentSize = 0)
    {
        if (fragmentSize <= 0) fragmentSize = Constants.ComputeFragmentSize(fileSize, null);
        return (int)((fileSize + fragmentSize - 1) / fragmentSize);
    }

    public static string ComputeFingerprint(byte[] data)
    {
        byte[] hash = SHA256.HashData(data);
        return Hex.EncodeLower(hash);
    }
}



