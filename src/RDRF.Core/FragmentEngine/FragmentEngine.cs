using System.Security.Cryptography;
using System.Text;

namespace RDRF.Core.FragmentEngine;

/// <summary>
/// Static Frags utility: split/merge files, fragment naming, fingerprint computation.
/// </summary>

public static class Frags
{
    private const int DefaultFragmentSize = 1024 * 1024;

    public static (List<byte[]> fragments, string fingerprint) SplitFile(string filePath, int fragmentSize = 0)
    {
        if (fragmentSize <= 0) fragmentSize = DefaultFragmentSize;

        byte[] fileData = File.ReadAllBytes(filePath);
        string fingerprint = ComputeFingerprint(fileData);

        var fragments = new List<byte[]>();
        for (int offset = 0; offset < fileData.Length; offset += fragmentSize)
        {
            int len = Math.Min(fragmentSize, fileData.Length - offset);
            byte[] fragment = new byte[len];
            Buffer.BlockCopy(fileData, offset, fragment, 0, len);
            fragments.Add(fragment);
        }
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
        if (fragmentSize <= 0) fragmentSize = DefaultFragmentSize;

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
        int totalSize = 0;
        foreach (var f in fragments) totalSize += f.Length;
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
        => string.Format(Constants.FragmentFilePattern, filePrefix, index);

    public static int GetFragmentCount(long fileSize, int fragmentSize = 0)
    {
        if (fragmentSize <= 0) fragmentSize = DefaultFragmentSize;
        return (int)((fileSize + fragmentSize - 1) / fragmentSize);
    }

    public static string ComputeFingerprint(byte[] data)
    {
        byte[] hash = SHA256.HashData(data);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}

