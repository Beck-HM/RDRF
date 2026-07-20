namespace RDRF.Core.Diff;

/// <summary>
/// Diff strategy selection and computation. Chooses strategy based on file type.
/// </summary>

public class DiffEngine
{
    private readonly List<IDiffStrategy> _strategies;

    public DiffEngine()
    {
        _strategies =
        [
            new Strategies.JsonDiffStrategy(),
            new Strategies.IniDiffStrategy(),
            new Strategies.ImageDiffStrategy(),
            new Strategies.MediaDiffStrategy(),
            new Strategies.TextGenericStrategy(),
            new Strategies.BinaryDefaultStrategy(),
        ];
    }

    public DiffEngine(IEnumerable<IDiffStrategy> additionalStrategies)
    {
        _strategies = new List<IDiffStrategy>
        {
            new Strategies.JsonDiffStrategy(),
            new Strategies.IniDiffStrategy(),
            new Strategies.ImageDiffStrategy(),
            new Strategies.MediaDiffStrategy(),
            new Strategies.TextGenericStrategy(),
            new Strategies.BinaryDefaultStrategy(),
        };
        if (additionalStrategies != null)
            _strategies.AddRange(additionalStrategies);
    }

    public IDiffStrategy SelectStrategy(string? fileName, ReadOnlySpan<byte> sample)
    {
        IDiffStrategy best = _strategies[^1];
        double bestScore = -1;

        foreach (var s in _strategies)
        {
            double score = s.MatchScore(fileName, sample);
            if (score > bestScore)
            {
                bestScore = score;
                best = s;
            }
        }

        return best;
    }

    public DiffResult ComputeDiff(byte[] oldData, byte[] newData, string? label = null)
    {
        var sample = newData.Length > 0 ? newData.AsSpan(0, Math.Min(newData.Length, 8192)) : ReadOnlySpan<byte>.Empty;
        var strategy = SelectStrategy(label, sample);
        var result = strategy.ComputeDiff(oldData, newData, label);
        return result;
    }

    /// <summary>
    /// Diff two files on disk. Streams an 8 KiB sample for strategy selection;
    /// binary strategies only use lengths (no full ReadAllBytes). Text/media strategies
    /// load content only when needed.
    /// </summary>
    public DiffResult ComputeDiffFromFiles(string oldPath, string newPath, string? label = null)
    {
        long oldLen = new FileInfo(oldPath).Length;
        long newLen = new FileInfo(newPath).Length;
        byte[] sampleBuf = new byte[8192];
        int sampleLen;
        using (var fs = new FileStream(newPath, FileMode.Open, FileAccess.Read, FileShare.Read,
            8192, FileOptions.SequentialScan))
        {
            sampleLen = fs.Read(sampleBuf, 0, sampleBuf.Length);
        }
        var strategy = SelectStrategy(label, sampleBuf.AsSpan(0, sampleLen));

        // Binary fallback only needs sizes — avoid loading multi-GB files into RAM.
        if (strategy is Strategies.BinaryDefaultStrategy || strategy.Name == "binary_default")
            return ComputeBinarySizeDiff(oldLen, newLen, label);

        // Text/image/media: content required by strategy APIs.
        byte[] oldData = oldLen == 0 ? Array.Empty<byte>() : File.ReadAllBytes(oldPath);
        byte[] newData = newLen == 0 ? Array.Empty<byte>() : File.ReadAllBytes(newPath);
        return strategy.ComputeDiff(oldData, newData, label);
    }

    /// <summary>Size-only binary diff without allocating file contents.</summary>
    public static DiffResult ComputeBinarySizeDiff(long oldLen, long newLen, string? label = null)
    {
        long addedBytes = Math.Max(0, newLen - oldLen);
        long removedBytes = Math.Max(0, oldLen - newLen);
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"--- a/{label ?? "file"} (binary)");
        sb.AppendLine($"+++ b/{label ?? "file"} (binary)");
        if (oldLen == newLen)
            sb.AppendLine($"File size unchanged: {oldLen} bytes");
        else
            sb.AppendLine($"Old size: {oldLen} bytes -> New size: {newLen} bytes");

        return new DiffResult
        {
            Label = label,
            IsBinary = true,
            AddedBytes = addedBytes,
            RemovedBytes = removedBytes,
            Lines =
            [
                new DiffLine
                {
                    Type = DiffLineType.Header,
                    Text = $"(binary) {label ?? "file"}: {oldLen} -> {newLen} bytes"
                }
            ],
            HumanDiff = sb.ToString(),
            DetectedFileType = "binary",
            OriginalSize = oldLen,
            ChangeRatio = oldLen > 0 ? (double)Math.Abs(newLen - oldLen) / oldLen : 0,
        };
    }
}

