using System.Text;

namespace RDRF.Core.Diff.Strategies;

/// <summary>
/// Binary fallback diff: compares file sizes only.
/// </summary>

public class BinaryDefaultStrategy : IDiffStrategy
{
    public string Name => "binary_default";

    public double MatchScore(string? fileName, ReadOnlySpan<byte> sample)
    {
        return 0.01;
    }

    public DiffResult ComputeDiff(byte[] oldData, byte[] newData, string? label)
    {
        long addedBytes = Math.Max(0, newData.LongLength - oldData.LongLength);
        long removedBytes = Math.Max(0, oldData.LongLength - newData.LongLength);

        var sb = new StringBuilder();
        sb.AppendLine($"--- a/{label ?? "file"} (binary)");
        sb.AppendLine($"+++ b/{label ?? "file"} (binary)");
        if (oldData.LongLength == newData.LongLength)
            sb.AppendLine($"File size unchanged: {oldData.Length} bytes");
        else
            sb.AppendLine($"Old size: {oldData.Length} bytes -> New size: {newData.Length} bytes");

        return new DiffResult
        {
            Label = label,
            IsBinary = true,
            AddedBytes = addedBytes,
            RemovedBytes = removedBytes,
            Lines = new List<DiffLine>
            {
                new DiffLine { Type = DiffLineType.Header, Text = $"(binary) {label ?? "file"}: {oldData.Length} -> {newData.Length} bytes" }
            },
            HumanDiff = sb.ToString(),
            DetectedFileType = "binary",
            OriginalSize = oldData.LongLength,
            ChangeRatio = oldData.Length > 0
                ? (double)(Math.Abs(newData.Length - oldData.Length)) / oldData.Length
                : 0,
        };
    }
}

