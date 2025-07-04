using System.Drawing;
using System.Text;

namespace RDRF.Core.Diff.Strategies;

public class ImageDiffStrategy : IDiffStrategy
{
    public string Name => "image";

    private static readonly HashSet<string> _imageExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".tif", ".tiff",
    };

    public double MatchScore(string? fileName, ReadOnlySpan<byte> sample)
    {
        if (!string.IsNullOrEmpty(fileName))
        {
            string ext = Path.GetExtension(fileName);
            if (!string.IsNullOrEmpty(ext) && _imageExtensions.Contains(ext))
                return 1.0;
        }

        if (sample.Length >= 8)
        {
            // PNG: 89 50 4E 47 0D 0A 1A 0A
            if (sample[0] == 0x89 && sample[1] == 0x50 && sample[2] == 0x4E && sample[3] == 0x47)
                return 0.95;
            // JPEG: FF D8 FF
            if (sample[0] == 0xFF && sample[1] == 0xD8 && sample[2] == 0xFF)
                return 0.95;
            // GIF: 47 49 46 38
            if (sample[0] == 0x47 && sample[1] == 0x49 && sample[2] == 0x46 && sample[3] == 0x38)
                return 0.95;
            // BMP: 42 4D
            if (sample[0] == 0x42 && sample[1] == 0x4D)
                return 0.95;
        }

        return 0;
    }

    public DiffResult ComputeDiff(byte[] oldData, byte[] newData, string? label)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"--- a/{label ?? "file"} (image)");
        sb.AppendLine($"+++ b/{label ?? "file"} (image)");

        var lines = new List<DiffLine>();
        long addedBytes = Math.Max(0, newData.LongLength - oldData.LongLength);
        long removedBytes = Math.Max(0, oldData.LongLength - newData.LongLength);

        try
        {
            using var oldMs = new MemoryStream(oldData);
            using var newMs = new MemoryStream(newData);
            using var oldImg = Image.FromStream(oldMs, false, false);
            using var newImg = Image.FromStream(newMs, false, false);

            string oldDesc = Describe(oldImg);
            string newDesc = Describe(newImg);

            if (oldDesc != newDesc)
            {
                lines.Add(new DiffLine { Type = DiffLineType.Deletion, Text = oldDesc });
                sb.AppendLine($"-{oldDesc}");
                lines.Add(new DiffLine { Type = DiffLineType.Addition, Text = newDesc });
                sb.AppendLine($"+{newDesc}");
            }

            string sizeLine = $"  File: {FormatBytes(oldData.Length)} -> {FormatBytes(newData.Length)} ({FormatBytes(newData.Length - oldData.Length)})";
            if (oldData.Length != newData.Length)
            {
                lines.Add(new DiffLine { Type = DiffLineType.Context, Text = sizeLine });
                sb.AppendLine(sizeLine);
            }
        }
        catch (Exception ex)
        {
            string err = $"(error reading image: {ex.Message})";
            lines.Add(new DiffLine { Type = DiffLineType.Header, Text = err });
            sb.AppendLine(err);
        }

        return new DiffResult
        {
            Label = label,
            IsBinary = true,
            AddedBytes = addedBytes,
            RemovedBytes = removedBytes,
            Lines = lines,
            HumanDiff = sb.ToString(),
            DetectedFileType = "image",
            OriginalSize = oldData.LongLength,
            ChangeRatio = oldData.Length > 0
                ? (double)(Math.Abs(newData.Length - oldData.Length)) / oldData.Length
                : 0,
        };
    }

    private static string Describe(Image img)
    {
        var fmt = img.RawFormat?.ToString().ToLowerInvariant() ?? "unknown";
        return $"{img.Width}x{img.Height}, {img.HorizontalResolution:F0}dpi, {img.PixelFormat}, {fmt}";
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes >= 1_000_000_000) return $"{bytes / 1_000_000_000.0:F1}GB";
        if (bytes >= 1_000_000) return $"{bytes / 1_000_000.0:F1}MB";
        if (bytes >= 1_000) return $"{(double)bytes / 1000:F1}KB";
        return $"{bytes}B";
    }
}
