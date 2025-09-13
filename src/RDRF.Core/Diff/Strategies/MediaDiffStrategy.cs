using System.Text;
using TagLib;

namespace RDRF.Core.Diff.Strategies;

public class MediaDiffStrategy : IDiffStrategy
{
    public string Name => "media";

    private static readonly HashSet<string> _mediaExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".mp3", ".flac", ".wav", ".ogg", ".aac", ".wma", ".m4a",
        ".mp4", ".mkv", ".avi", ".mov", ".webm", ".mts", ".m2ts",
    };

    public double MatchScore(string? fileName, ReadOnlySpan<byte> sample)
    {
        if (!string.IsNullOrEmpty(fileName))
        {
            string ext = Path.GetExtension(fileName);
            if (!string.IsNullOrEmpty(ext) && _mediaExtensions.Contains(ext))
                return 1.0;
        }
        return 0;
    }

    public DiffResult ComputeDiff(byte[] oldData, byte[] newData, string? label)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"--- a/{label ?? "file"} (media)");
        sb.AppendLine($"+++ b/{label ?? "file"} (media)");

        var lines = new List<DiffLine>();
        long addedBytes = Math.Max(0, newData.LongLength - oldData.LongLength);
        long removedBytes = Math.Max(0, oldData.LongLength - newData.LongLength);

        try
        {
            var oldProps = ReadProperties(oldData);
            var newProps = ReadProperties(newData);

            string typeLabel = (oldProps.TryGetValue("type", out var ot) ? ot : newProps.GetValueOrDefault("type", "media")) switch
            {
                "audio" => "audio",
                "video" => "video",
                _ => "media",
            };

            var keys = oldProps.Keys.Union(newProps.Keys)
                .Where(k => k != "type")
                .OrderBy(k => k)
                .ToList();

            foreach (var key in keys)
            {
                oldProps.TryGetValue(key, out var oldVal);
                newProps.TryGetValue(key, out var newVal);

                if (oldVal != newVal)
                {
                    if (oldVal == null)
                    {
                        string msg = $"{key}: (none) -> {newVal}";
                        lines.Add(new DiffLine { Type = DiffLineType.Addition, Text = msg });
                        sb.AppendLine($"+{msg}");
                    }
                    else if (newVal == null)
                    {
                        string msg = $"{key}: {oldVal} -> (none)";
                        lines.Add(new DiffLine { Type = DiffLineType.Deletion, Text = msg });
                        sb.AppendLine($"-{msg}");
                    }
                    else
                    {
                        string msg = $"{key}: {oldVal} -> {newVal}";
                        lines.Add(new DiffLine { Type = DiffLineType.Deletion, Text = msg });
                        sb.AppendLine($"-{msg}");
                        lines.Add(new DiffLine { Type = DiffLineType.Addition, Text = msg });
                        sb.AppendLine($"+{msg}");
                    }
                }
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
            string err = $"(error reading media metadata: {ex.Message})";
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
            DetectedFileType = "media",
            OriginalSize = oldData.LongLength,
            ChangeRatio = oldData.Length > 0
                ? (double)(Math.Abs(newData.Length - oldData.Length)) / oldData.Length
                : 0,
        };
    }

    private static Dictionary<string, string> ReadProperties(byte[] data)
    {
        var props = new Dictionary<string, string>();

        try
        {
            using var readMs = new MemoryStream(data);
            var file = TagLib.File.Create(new StreamFileAbstraction("file", readMs, new MemoryStream()));

            var tag = file.Tag;
            var props_ = file.Properties;

            if (tag != null)
            {
                if (!string.IsNullOrEmpty(tag.Title))
                    props["Title"] = tag.Title;
                if (!string.IsNullOrEmpty(tag.FirstAlbumArtist) || !string.IsNullOrEmpty(tag.FirstPerformer))
                    props["Artist"] = tag.FirstAlbumArtist ?? tag.FirstPerformer ?? "";
                if (!string.IsNullOrEmpty(tag.Album))
                    props["Album"] = tag.Album;
                if (tag.Year > 0)
                    props["Year"] = tag.Year.ToString();
                if (!string.IsNullOrEmpty(tag.FirstGenre))
                    props["Genre"] = tag.FirstGenre;
                if (tag.Track > 0)
                    props["Track"] = tag.Track.ToString();
            }

            if (props_ != null)
            {
                if (props_.Duration.TotalSeconds > 0)
                    props["Duration"] = FormatDuration(props_.Duration);

                if (props_.AudioBitrate > 0)
                    props["Audio Bitrate"] = $"{props_.AudioBitrate}kbps";
                if (props_.AudioSampleRate > 0)
                    props["Sample Rate"] = $"{props_.AudioSampleRate}Hz";
                if (props_.AudioChannels > 0)
                    props["Channels"] = props_.AudioChannels.ToString();

                if (props_.VideoWidth > 0 && props_.VideoHeight > 0)
                {
                    props["type"] = "video";
                    props["Resolution"] = $"{props_.VideoWidth}x{props_.VideoHeight}";

                    foreach (var codec in props_.Codecs)
                    {
                        string? desc = codec?.Description;
                        if (!string.IsNullOrEmpty(desc))
                            props["Codec"] = desc;
                    }
                }
                else
                {
                    props["type"] = "audio";
                }

                if (!string.IsNullOrEmpty(props_.Description))
                    props["Description"] = props_.Description;
            }

            file.Dispose();
        }
        catch
        {
            // TagLib may throw for unsupported formats or corrupt files
        }

        return props;
    }

    private static string FormatDuration(TimeSpan ts)
    {
        if (ts.TotalHours >= 1)
            return $"{(int)ts.TotalHours}:{ts.Minutes:D2}:{ts.Seconds:D2}";
        return $"{ts.Minutes}:{ts.Seconds:D2}";
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes >= 1_000_000_000) return $"{bytes / 1_000_000_000.0:F1}GB";
        if (bytes >= 1_000_000) return $"{bytes / 1_000_000.0:F1}MB";
        if (bytes >= 1_000) return $"{(double)bytes / 1000:F1}KB";
        return $"{bytes}B";
    }
}

internal class StreamFileAbstraction : TagLib.File.IFileAbstraction
{
    private readonly string _name;
    private readonly MemoryStream _readStream;
    private readonly MemoryStream _writeStream;

    public StreamFileAbstraction(string name, MemoryStream readStream, MemoryStream writeStream)
    {
        _name = name;
        _readStream = readStream;
        _writeStream = writeStream;
    }

    public string Name => _name;
    public Stream ReadStream => _readStream;
    public Stream WriteStream => _writeStream;

    public void CloseStream(Stream stream)
    {
        stream.Close();
    }
}
