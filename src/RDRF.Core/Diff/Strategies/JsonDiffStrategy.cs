using System.Text;
using System.Text.Json;

namespace RDRF.Core.Diff.Strategies;

public class JsonDiffStrategy : IDiffStrategy
{
    public string Name => "json";

    public double MatchScore(string? fileName, ReadOnlySpan<byte> sample)
    {
        if (!string.IsNullOrEmpty(fileName))
        {
            string ext = Path.GetExtension(fileName);
            if (".json".Equals(ext, StringComparison.OrdinalIgnoreCase))
                return 1.0;
        }

        int start = 0;
        while (start < sample.Length && sample[start] <= 0x20)
            start++;
        if (start < sample.Length && (sample[start] == (byte)'{' || sample[start] == (byte)'['))
            return 0.95;

        return 0;
    }

    public DiffResult ComputeDiff(byte[] oldData, byte[] newData, string? label)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"--- a/{label ?? "file"} (json)");
        sb.AppendLine($"+++ b/{label ?? "file"} (json)");

        var lines = new List<DiffLine>();
        long addedBytes = Math.Max(0, newData.LongLength - oldData.LongLength);
        long removedBytes = Math.Max(0, oldData.LongLength - newData.LongLength);

        try
        {
            using var oldDoc = JsonDocument.Parse(oldData);
            using var newDoc = JsonDocument.Parse(newData);
            CompareElements(oldDoc.RootElement, newDoc.RootElement, "$", lines, sb);
        }
        catch (JsonException)
        {
            sb.AppendLine("(invalid JSON, falling back to text diff)");
            lines.Add(new DiffLine { Type = DiffLineType.Header, Text = "(invalid JSON)" });
        }

        return new DiffResult
        {
            Label = label,
            IsBinary = false,
            AddedBytes = addedBytes,
            RemovedBytes = removedBytes,
            Lines = lines,
            HumanDiff = sb.ToString(),
            DetectedFileType = "json",
            OriginalSize = oldData.LongLength,
            ChangeRatio = oldData.Length > 0
                ? (double)(Math.Abs(newData.Length - oldData.Length)) / oldData.Length
                : 0,
        };
    }

    private static void CompareElements(JsonElement old, JsonElement newEl, string path,
        List<DiffLine> lines, StringBuilder sb)
    {
        if (old.ValueKind != newEl.ValueKind)
        {
            string msg = $"{path}: {FormatValue(old)} ({old.ValueKind}) -> {FormatValue(newEl)} ({newEl.ValueKind})";
            lines.Add(new DiffLine { Type = DiffLineType.Deletion, Text = msg });
            sb.AppendLine($"-{msg}");
            lines.Add(new DiffLine { Type = DiffLineType.Addition, Text = msg });
            sb.AppendLine($"+{msg}");
            return;
        }

        switch (old.ValueKind)
        {
            case JsonValueKind.Object:
                var oldProps = new HashSet<string>();
                foreach (var p in old.EnumerateObject()) oldProps.Add(p.Name);

                foreach (var p in newEl.EnumerateObject())
                {
                    if (old.TryGetProperty(p.Name, out var oldVal))
                    {
                        oldProps.Remove(p.Name);
                        CompareElements(oldVal, p.Value, $"{path}.{p.Name}", lines, sb);
                    }
                    else
                    {
                        string msg = $"{path}.{p.Name}: (added) -> {FormatValue(p.Value)}";
                        lines.Add(new DiffLine { Type = DiffLineType.Addition, Text = msg });
                        sb.AppendLine($"+{msg}");
                    }
                }

                foreach (var removed in oldProps)
                {
                    if (old.TryGetProperty(removed, out var removedVal))
                    {
                        string msg = $"{path}.{removed}: {FormatValue(removedVal)} -> (removed)";
                        lines.Add(new DiffLine { Type = DiffLineType.Deletion, Text = msg });
                        sb.AppendLine($"-{msg}");
                    }
                }
                break;

            case JsonValueKind.Array:
                var oldArr = old.EnumerateArray().ToList();
                var newArr = newEl.EnumerateArray().ToList();
                int max = Math.Max(oldArr.Count, newArr.Count);
                for (int i = 0; i < max; i++)
                {
                    string idxPath = $"{path}[{i}]";
                    if (i >= oldArr.Count)
                    {
                        string msg = $"{idxPath}: (added) -> {FormatValue(newArr[i])}";
                        lines.Add(new DiffLine { Type = DiffLineType.Addition, Text = msg });
                        sb.AppendLine($"+{msg}");
                    }
                    else if (i >= newArr.Count)
                    {
                        string msg = $"{idxPath}: {FormatValue(oldArr[i])} -> (removed)";
                        lines.Add(new DiffLine { Type = DiffLineType.Deletion, Text = msg });
                        sb.AppendLine($"-{msg}");
                    }
                    else
                    {
                        CompareElements(oldArr[i], newArr[i], idxPath, lines, sb);
                    }
                }
                break;

            default:
                if (old.ToString() != newEl.ToString())
                {
                    string msg = $"{path}: {FormatValue(old)} -> {FormatValue(newEl)}";
                    lines.Add(new DiffLine { Type = DiffLineType.Deletion, Text = msg });
                    sb.AppendLine($"-{msg}");
                    lines.Add(new DiffLine { Type = DiffLineType.Addition, Text = msg });
                    sb.AppendLine($"+{msg}");
                }
                break;
        }
    }

    private static string FormatValue(JsonElement el) => el.ValueKind switch
    {
        JsonValueKind.String => $"\"{el.GetString()}\"",
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        JsonValueKind.Null => "null",
        JsonValueKind.Number => el.GetRawText(),
        _ => el.GetRawText(),
    };
}
