using System.Text;

namespace RDRF.Core.Diff.Strategies;

public class IniDiffStrategy : IDiffStrategy
{
    public string Name => "ini";

    private static readonly HashSet<string> _iniExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ini", ".cfg", ".conf", ".editorconfig", ".gitconfig", ".gitattributes", ".gitmodules",
    };

    public double MatchScore(string? fileName, ReadOnlySpan<byte> sample)
    {
        if (!string.IsNullOrEmpty(fileName))
        {
            string ext = Path.GetExtension(fileName);
            if (!string.IsNullOrEmpty(ext) && _iniExtensions.Contains(ext))
                return 1.0;
        }

        if (sample.Length == 0) return 0;

        int end = Math.Min(sample.Length, 512);
        for (int i = 0; i < end; i++)
        {
            if (sample[i] == (byte)'\n')
            {
                string firstLine = Encoding.UTF8.GetString(sample[0..i]).Trim();
                if (firstLine.StartsWith('[') && firstLine.Contains(']'))
                    return 0.8;
                break;
            }
        }

        return 0;
    }

    public DiffResult ComputeDiff(byte[] oldData, byte[] newData, string? label)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"--- a/{label ?? "file"} (ini)");
        sb.AppendLine($"+++ b/{label ?? "file"} (ini)");

        var lines = new List<DiffLine>();
        long addedBytes = Math.Max(0, newData.LongLength - oldData.LongLength);
        long removedBytes = Math.Max(0, oldData.LongLength - newData.LongLength);

        var oldIni = ParseIni(oldData);
        var newIni = ParseIni(newData);
        var allSections = new HashSet<string>();
        foreach (var k in oldIni.Keys) allSections.Add(k);
        foreach (var k in newIni.Keys) allSections.Add(k);

        foreach (var section in allSections.OrderBy(s => s == "" ? 0 : 1).ThenBy(s => s))
        {
            oldIni.TryGetValue(section, out var oldKeys);
            newIni.TryGetValue(section, out var newKeys);

            oldKeys ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            newKeys ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            if (oldKeys.Count == 0 && newKeys.Count > 0)
            {
                string msg = $"[{section}] (section added)";
                lines.Add(new DiffLine { Type = DiffLineType.Header, Text = msg });
                sb.AppendLine(msg);
            }
            else if (oldKeys.Count > 0 && newKeys.Count == 0)
            {
                string msg = $"[{section}] (section removed)";
                lines.Add(new DiffLine { Type = DiffLineType.Header, Text = msg });
                sb.AppendLine(msg);
            }

            var allKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var k in oldKeys.Keys) allKeys.Add(k);
            foreach (var k in newKeys.Keys) allKeys.Add(k);

            foreach (var key in allKeys.OrderBy(k => k))
            {
                bool hasOld = oldKeys.TryGetValue(key, out var oldVal);
                bool hasNew = newKeys.TryGetValue(key, out var newVal);

                if (hasOld && hasNew)
                {
                    if (oldVal != newVal)
                    {
                        string msg = $"  {key} = {oldVal}  ->  {newVal}";
                        lines.Add(new DiffLine { Type = DiffLineType.Deletion, Text = msg });
                        sb.AppendLine($"-{msg}");
                    }
                }
                else if (hasNew)
                {
                    string msg = $"  {key} = {newVal}  (added)";
                    lines.Add(new DiffLine { Type = DiffLineType.Addition, Text = msg });
                    sb.AppendLine($"+{msg}");
                }
                else
                {
                    string msg = $"  {key} = {oldVal}  (removed)";
                    lines.Add(new DiffLine { Type = DiffLineType.Deletion, Text = msg });
                    sb.AppendLine($"-{msg}");
                }
            }
        }

        return new DiffResult
        {
            Label = label,
            IsBinary = false,
            AddedBytes = addedBytes,
            RemovedBytes = removedBytes,
            Lines = lines,
            HumanDiff = sb.ToString(),
            DetectedFileType = "ini",
            OriginalSize = oldData.LongLength,
            ChangeRatio = oldData.Length > 0
                ? (double)(Math.Abs(newData.Length - oldData.Length)) / oldData.Length
                : 0,
        };
    }

    private static Dictionary<string, Dictionary<string, string>> ParseIni(byte[] data)
    {
        var result = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        string currentSection = "";
        result[currentSection] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        int offset = data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF ? 3 : 0;
        var text = Encoding.UTF8.GetString(data, offset, data.Length - offset);
        foreach (string raw in text.Split('\n'))
        {
            string line = raw.TrimEnd('\r');

            // Only treat ; or # as comment markers when they appear at the start
            // of a token (preceded only by whitespace), not inside values.
            int commentIdx = -1;
            for (int i = 0; i < line.Length; i++)
            {
                if ((line[i] == ';' || line[i] == '#') && (i == 0 || char.IsWhiteSpace(line[i - 1])))
                {
                    commentIdx = i;
                    break;
                }
            }
            if (commentIdx >= 0)
                line = line[..commentIdx];

            line = line.Trim();
            if (line.Length == 0) continue;

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                currentSection = line[1..^1].Trim();
                if (!result.ContainsKey(currentSection))
                    result[currentSection] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            }
            else
            {
                int eqIdx = line.IndexOf('=');
                if (eqIdx > 0)
                {
                    string key = line[..eqIdx].Trim();
                    string val = line[(eqIdx + 1)..].Trim();
                    result[currentSection][key] = val;
                }
            }
        }

        return result;
    }
}
