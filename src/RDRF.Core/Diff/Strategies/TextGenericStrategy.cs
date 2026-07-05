using System.Text;

namespace RDRF.Core.Diff.Strategies;

/// <summary>
/// Line-based text diff with LCS-like matching and unified output.
/// </summary>

public class TextGenericStrategy : IDiffStrategy
{
    public string Name => "text_generic";

    private static readonly HashSet<string> _textExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        // Code
        ".cs", ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".cpp", ".h", ".hpp",
        ".c", ".rs", ".go", ".rb", ".php", ".swift", ".kt", ".scala", ".dart",
        ".lua", ".r", ".m", ".mm", ".pl", ".pm", ".sh", ".bash", ".zsh", ".ps1",
        ".fs", ".fsx", ".clj", ".groovy", ".sql", ".rkt", ".sml",
        // Web
        ".html", ".htm", ".css", ".scss", ".less", ".vue", ".svelte",
        // Config / data
        ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
        ".gitignore", ".dockerignore", ".editorconfig", ".env",
        // Doc
        ".md", ".markdown", ".txt", ".rst", ".tex", ".bib",
        // Data
        ".csv", ".tsv", ".log",
        // Build
        ".cmake", ".makefile", ".gradle", ".sln", ".csproj", ".fsproj",
    };

    public double MatchScore(string? fileName, ReadOnlySpan<byte> sample)
    {
        if (!string.IsNullOrEmpty(fileName))
        {
            string ext = Path.GetExtension(fileName);
            if (!string.IsNullOrEmpty(ext) && _textExtensions.Contains(ext))
                return 1.0;
        }

        if (sample.Length == 0) return 0.9;

        bool hasNull = false;
        int nonText = 0;
        int len = Math.Min(sample.Length, 1024);
        for (int i = 0; i < len; i++)
        {
            byte b = sample[i];
            if (b == 0) hasNull = true;
            else if (b < 0x09 || (b > 0x0D && b < 0x20))
                nonText++;
        }

        if (hasNull) return 0;
        return nonText <= len / 10 ? 0.9 : 0;
    }

    public DiffResult ComputeDiff(byte[] oldData, byte[] newData, string? label)
    {
        var oldLines = SplitLines(oldData);
        var newLines = SplitLines(newData);
        var edits = ComputeLineEdits(oldLines, newLines);

        int addedLines = edits.Count(e => e.Kind == EditKind.Insert);
        int removedLines = edits.Count(e => e.Kind == EditKind.Delete);
        int changedLines = Math.Max(addedLines, removedLines);
        long addedBytes = Math.Max(0, newData.LongLength - oldData.LongLength);
        long removedBytes = Math.Max(0, oldData.LongLength - newData.LongLength);

        var lines = new List<DiffLine>();
        var sb = new StringBuilder();
        sb.AppendLine($"--- a/{label ?? "file"}");
        sb.AppendLine($"+++ b/{label ?? "file"}");

        var batches = new List<List<EditOp>>();
        List<EditOp>? current = null;

        foreach (var edit in edits)
        {
            if (edit.Kind == EditKind.Keep)
            {
                if (current == null || current.Last().Kind != EditKind.Keep)
                {
                    current = new List<EditOp>();
                    batches.Add(current);
                }
                current.Add(edit);
            }
            else
            {
                if (current == null || current.Last().Kind == EditKind.Keep)
                {
                    current = new List<EditOp>();
                    batches.Add(current);
                }
                current.Add(edit);
            }
        }

        foreach (var batch in batches)
        {
            if (batch.All(e => e.Kind == EditKind.Keep) && batch.Count <= 2)
                continue;

            int delCount = batch.Count(e => e.Kind == EditKind.Delete);
            int insCount = batch.Count(e => e.Kind == EditKind.Insert);
            int keepCount = batch.Count(e => e.Kind == EditKind.Keep);

            lines.Add(new DiffLine { Type = DiffLineType.Header, Text = $"@@ -{delCount + keepCount} +{insCount + keepCount} @@" });
            sb.AppendLine($"@@ -{delCount + keepCount} +{insCount + keepCount} @@");

            foreach (var edit in batch)
            {
                switch (edit.Kind)
                {
                    case EditKind.Keep:
                        lines.Add(new DiffLine { Type = DiffLineType.Context, Text = edit.OldLine });
                        sb.AppendLine($" {edit.OldLine}");
                        break;
                    case EditKind.Delete:
                        lines.Add(new DiffLine { Type = DiffLineType.Deletion, Text = edit.OldLine });
                        sb.AppendLine($"-{edit.OldLine}");
                        break;
                    case EditKind.Insert:
                        lines.Add(new DiffLine { Type = DiffLineType.Addition, Text = edit.NewLine });
                        sb.AppendLine($"+{edit.NewLine}");
                        break;
                }
            }
        }

        return new DiffResult
        {
            Label = label,
            IsBinary = false,
            AddedBytes = addedBytes,
            RemovedBytes = removedBytes,
            AddedLines = addedLines,
            RemovedLines = removedLines,
            ChangedLines = changedLines,
            Lines = lines,
            HumanDiff = sb.ToString(),
            DetectedFileType = "text",
            OriginalSize = oldData.LongLength,
            ChangeRatio = oldData.Length > 0
                ? (double)(Math.Abs(newData.Length - oldData.Length)) / oldData.Length
                : 0,
        };
    }

    private static List<string> SplitLines(byte[] data)
    {
        var lines = new List<string>();
        int start = 0;
        if (data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF)
            start = 3;
        for (int i = start; i < data.Length; i++)
        {
            if (data[i] == '\n')
            {
                int end = i > 0 && data[i - 1] == '\r' ? i - 1 : i;
                lines.Add(Encoding.UTF8.GetString(data, start, end - start));
                start = i + 1;
            }
        }
        if (start < data.Length)
            lines.Add(Encoding.UTF8.GetString(data, start, data.Length - start));
        return lines;
    }

    private static List<EditOp> ComputeLineEdits(List<string> oldLines, List<string> newLines)
    {
        int prefixLen = 0;
        while (prefixLen < oldLines.Count && prefixLen < newLines.Count
               && oldLines[prefixLen] == newLines[prefixLen])
            prefixLen++;

        int suffixLen = 0;
        while (suffixLen < oldLines.Count - prefixLen && suffixLen < newLines.Count - prefixLen
               && oldLines[oldLines.Count - 1 - suffixLen] == newLines[newLines.Count - 1 - suffixLen])
            suffixLen++;

        var edits = new List<EditOp>();
        int pos = 0;

        int ctxStart = Math.Max(0, prefixLen - 3);
        for (int i = ctxStart; i < prefixLen; i++)
        {
            edits.Add(new EditOp { Kind = EditKind.Keep, OldLine = oldLines[i], NewLine = newLines[i] });
            pos++;
        }

        int oldMid = prefixLen;
        int newMid = prefixLen;
        int oldMidEnd = oldLines.Count - suffixLen;
        int newMidEnd = newLines.Count - suffixLen;

        var newLineMap = new Dictionary<string, List<int>>();
        for (int i = newMid; i < newMidEnd; i++)
        {
            if (!newLineMap.ContainsKey(newLines[i]))
                newLineMap[newLines[i]] = new List<int>();
            newLineMap[newLines[i]].Add(i);
        }

        var oldToNew = new Dictionary<int, int>();
        var usedNew = new HashSet<int>();
        for (int i = oldMid; i < oldMidEnd; i++)
        {
            if (newLineMap.TryGetValue(oldLines[i], out var indices))
            {
                foreach (int j in indices)
                {
                    if (!usedNew.Contains(j) && !oldToNew.ContainsValue(j))
                    {
                        oldToNew[i] = j;
                        usedNew.Add(j);
                        break;
                    }
                }
            }
        }

        var result = new List<(EditKind Kind, int OldIdx, int NewIdx)>();
        int oi = oldMid;
        int ni = newMid;
        while (oi < oldMidEnd || ni < newMidEnd)
        {
            if (oi < oldMidEnd && !oldToNew.ContainsKey(oi))
            {
                result.Add((EditKind.Delete, oi, -1));
                oi++;
            }
            else if (ni < newMidEnd && !usedNew.Contains(ni))
            {
                result.Add((EditKind.Insert, -1, ni));
                ni++;
            }
            else if (oi < oldMidEnd && oldToNew.TryGetValue(oi, out int matched))
            {
                result.Add((EditKind.Keep, oi, matched));
                oi++;
                while (ni < matched && !usedNew.Contains(ni))
                {
                    result.Add((EditKind.Insert, -1, ni));
                    ni++;
                }
                if (ni == matched) ni = matched + 1;
            }
            else
            {
                break;
            }
        }

        foreach (var r in result)
        {
            switch (r.Kind)
            {
                case EditKind.Keep:
                    edits.Add(new EditOp { Kind = EditKind.Keep, OldLine = oldLines[r.OldIdx], NewLine = newLines[r.NewIdx] });
                    pos++;
                    break;
                case EditKind.Delete:
                    edits.Add(new EditOp { Kind = EditKind.Delete, OldLine = oldLines[r.OldIdx] });
                    break;
                case EditKind.Insert:
                    edits.Add(new EditOp { Kind = EditKind.Insert, NewLine = newLines[r.NewIdx] });
                    break;
            }
        }

        int suffixCtxEnd = Math.Min(oldLines.Count, oldLines.Count - suffixLen + 3);
        for (int i = oldLines.Count - suffixLen; i < suffixCtxEnd && i < oldLines.Count; i++)
        {
            int newIdx = newLines.Count - suffixLen + (i - (oldLines.Count - suffixLen));
            edits.Add(new EditOp { Kind = EditKind.Keep, OldLine = oldLines[i], NewLine = newIdx < newLines.Count ? newLines[newIdx] : "" });
        }

        return edits;
    }

    private enum EditKind { Keep, Delete, Insert }

    private class EditOp
    {
        public EditKind Kind { get; set; }
        public string OldLine { get; set; } = "";
        public string NewLine { get; set; } = "";
    }
}

