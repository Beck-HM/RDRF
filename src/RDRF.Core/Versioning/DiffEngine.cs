using System.Text;

namespace RDRF.Core.Versioning;

public static class DiffEngine
{
    public static (string HumanDiff, long AddedBytes, long RemovedBytes)
        ComputeDiff(byte[] oldData, byte[] newData)
    {
        long addedBytes = Math.Max(0, newData.LongLength - oldData.LongLength);
        long removedBytes = Math.Max(0, oldData.LongLength - newData.LongLength);

        bool oldIsText = IsLikelyText(oldData);
        bool newIsText = IsLikelyText(newData);

        if (oldIsText && newIsText)
            return (ComputeTextDiff(oldData, newData), addedBytes, removedBytes);

        var sb = new StringBuilder();
        sb.AppendLine($"--- (binary)");
        sb.AppendLine($"+++ (binary)");
        sb.AppendLine($"@@ size change @@");
        if (oldData.LongLength == newData.LongLength)
            sb.AppendLine($" File size unchanged: {oldData.Length} bytes");
        else
            sb.AppendLine($" Old size: {oldData.Length} bytes → New size: {newData.Length} bytes");
        return (sb.ToString(), addedBytes, removedBytes);
    }

    private static bool IsLikelyText(byte[] data)
    {
        if (data.Length == 0) return true;
        int nonText = 0;
        int sample = Math.Min(data.Length, 1024);
        for (int i = 0; i < sample; i++)
        {
            byte b = data[i];
            if (b == 0) return false;
            if (b < 0x09 || (b > 0x0D && b < 0x20))
                nonText++;
        }
        return nonText <= sample / 10;
    }

    private static string ComputeTextDiff(byte[] oldData, byte[] newData)
    {
        var oldLines = SplitLines(oldData);
        var newLines = SplitLines(newData);
        var edits = ComputeLineEdits(oldLines, newLines);
        return FormatUnifiedDiff(oldLines, newLines, edits);
    }

    private static List<string> SplitLines(byte[] data)
    {
        var lines = new List<string>();
        int start = 0;
        for (int i = 0; i < data.Length; i++)
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
        // Find common prefix
        int prefixLen = 0;
        while (prefixLen < oldLines.Count && prefixLen < newLines.Count
               && oldLines[prefixLen] == newLines[prefixLen])
            prefixLen++;

        // Find common suffix (after removing prefix)
        int suffixLen = 0;
        while (suffixLen < oldLines.Count - prefixLen && suffixLen < newLines.Count - prefixLen
               && oldLines[oldLines.Count - 1 - suffixLen] == newLines[newLines.Count - 1 - suffixLen])
            suffixLen++;

        var edits = new List<EditOp>();
        int pos = 0;

        // Equal prefix context (show up to 3 lines)
        int ctxStart = Math.Max(0, prefixLen - 3);
        for (int i = ctxStart; i < prefixLen; i++)
        {
            edits.Add(new EditOp { Kind = EditKind.Keep, OldLine = oldLines[i], NewLine = newLines[i] });
            pos++;
        }

        // Changed middle section
        int oldMid = prefixLen;
        int newMid = prefixLen;
        int oldMidEnd = oldLines.Count - suffixLen;
        int newMidEnd = newLines.Count - suffixLen;

        // Hash new lines for matching
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
                // Ensure ni catches up if needed
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

        // Equal suffix context
        int suffixCtxEnd = Math.Min(oldLines.Count, oldLines.Count - suffixLen + 3);
        for (int i = oldLines.Count - suffixLen; i < suffixCtxEnd && i < oldLines.Count; i++)
        {
            int newIdx = newLines.Count - suffixLen + (i - (oldLines.Count - suffixLen));
            edits.Add(new EditOp { Kind = EditKind.Keep, OldLine = oldLines[i], NewLine = newIdx < newLines.Count ? newLines[newIdx] : "" });
        }

        return edits;
    }

    private static string FormatUnifiedDiff(List<string> oldLines, List<string> newLines, List<EditOp> edits)
    {
        var sb = new StringBuilder();
        sb.AppendLine("--- a/backup");
        sb.AppendLine("+++ b/backup");

        var batches = new List<List<EditOp>>();
        List<EditOp>? current = null;

        foreach (var edit in edits)
        {
            if (edit.Kind == EditKind.Keep)
            {
                // Start a new batch for context keeps
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

            sb.AppendLine($"@@ -{delCount + keepCount} +{insCount + keepCount} @@");
            foreach (var edit in batch)
            {
                switch (edit.Kind)
                {
                    case EditKind.Keep: sb.AppendLine($" {edit.OldLine}"); break;
                    case EditKind.Delete: sb.AppendLine($"-{edit.OldLine}"); break;
                    case EditKind.Insert: sb.AppendLine($"+{edit.NewLine}"); break;
                }
            }
        }

        return sb.ToString();
    }

    private enum EditKind { Keep, Delete, Insert }

    private class EditOp
    {
        public EditKind Kind { get; set; }
        public string OldLine { get; set; } = "";
        public string NewLine { get; set; } = "";
    }
}
