using System.Windows.Media;
using RDRF.Core.Diff;

namespace RDRF.App.ViewModels;

public class SideBySideDiffLine
{
    public DiffLineType Type { get; }
    public string OldLine { get; }
    public string NewLine { get; }
    public int OldLineNumber { get; }
    public int NewLineNumber { get; }
    public bool IsOldLine => !string.IsNullOrEmpty(OldLine);
    public bool IsNewLine => !string.IsNullOrEmpty(NewLine);
    public string LineNumbers { get; }

    public SolidColorBrush OldBackground { get; }
    public SolidColorBrush NewBackground { get; }
    public SolidColorBrush OldForeground { get; }
    public SolidColorBrush NewForeground { get; }

    private static readonly SolidColorBrush Transparent = new(Color.FromArgb(0, 0, 0, 0));
    private static readonly SolidColorBrush DeletionBg = new(Color.FromArgb(0x18, 0xFF, 0x55, 0x55));
    private static readonly SolidColorBrush AdditionBg = new(Color.FromArgb(0x18, 0x50, 0xFA, 0x7B));
    private static readonly SolidColorBrush HeaderBg = new(Color.FromArgb(0x18, 0xAA, 0xAA, 0xCC));

    public SideBySideDiffLine(DiffLineType type, string oldLine, string newLine,
        int oldLineNumber = 0, int newLineNumber = 0)
    {
        Type = type;
        OldLine = oldLine;
        NewLine = newLine;
        OldLineNumber = oldLineNumber;
        NewLineNumber = newLineNumber;

        LineNumbers = IsOldLine && IsNewLine
            ? $"{OldLineNumber,4} | {NewLineNumber,-4}"
            : IsOldLine
                ? $"{OldLineNumber,4} |"
                : $"     | {NewLineNumber,-4}";

        OldBackground = type switch
        {
            DiffLineType.Deletion => DeletionBg,
            DiffLineType.Header => HeaderBg,
            _ => Transparent,
        };
        NewBackground = type switch
        {
            DiffLineType.Addition => AdditionBg,
            DiffLineType.Header => HeaderBg,
            _ => Transparent,
        };
        OldForeground = type switch
        {
            DiffLineType.Deletion => new SolidColorBrush(Color.FromRgb(0xFF, 0x55, 0x55)),
            DiffLineType.Header => new SolidColorBrush(Color.FromRgb(0xBB, 0x88, 0xFF)),
            _ => new SolidColorBrush(Color.FromRgb(0xE0, 0xE0, 0xE8)),
        };
        NewForeground = type switch
        {
            DiffLineType.Addition => new SolidColorBrush(Color.FromRgb(0x50, 0xFA, 0x7B)),
            DiffLineType.Header => new SolidColorBrush(Color.FromRgb(0xBB, 0x88, 0xFF)),
            _ => new SolidColorBrush(Color.FromRgb(0xE0, 0xE0, 0xE8)),
        };
    }
}
