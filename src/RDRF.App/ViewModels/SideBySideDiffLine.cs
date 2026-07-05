using System.Windows.Media;
using RDRF.Core.Diff;

namespace RDRF.App.ViewModels;

/// <summary>
/// Diff line model for WPF side-by-side view with color brushes.
/// </summary>
public class SideBySideDiffLine
{
    public DiffLineType Type { get; }
    public string OldText { get; }
    public string NewText { get; }
    public int OldLineNumber { get; }
    public int NewLineNumber { get; }
    public string OldNumberDisplay { get; }
    public string NewNumberDisplay { get; }
    public bool HasOld => OldLineNumber > 0;
    public bool HasNew => NewLineNumber > 0;

    public SolidColorBrush OldBg { get; }
    public SolidColorBrush NewBg { get; }
    public SolidColorBrush OldFg { get; }
    public SolidColorBrush NewFg { get; }
    public SolidColorBrush NumberFg { get; }

    private static readonly SolidColorBrush Transparent = new(Color.FromArgb(0, 0, 0, 0));
    private static readonly SolidColorBrush DelBg = new(Color.FromArgb(0x18, 0xFF, 0x55, 0x55));
    private static readonly SolidColorBrush AddBg = new(Color.FromArgb(0x18, 0x50, 0xFA, 0x7B));
    private static readonly SolidColorBrush HdrBg = new(Color.FromArgb(0x18, 0xAA, 0xAA, 0xCC));
    private static readonly SolidColorBrush Red = new(Color.FromRgb(0xFF, 0x55, 0x55));
    private static readonly SolidColorBrush Green = new(Color.FromRgb(0x50, 0xFA, 0x7B));
    private static readonly SolidColorBrush Purple = new(Color.FromRgb(0xBB, 0x88, 0xFF));
    private static readonly SolidColorBrush Light = new(Color.FromRgb(0xE0, 0xE0, 0xE8));
    private static readonly SolidColorBrush Dim = new(Color.FromRgb(0x66, 0x66, 0x66));

    public SideBySideDiffLine(DiffLineType type, string oldText, string newText,
        int oldLineNumber = 0, int newLineNumber = 0)
    {
        Type = type;
        OldText = oldText;
        NewText = newText;
        OldLineNumber = oldLineNumber;
        NewLineNumber = newLineNumber;
        OldNumberDisplay = oldLineNumber > 0 ? oldLineNumber.ToString() : "";
        NewNumberDisplay = newLineNumber > 0 ? newLineNumber.ToString() : "";

        NumberFg = Dim;
        OldBg = type == DiffLineType.Deletion ? DelBg : type == DiffLineType.Header ? HdrBg : Transparent;
        NewBg = type == DiffLineType.Addition ? AddBg : type == DiffLineType.Header ? HdrBg : Transparent;
        OldFg = type == DiffLineType.Deletion ? Red : type == DiffLineType.Header ? Purple : Light;
        NewFg = type == DiffLineType.Addition ? Green : type == DiffLineType.Header ? Purple : Light;
    }
}


