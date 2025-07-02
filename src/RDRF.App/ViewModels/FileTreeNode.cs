using System.Collections.ObjectModel;
using System.Windows.Media;

namespace RDRF.App.ViewModels;

public class FileTreeNode
{
    public string Name { get; set; } = string.Empty;
    public string FullPath { get; set; } = string.Empty;
    public bool IsDirectory { get; set; }
    public string ChangeType { get; set; } = "unchanged";
    public string Diff { get; set; } = string.Empty;
    public ObservableCollection<FileTreeNode> Children { get; } = new();
    public bool IsExpanded { get; set; } = true;

    public SolidColorBrush ChangeColor => ChangeType switch
    {
        "added" => new SolidColorBrush(Color.FromRgb(0x50, 0xFA, 0x7B)),
        "modified" => new SolidColorBrush(Color.FromRgb(0xFF, 0xB8, 0x4D)),
        "modified (binary)" => new SolidColorBrush(Color.FromRgb(0xFF, 0xB8, 0x4D)),
        "deleted" => new SolidColorBrush(Color.FromRgb(0xFF, 0x55, 0x55)),
        _ => new SolidColorBrush(Color.FromRgb(0x88, 0x88, 0x88)),
    };

    public string ChangeGlyph => ChangeType switch
    {
        "added" => "[+]",
        "modified" or "modified (binary)" => "[*]",
        "deleted" => "[-]",
        _ => "[ ]",
    };

    public string Icon => IsDirectory ? "\U0001F4C1" : "\U0001F4C4";
}
