using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Media;

namespace RDRF.App.ViewModels;

public enum DiffLineType
{
    Header,
    Context,
    Addition,
    Deletion
}

public class DiffLineItem : INotifyPropertyChanged
{
    public DiffLineType Type { get; }
    public string Text { get; }
    public Brush Foreground { get; }
    public Brush Background { get; }

    public DiffLineItem(DiffLineType type, string text)
    {
        Type = type;
        Text = text;
        Foreground = type switch
        {
            DiffLineType.Header => new SolidColorBrush(Color.FromRgb(0x7C, 0x6B, 0xF2)),
            DiffLineType.Addition => new SolidColorBrush(Color.FromRgb(0x50, 0xFA, 0x7B)),
            DiffLineType.Deletion => new SolidColorBrush(Color.FromRgb(0xFF, 0x55, 0x55)),
            _ => new SolidColorBrush(Color.FromRgb(0xE0, 0xE0, 0xE8)),
        };
        Background = type switch
        {
            DiffLineType.Header => new SolidColorBrush(Color.FromArgb(0x20, 0x7C, 0x6B, 0xF2)),
            DiffLineType.Addition => new SolidColorBrush(Color.FromArgb(0x15, 0x50, 0xFA, 0x7B)),
            DiffLineType.Deletion => new SolidColorBrush(Color.FromArgb(0x15, 0xFF, 0x55, 0x55)),
            _ => Brushes.Transparent,
        };
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
