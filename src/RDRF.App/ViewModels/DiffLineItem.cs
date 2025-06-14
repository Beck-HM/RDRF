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
    public double FontSize { get; }
    public double FontWeight { get; }

    public DiffLineItem(DiffLineType type, string text)
    {
        Type = type;
        Text = text;
        FontSize = type switch
        {
            DiffLineType.Header => 15,
            DiffLineType.Addition => 13,
            DiffLineType.Deletion => 13,
            _ => 12,
        };
        FontWeight = type == DiffLineType.Header ? 700 : 400;
        Foreground = type switch
        {
            DiffLineType.Addition => new SolidColorBrush(Color.FromRgb(0x50, 0xFA, 0x7B)),
            DiffLineType.Deletion => new SolidColorBrush(Color.FromRgb(0xFF, 0x55, 0x55)),
            _ => new SolidColorBrush(Color.FromRgb(0xE0, 0xE0, 0xE8)),
        };
        Background = type switch
        {
            DiffLineType.Addition => new SolidColorBrush(Color.FromArgb(0x18, 0x50, 0xFA, 0x7B)),
            DiffLineType.Deletion => new SolidColorBrush(Color.FromArgb(0x18, 0xFF, 0x55, 0x55)),
            _ => Brushes.Transparent,
        };
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
