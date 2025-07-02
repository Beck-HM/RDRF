using System.Collections;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using RDRF.App.ViewModels;
using RDRF.Core.Diff;

namespace RDRF.App.Controls;

public partial class SideBySideDiffView : UserControl
{
    public static readonly DependencyProperty ItemsSourceProperty =
        DependencyProperty.Register(nameof(ItemsSource), typeof(IEnumerable),
            typeof(SideBySideDiffView),
            new PropertyMetadata(null, OnItemsSourceChanged));

    public static readonly DependencyProperty FileTreeSourceProperty =
        DependencyProperty.Register(nameof(FileTreeSource), typeof(IEnumerable),
            typeof(SideBySideDiffView),
            new PropertyMetadata(null));

    public IEnumerable? ItemsSource
    {
        get => (IEnumerable?)GetValue(ItemsSourceProperty);
        set => SetValue(ItemsSourceProperty, value);
    }

    public IEnumerable? FileTreeSource
    {
        get => (IEnumerable?)GetValue(FileTreeSourceProperty);
        set => SetValue(FileTreeSourceProperty, value);
    }

    public SideBySideDiffView()
    {
        InitializeComponent();
    }

    private static void OnItemsSourceChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is SideBySideDiffView view && e.NewValue is IEnumerable items)
            view.DiffItems.ItemsSource = items;
    }

    private void OnFileTreeSelectionChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (e.NewValue is FileTreeNode node && !node.IsDirectory && !string.IsNullOrEmpty(node.Diff))
        {
            var lines = ParseSideBySide(node.Diff);
            DiffItems.ItemsSource = lines;
        }
    }

    public static List<SideBySideDiffLine> ParseSideBySide(string diff)
    {
        var result = new List<SideBySideDiffLine>();
        int oldNum = 0;
        int newNum = 0;

        foreach (string rawLine in diff.Split('\n'))
        {
            if (string.IsNullOrEmpty(rawLine))
                continue;

            if (rawLine.StartsWith("--- ") || rawLine.StartsWith("+++ "))
                continue;

            if (rawLine.StartsWith("@@"))
            {
                int start = rawLine.IndexOf("@@ ", StringComparison.Ordinal) + 3;
                int end = rawLine.LastIndexOf(" @@", StringComparison.Ordinal);
                string content = start > 2 && end > start
                    ? rawLine[start..end]
                    : rawLine.Trim('@', ' ');

                var parts = content.Split(' ');
                if (parts.Length >= 2)
                {
                    int.TryParse(parts[0].TrimStart('-'), out oldNum);
                    if (parts.Length >= 2)
                        int.TryParse(parts[1].TrimStart('+'), out newNum);
                    if (oldNum > 0) oldNum--;
                    if (newNum > 0) newNum--;
                }

                result.Add(new SideBySideDiffLine(DiffLineType.Header,
                    rawLine, rawLine, oldNum, newNum));
            }
            else if (rawLine.StartsWith('-'))
            {
                oldNum++;
                result.Add(new SideBySideDiffLine(DiffLineType.Deletion,
                    rawLine, "", oldNum, 0));
            }
            else if (rawLine.StartsWith('+'))
            {
                newNum++;
                result.Add(new SideBySideDiffLine(DiffLineType.Addition,
                    "", rawLine, 0, newNum));
            }
            else if (rawLine.StartsWith(' '))
            {
                oldNum++;
                newNum++;
                result.Add(new SideBySideDiffLine(DiffLineType.Context,
                    rawLine, rawLine, oldNum, newNum));
            }
        }

        return result;
    }
}
