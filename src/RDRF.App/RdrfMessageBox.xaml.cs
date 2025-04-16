using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace RDRF.App;

public partial class RdrfMessageBox : Window
{
    public enum DialogIcon
    {
        Info,
        Success,
        Warning,
        Error
    }

    private RdrfMessageBox()
    {
        InitializeComponent();
        Owner = Application.Current.MainWindow;
    }

    public static void Show(
        string message,
        string title = "RDRF",
        DialogIcon icon = DialogIcon.Info,
        string? extraInfo = null)
    {
        var dialog = new RdrfMessageBox
        {
            DialogTitle = { Text = title },
            DialogMessage = { Text = message }
        };

        switch (icon)
        {
            case DialogIcon.Success:
                dialog.TitleIcon.Text = "\u2713";
                dialog.TitleIcon.Foreground = new SolidColorBrush(Color.FromRgb(0x50, 0xFA, 0x7B));
                break;
            case DialogIcon.Error:
                dialog.TitleIcon.Text = "\u2717";
                dialog.TitleIcon.Foreground = new SolidColorBrush(Color.FromRgb(0xFF, 0x55, 0x55));
                break;
            case DialogIcon.Warning:
                dialog.TitleIcon.Text = "\u26A0";
                dialog.TitleIcon.Foreground = new SolidColorBrush(Color.FromRgb(0xFF, 0xB8, 0x6C));
                break;
            case DialogIcon.Info:
                dialog.TitleIcon.Text = "\u2139";
                dialog.TitleIcon.Foreground = new SolidColorBrush(Color.FromRgb(0x7C, 0x6B, 0xF2));
                break;
        }

        if (!string.IsNullOrEmpty(extraInfo))
        {
            dialog.ExtraInfoBorder.Visibility = Visibility.Visible;
            dialog.ExtraInfoText.Text = extraInfo;
        }

        dialog.ShowDialog();
    }

    private void OkButton_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
        Close();
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void CopyButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(ExtraInfoText.Text);
            CopyButton.Content = "Copied!";
        }
        catch
        {
            CopyButton.Content = "Failed";
        }
    }
}
