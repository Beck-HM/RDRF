using System.IO;
using System.Windows;

namespace RDRF.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var mainWindow = new MainWindow();
        if (e.Args.Length > 0)
        {
            string path = e.Args[0];
            if (File.Exists(path) &&
                path.EndsWith(".indrdrf", System.StringComparison.OrdinalIgnoreCase))
            {
                mainWindow.LoadIndexFile(path);
            }
        }
        mainWindow.Show();
    }
}
