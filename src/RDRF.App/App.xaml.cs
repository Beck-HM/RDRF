using System.IO;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using RDRF.App.Services;
using RDRF.App.ViewModels;
using RDRF.Core.Composition;

namespace RDRF.App;

public partial class App : Application
{
    internal static ServiceProvider Services { get; private set; } = null!;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var services = new ServiceCollection();
        services.AddRdrfCore();
        services.AddTransient<IEncryptService, EncryptService>();
        services.AddTransient<IDecryptService, DecryptService>();
        services.AddTransient<EncryptViewModel>();
        services.AddTransient<DecryptViewModel>();
        services.AddTransient<HistoryViewModel>();
        services.AddTransient<SettingsViewModel>();
        services.AddTransient<MainWindow>();
        Services = services.BuildServiceProvider();

        var mainWindow = Services.GetRequiredService<MainWindow>();
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
