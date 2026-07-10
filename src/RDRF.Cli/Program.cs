using Microsoft.Extensions.DependencyInjection;
using RDRF.Cli.Commands;
using RDRF.Core.Composition;
using System.CommandLine;
using System.Globalization;

class Program
{
    static async Task<int> Main(string[] args)
    {
        CultureInfo.DefaultThreadCurrentUICulture = new CultureInfo("en-US");

        var services = new ServiceCollection();
        services.AddRdrfCore();
        services.AddTransient<BackupCommand>();
        services.AddTransient<RestoreCommand>();
        services.AddTransient<InfoCommand>();
        services.AddTransient<VerifyCommand>();
        services.AddTransient<StatusCommand>();
        services.AddTransient<NextCommand>();
        services.AddTransient<CheckCommand>();
        services.AddTransient<DiffCommand>();
        services.AddTransient<InitCommand>();
        services.AddTransient<ListCommand>();
        services.AddTransient<RemoveBackendCommand>();
        services.AddTransient<ResetCommand>();
        services.AddTransient<RemoteCommand>();
        services.AddTransient<PushCommand>();
        services.AddTransient<PullCommand>();

        using var provider = services.BuildServiceProvider();

        var root = new RootCommand("RDRF - Redundant Distributed Recovery File");
        root.Subcommands.Add(provider.GetRequiredService<BackupCommand>());
        root.Subcommands.Add(provider.GetRequiredService<RestoreCommand>());
        root.Subcommands.Add(provider.GetRequiredService<InfoCommand>());
        root.Subcommands.Add(provider.GetRequiredService<VerifyCommand>());
        root.Subcommands.Add(provider.GetRequiredService<StatusCommand>());
        root.Subcommands.Add(provider.GetRequiredService<NextCommand>());
        root.Subcommands.Add(provider.GetRequiredService<CheckCommand>());
        root.Subcommands.Add(provider.GetRequiredService<DiffCommand>());
        root.Subcommands.Add(provider.GetRequiredService<InitCommand>());
        root.Subcommands.Add(provider.GetRequiredService<ListCommand>());
        root.Subcommands.Add(provider.GetRequiredService<RemoveBackendCommand>());
        root.Subcommands.Add(provider.GetRequiredService<ResetCommand>());
        root.Subcommands.Add(provider.GetRequiredService<RemoteCommand>());
        root.Subcommands.Add(provider.GetRequiredService<PushCommand>());
        root.Subcommands.Add(provider.GetRequiredService<PullCommand>());

        var parseResult = root.Parse(args);
        return await parseResult.InvokeAsync();
    }
}
