using Microsoft.Extensions.DependencyInjection;
using RDRF.Cli.Commands;
using RDRF.Core.Composition;
using RDRF.Core.Configuration;
using RDRF.Core.Logging;
using RDRF.Core.PasswordManager;
using System.CommandLine;
using System.Globalization;

class Program
{
    static async Task<int> Main(string[] args)
    {
        CultureInfo.DefaultThreadCurrentUICulture = new CultureInfo("en-US");
        RdrfConfig.Initialize();
        GlobalConfig.Load();

        var services = new ServiceCollection();
        services.AddRdrfCore();
        services.AddSingleton<PasswordManager>();
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
        services.AddTransient<FpCommand>();
        services.AddTransient<ConfigCommand>();
        services.AddTransient<ReachCommand>();
        services.AddTransient<RescueCommand>();
        services.AddTransient<EtiCommand>();
        services.AddTransient<ServerCommand>();

        using var provider = services.BuildServiceProvider();

        // Add console logging for CLI
        var logger = provider.GetRequiredService<RdrfLogger>();
        logger.AddSink(new ConsoleLogSink { Level = RDRF.Core.Logging.LogLevel.Warning });

        // Handle --version before parsing (fast path)
        if (args.Length == 1 && (args[0] == "--version" || args[0] == "-v"))
        {
            var ver = typeof(Program).Assembly.GetName().Version;
            Console.WriteLine($"rdrf version {ver}");
            Console.WriteLine("FSS flags: -fss1..-fss5 -fss5+ -fss6 -fss61|-fss62 (aliases --fss6.1/--fss6.2)");
            return 0;
        }

        var root = new RootCommand(
            "RDRF - Redundant Distributed Recovery File. Backup: rdrf backup <file> -fss61 -password <p> [-c lz4]");
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
        root.Subcommands.Add(provider.GetRequiredService<FpCommand>());
        root.Subcommands.Add(provider.GetRequiredService<ConfigCommand>());
        root.Subcommands.Add(provider.GetRequiredService<ReachCommand>());
        root.Subcommands.Add(provider.GetRequiredService<RescueCommand>());
        root.Subcommands.Add(provider.GetRequiredService<EtiCommand>());
        root.Subcommands.Add(provider.GetRequiredService<ServerCommand>());

        var parseResult = root.Parse(args);
        return await parseResult.InvokeAsync();
    }
}
