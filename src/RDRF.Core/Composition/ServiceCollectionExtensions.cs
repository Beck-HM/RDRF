using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using RDRF.Core.Abstractions;
using RDRF.Core.Compression;
using RDRF.Core.Configuration;
using RDRF.Core.Diff;
using RDRF.Core.Encryption;
using RDRF.Core.FragmentEngine;
using RDRF.Core.FSA;
using RDRF.Core.FSS;
using RDRF.Core.Index;
using RDRF.Core.Integrity;
using RDRF.Core.Logging;
using RDRF.Core.Metadata;

namespace RDRF.Core.Composition;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddRdrfCore(this IServiceCollection services)
    {
        // Singletons — stateless or shared services
        services.TryAddSingleton<RdrfConfigService>(_ =>
        {
            var cfg = new RdrfConfigService();
            RdrfConfigService.SetInstance(cfg);
            return cfg;
        });
        services.TryAddSingleton<GlobalConfigService>(sp =>
        {
            var rdrf = sp.GetRequiredService<RdrfConfigService>();
            var cfg = new GlobalConfigService(rdrf);
            GlobalConfigService.SetInstance(cfg);
            return cfg;
        });
        services.TryAddSingleton<IFSSEngine>(_ => new FSSEngineWrapper());
        services.TryAddSingleton<IFsaEngine>(_ => new FsaEngineWrapper());
        services.TryAddSingleton<IEncryptionLayer>(_ => new EncryptionLayerWrapper());
        services.TryAddSingleton<IIntegrityChecker>(_ => new IntegrityCheckerWrapper());
        services.TryAddSingleton<IFragmentEngine>(_ => new FragmentEngineWrapper());
        services.TryAddSingleton<IIndexManager>(_ => new IndexManagerWrapper());
        services.TryAddSingleton<IMetadataManager>(_ => new MetadataManagerWrapper());
        services.TryAddSingleton<ICompressor>(_ => new CompressorWrapper());
        services.TryAddSingleton<CompressionRouter>(_ =>
        {
            var router = new CompressionRouter();
            Compressor.RouterOverride = router;
            return router;
        });
        services.TryAddTransient<IRecoveryExecutor>(sp =>
        {
            var fss = sp.GetRequiredService<IFSSEngine>();
            return new RecoveryExecutor(fss);
        });

        services.TryAddSingleton<DiffEngine>();

        // Logger — register sinks then central logger
        services.TryAddSingleton<FileLogSink>();
        services.TryAddSingleton<DebugLogSink>();
        services.TryAddSingleton<RdrfLogger>(sp =>
        {
            var logger = new RdrfLogger();
            logger.AddSink(sp.GetRequiredService<FileLogSink>());
            logger.AddSink(sp.GetRequiredService<DebugLogSink>());
            return logger;
        });

        return services;
    }
}
