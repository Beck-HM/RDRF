using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using RDRF.Core.Abstractions;
using RDRF.Core.Compression;
using RDRF.Core.Encryption;
using RDRF.Core.FragmentEngine;
using RDRF.Core.FSA;
using RDRF.Core.FSS;
using RDRF.Core.Index;
using RDRF.Core.Integrity;
using RDRF.Core.Metadata;

namespace RDRF.Core.Composition;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddRdrfCore(this IServiceCollection services)
    {
        // Singletons — stateless or shared services
        services.TryAddSingleton<IFSSEngine>(_ => new FSSEngineWrapper());
        services.TryAddSingleton<IFsaEngine>(_ => new FsaEngineWrapper());
        services.TryAddSingleton<IEncryptionLayer>(_ => new EncryptionLayerWrapper());
        services.TryAddSingleton<IIntegrityChecker>(_ => new IntegrityCheckerWrapper());
        services.TryAddSingleton<IFragmentEngine>(_ => new FragmentEngineWrapper());
        services.TryAddSingleton<IIndexManager>(_ => new IndexManagerWrapper());
        services.TryAddSingleton<IMetadataManager>(_ => new MetadataManagerWrapper());
        services.TryAddSingleton<ICompressor>(_ => new CompressorWrapper());
        services.TryAddTransient<IRecoveryExecutor>(sp =>
        {
            var fss = sp.GetRequiredService<IFSSEngine>();
            return new RecoveryExecutor(fss);
        });

        return services;
    }
}
