namespace RDRF.Core.DSAA;

/// <summary>
/// Factory that creates <see cref="IStorageBackend"/> instances from
/// a configuration dictionary. Plugins are discovered via
/// <see cref="PluginLoader"/>.
/// </summary>
public interface IStorageBackendFactory
{
    /// <summary>Backend type identifier (e.g. "path", "rest", "key").</summary>
    string Type { get; }

    /// <summary>Creates a new backend instance from the given configuration.</summary>
    IStorageBackend Create(Dictionary<string, object> config);
}
