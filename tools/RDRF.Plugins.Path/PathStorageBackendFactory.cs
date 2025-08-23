using RDRF.Dssa;

namespace RDRF.Plugins.Path;

public class PathStorageBackendFactory : IStorageBackendFactory
{
    public string Type => "path";

    public IStorageBackend Create(Dictionary<string, object> config)
    {
        if (!config.TryGetValue("base_path", out var basePathObj))
            throw new ArgumentException("PATH backend requires 'base_path' parameter");

        var basePath = basePathObj?.ToString();
        if (string.IsNullOrEmpty(basePath))
            throw new ArgumentException("'base_path' must be a non-empty path");

        return new PathStorageBackend(basePath);
    }
}
