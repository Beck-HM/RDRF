using System.Reflection;
using RDRF.Core.DSAA.NativePlugin;
using RDRF.Core.Logging;

namespace RDRF.Core.DSAA;

public static class PluginLoader
{
    public static List<IStorageBackendFactory> Load(string directory)
    {
        var factories = new List<IStorageBackendFactory>();
        if (!Directory.Exists(directory))
            return factories;

        // Load .NET assembly plugins
        foreach (var dllPath in Directory.GetFiles(directory, "*.dll"))
        {
            try
            {
                var asm = Assembly.LoadFrom(Path.GetFullPath(dllPath));
                foreach (var type in asm.GetExportedTypes())
                {
                    if (type is { IsClass: true, IsAbstract: false } &&
                        typeof(IStorageBackendFactory).IsAssignableFrom(type))
                    {
                        if (Activator.CreateInstance(type) is IStorageBackendFactory factory)
                            factories.Add(factory);
                    }
                }
            }
            catch (Exception ex)
            {
                RdrfLogger.Default.Warn("PluginLoader",
                    $"Failed to load plugin DLL '{dllPath}': {ex.Message}");
                Console.Error.WriteLine(
                    $"[PluginLoader] Failed to load plugin '{Path.GetFileName(dllPath)}': {ex.Message}");
            }
        }

        // Load native (C ABI) plugins
        factories.AddRange(NativePluginLoader.Load(directory));

        return factories;
    }
}
