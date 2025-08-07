using System.Reflection;
using RDRF.Storage;

namespace RDRF.PluginLoader;

public static class PluginLoader
{
    public static List<IStorageBackendFactory> Load(string directory)
    {
        var factories = new List<IStorageBackendFactory>();
        if (!Directory.Exists(directory))
            return factories;

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
            catch
            {
            }
        }
        return factories;
    }
}
