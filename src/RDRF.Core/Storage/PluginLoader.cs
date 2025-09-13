using System.Diagnostics;
using System.Reflection;

namespace RDRF.Dssa;

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
            catch (Exception ex)
            {
                Debug.WriteLine($"[PluginLoader] Failed to load plugin DLL '{dllPath}': {ex.Message}");
                Console.Error.WriteLine($"[PluginLoader] Failed to load plugin '{Path.GetFileName(dllPath)}': {ex.Message}");
            }
        }
        return factories;
    }
}
