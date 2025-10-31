using System.Reflection;
#if !NETSTANDARD2_0
using System.Runtime.Loader;
#endif

namespace HeroCrypt.Plugins;

/// <summary>
/// Dynamically loads and manages algorithm plugins from assemblies or directories.
/// </summary>
public class PluginLoader
{
    private readonly List<IAlgorithmPlugin> _plugins = new();

    /// <summary>
    /// Gets a read-only collection of all successfully loaded plugins.
    /// </summary>
    public IReadOnlyList<IAlgorithmPlugin> LoadedPlugins => _plugins.AsReadOnly();

    /// <summary>
    /// Loads all plugins implementing <see cref="IAlgorithmPlugin"/> from the specified assembly.
    /// </summary>
    /// <param name="assembly">The assembly to scan for plugin types.</param>
    public void LoadFromAssembly(Assembly assembly)
    {
        var pluginTypes = assembly.GetTypes()
            .Where(t => typeof(IAlgorithmPlugin).IsAssignableFrom(t) && !t.IsAbstract && !t.IsInterface)
            .ToList();

        foreach (var type in pluginTypes)
        {
            try
            {
                var plugin = Activator.CreateInstance(type) as IAlgorithmPlugin;
                if (plugin != null)
                {
                    _plugins.Add(plugin);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to load plugin {type.Name}: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Loads all plugins from DLL files in the specified directory.
    /// </summary>
    /// <param name="directory">The directory path to scan for plugin DLL files.</param>
    public void LoadFromDirectory(string directory)
    {
        if (!Directory.Exists(directory))
            return;

        var pluginFiles = Directory.GetFiles(directory, "*.dll", SearchOption.TopDirectoryOnly);

        foreach (var file in pluginFiles)
        {
            try
            {
                var assembly = LoadPluginAssembly(file);
                LoadFromAssembly(assembly);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to load plugin from {file}: {ex.Message}");
            }
        }
    }

    private static Assembly LoadPluginAssembly(string path)
    {
#if !NETSTANDARD2_0
        var loadContext = new PluginLoadContext(path);
        return loadContext.LoadFromAssemblyPath(path);
#else
        return Assembly.LoadFrom(path);
#endif
    }

    /// <summary>
    /// Retrieves a loaded plugin by its name (case-insensitive).
    /// </summary>
    /// <param name="name">The name of the plugin to retrieve.</param>
    /// <returns>The plugin with the specified name, or null if not found.</returns>
    public IAlgorithmPlugin? GetPlugin(string name)
    {
        return _plugins.FirstOrDefault(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Retrieves all loaded plugins in the specified category.
    /// </summary>
    /// <param name="category">The category to filter plugins by.</param>
    /// <returns>An enumerable of plugins in the specified category.</returns>
    public IEnumerable<IAlgorithmPlugin> GetPluginsByCategory(AlgorithmCategory category)
    {
        return _plugins.Where(p => p.Category == category);
    }
}

#if !NETSTANDARD2_0
internal sealed class PluginLoadContext : AssemblyLoadContext
{
    private readonly AssemblyDependencyResolver _resolver;

    /// <summary>
    /// Initializes a new instance of the <see cref="PluginLoadContext"/> class.
    /// </summary>
    /// <param name="pluginPath">The path to the plugin assembly.</param>
    public PluginLoadContext(string pluginPath)
    {
        _resolver = new AssemblyDependencyResolver(pluginPath);
    }

    protected override Assembly? Load(AssemblyName assemblyName)
    {
        string? assemblyPath = _resolver.ResolveAssemblyToPath(assemblyName);
        if (assemblyPath != null)
        {
            return LoadFromAssemblyPath(assemblyPath);
        }

        return null;
    }

    protected override IntPtr LoadUnmanagedDll(string unmanagedDllName)
    {
        string? libraryPath = _resolver.ResolveUnmanagedDllToPath(unmanagedDllName);
        if (libraryPath != null)
        {
            return LoadUnmanagedDllFromPath(libraryPath);
        }

        return IntPtr.Zero;
    }
}
#endif