using System.Reflection;
#if !NETSTANDARD2_0
using System.Runtime.Loader;
#endif

namespace HeroCrypt.Plugins;

public class PluginLoader
{
    private readonly List<IAlgorithmPlugin> _plugins = new();
    
    public IReadOnlyList<IAlgorithmPlugin> LoadedPlugins => _plugins.AsReadOnly();
    
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
    
    public IAlgorithmPlugin? GetPlugin(string name)
    {
        return _plugins.FirstOrDefault(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
    }
    
    public IEnumerable<IAlgorithmPlugin> GetPluginsByCategory(AlgorithmCategory category)
    {
        return _plugins.Where(p => p.Category == category);
    }
}

#if !NETSTANDARD2_0
internal sealed class PluginLoadContext : AssemblyLoadContext
{
    private readonly AssemblyDependencyResolver _resolver;
    
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