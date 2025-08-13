#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

using HeroCrypt.Abstractions;
using HeroCrypt.Plugins;
using HeroCrypt.Plugins.BuiltIn;
using HeroCrypt.Services;
using System.Reflection;

public static class ExtensionsToServiceCollection
{
    public static IServiceCollection AddHeroCrypt(this IServiceCollection services)
    {
        services.AddSingleton<IHashingService, Argon2HashingService>();
        services.AddSingleton<ICryptographyService, PgpCryptographyService>();
        services.AddSingleton<IKeyGenerationService, PgpCryptographyService>();
        
        return services;
    }
    
    public static IServiceCollection AddHeroCryptWithPlugins(this IServiceCollection services, Action<PluginOptions>? configure = null)
    {
        var options = new PluginOptions();
        configure?.Invoke(options);
        
        services.AddSingleton(options);
        services.AddSingleton<PluginLoader>();
        
        // Load built-in plugins
        if (options.LoadBuiltInPlugins)
        {
            var builtInPlugins = new List<IAlgorithmPlugin>
            {
                new Argon2Plugin(),
                new PgpPlugin()
            };
            
            foreach (var plugin in builtInPlugins)
            {
                if (!options.DisabledPlugins.Contains(plugin.Name))
                {
                    plugin.Register(services);
                }
            }
        }
        
        // Load external plugins
        if (!string.IsNullOrEmpty(options.PluginDirectory))
        {
            var loader = new PluginLoader();
            loader.LoadFromDirectory(options.PluginDirectory);
            
            foreach (var plugin in loader.LoadedPlugins)
            {
                if (!options.DisabledPlugins.Contains(plugin.Name))
                {
                    plugin.Register(services);
                }
            }
        }
        
        return services;
    }
    
    public static IServiceCollection AddHeroCrypt(this IServiceCollection services, Action<HeroCryptOptions> configure)
    {
        var options = new HeroCryptOptions();
        configure(options);
        
        services.AddSingleton(options);
        services.AddSingleton(options.Argon2);
        services.AddSingleton(options.Pgp);
        
        if (options.HashingService == HashingServiceType.Argon2)
        {
            services.AddSingleton<IHashingService>(sp => 
                new Argon2HashingService(sp.GetRequiredService<Argon2Options>()));
        }
        
        if (options.CryptographyService == CryptographyServiceType.PGP)
        {
            services.AddSingleton<ICryptographyService, PgpCryptographyService>();
            services.AddSingleton<IKeyGenerationService, PgpCryptographyService>();
        }
        
        return services;
    }
}

public class HeroCryptOptions
{
    public HashingServiceType HashingService { get; set; } = HashingServiceType.Argon2;
    public CryptographyServiceType CryptographyService { get; set; } = CryptographyServiceType.PGP;
    
    public Argon2Options Argon2 { get; set; } = new();
    public PgpOptions Pgp { get; set; } = new();
}

public enum HashingServiceType
{
    Argon2
}

public enum CryptographyServiceType
{
    PGP
}

public class PgpOptions
{
    public int DefaultKeySize { get; set; } = 2048;
    public bool UseCompression { get; set; } = true;
    public bool UseArmor { get; set; } = true;
}

public class PluginOptions
{
    public bool LoadBuiltInPlugins { get; set; } = true;
    public string? PluginDirectory { get; set; }
    public HashSet<string> DisabledPlugins { get; set; } = new();
}