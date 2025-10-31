using Microsoft.Extensions.DependencyInjection;

namespace HeroCrypt.Plugins;

/// <summary>
/// Base class for algorithm plugin implementations providing common functionality
/// for registering cryptographic algorithms with the dependency injection container.
/// </summary>
public abstract class AlgorithmPluginBase : IAlgorithmPlugin
{
    public abstract string Name { get; }
    public abstract string Version { get; }
    public abstract string Description { get; }
    public abstract AlgorithmCategory Category { get; }

    /// <summary>
    /// Registers the plugin's services with the dependency injection container.
    /// </summary>
    /// <param name="services">The service collection to register services with.</param>
    public abstract void Register(IServiceCollection services);

    protected virtual void ValidateConfiguration()
    {
        if (string.IsNullOrWhiteSpace(Name))
            throw new InvalidOperationException("Plugin name cannot be empty");

        if (string.IsNullOrWhiteSpace(Version))
            throw new InvalidOperationException("Plugin version cannot be empty");
    }
}