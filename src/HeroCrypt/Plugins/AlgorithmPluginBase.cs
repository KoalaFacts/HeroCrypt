using Microsoft.Extensions.DependencyInjection;

namespace HeroCrypt.Plugins;

public abstract class AlgorithmPluginBase : IAlgorithmPlugin
{
    public abstract string Name { get; }
    public abstract string Version { get; }
    public abstract string Description { get; }
    public abstract AlgorithmCategory Category { get; }

    public abstract void Register(IServiceCollection services);

    protected virtual void ValidateConfiguration()
    {
        if (string.IsNullOrWhiteSpace(Name))
            throw new InvalidOperationException("Plugin name cannot be empty");

        if (string.IsNullOrWhiteSpace(Version))
            throw new InvalidOperationException("Plugin version cannot be empty");
    }
}