using Microsoft.Extensions.DependencyInjection;

namespace HeroCrypt.Plugins;

public interface IAlgorithmPlugin
{
    string Name { get; }
    string Version { get; }
    string Description { get; }
    AlgorithmCategory Category { get; }

    void Register(IServiceCollection services);
}

public enum AlgorithmCategory
{
    Hashing,
    Encryption,
    KeyDerivation,
    DigitalSignature,
    KeyExchange,
    MAC
}

public interface IPluginMetadata
{
    string Author { get; }
    string License { get; }
    string ProjectUrl { get; }
    string[] SupportedPlatforms { get; }
    string[] Dependencies { get; }
}