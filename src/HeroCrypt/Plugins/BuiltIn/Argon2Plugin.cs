using HeroCrypt.Abstractions;
using HeroCrypt.Services;
using Microsoft.Extensions.DependencyInjection;

namespace HeroCrypt.Plugins.BuiltIn;

/// <summary>
/// Plugin providing RFC 9106 compliant Argon2 password hashing functionality.
/// Supports Argon2d, Argon2i, and Argon2id variants.
/// </summary>
public class Argon2Plugin : AlgorithmPluginBase
{
    /// <summary>
    /// Gets the plugin name.
    /// </summary>
    public override string Name => "Argon2";

    /// <summary>
    /// Gets the plugin version.
    /// </summary>
    public override string Version => "1.0.0";

    /// <summary>
    /// Gets the plugin description.
    /// </summary>
    public override string Description => "RFC 9106 compliant Argon2 password hashing (Argon2d, Argon2i, Argon2id)";

    /// <summary>
    /// Gets the plugin category.
    /// </summary>
    public override AlgorithmCategory Category => AlgorithmCategory.KeyDerivation;

    /// <summary>
    /// Registers Argon2 hashing services with the dependency injection container.
    /// </summary>
    /// <param name="services">The service collection to register services with.</param>
    public override void Register(IServiceCollection services)
    {
        services.AddSingleton<IHashingService, Argon2HashingService>();
        services.AddSingleton<Argon2Options>();
    }
}