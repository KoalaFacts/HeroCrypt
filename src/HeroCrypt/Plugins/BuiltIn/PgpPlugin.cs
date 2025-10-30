using HeroCrypt.Abstractions;
using HeroCrypt.Services;
using Microsoft.Extensions.DependencyInjection;

namespace HeroCrypt.Plugins.BuiltIn;

/// <summary>
/// Plugin providing PGP-compatible encryption and decryption using RSA and AES algorithms.
/// </summary>
public class PgpPlugin : AlgorithmPluginBase
{
    /// <summary>
    /// Gets the plugin name.
    /// </summary>
    public override string Name => "PGP/RSA";

    /// <summary>
    /// Gets the plugin version.
    /// </summary>
    public override string Version => "1.0.0";

    /// <summary>
    /// Gets the plugin description.
    /// </summary>
    public override string Description => "PGP-compatible encryption using RSA and AES";

    /// <summary>
    /// Gets the plugin category.
    /// </summary>
    public override AlgorithmCategory Category => AlgorithmCategory.Encryption;

    /// <summary>
    /// Registers PGP cryptography services with the dependency injection container.
    /// </summary>
    /// <param name="services">The service collection to register services with.</param>
    public override void Register(IServiceCollection services)
    {
        services.AddSingleton<ICryptographyService, PgpCryptographyService>();
        services.AddSingleton<IKeyGenerationService, PgpCryptographyService>();
    }
}