using HeroCrypt.Encryption;
using HeroCrypt.Hashing;
using HeroCrypt.KeyManagement;
using HeroCrypt.Signatures;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HeroCrypt.Extensions;

/// <summary>
/// Extension methods for registering HeroCrypt services with dependency injection
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds HeroCrypt services to the service collection
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddHeroCrypt(this IServiceCollection services)
    {
#if NET6_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(services);
#else
        if (services == null) throw new ArgumentNullException(nameof(services));
#endif

        // Register hashing services
        services.TryAddScoped<IPasswordHashingService, Argon2HashingService>();
        services.TryAddScoped<IBlake2bService, Blake2bHashingService>();

        // Register key derivation services
        services.TryAddScoped<IKeyDerivationService, KeyDerivationService>();

        // Register cryptography services
        services.TryAddScoped<ICryptographyService, PgpCryptographyService>();
        services.TryAddScoped<IPgpKeyGenerator, PgpCryptographyService>();
        services.TryAddScoped<IDigitalSignatureService, RsaDigitalSignatureService>();
        services.TryAddScoped<ICryptographicKeyGenerator, CryptographicKeyGenerator>();

        // Register modern cryptography services
        services.TryAddScoped<IEllipticCurveService, EllipticCurveService>();
        services.TryAddScoped<IAeadService, AeadService>();

        return services;
    }
}
