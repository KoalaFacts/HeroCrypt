using HeroCrypt.Abstractions;
using HeroCrypt.Configuration;
using HeroCrypt.Fluent;
using HeroCrypt.Hardware;
using HeroCrypt.Memory;
using HeroCrypt.Observability;
using HeroCrypt.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HeroCrypt.Extensions;

/// <summary>
/// Extension methods for registering HeroCrypt services with dependency injection
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds HeroCrypt services to the service collection with default configuration
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddHeroCrypt(this IServiceCollection services)
    {
        return services.AddHeroCrypt(options => { });
    }

    /// <summary>
    /// Adds HeroCrypt services to the service collection with custom configuration
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configureOptions">Configuration action</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddHeroCrypt(this IServiceCollection services, Action<HeroCryptOptions> configureOptions)
    {
#if NET6_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);
#else
        if (services == null) throw new ArgumentNullException(nameof(services));
        if (configureOptions == null) throw new ArgumentNullException(nameof(configureOptions));
#endif

        // Configure options
        services.Configure(configureOptions);

        // Register core services
        services.TryAddSingleton<IHardwareAccelerator>(provider =>
        {
            return HardwareAccelerationDetector.CreateAccelerator();
        });

        // Register telemetry
        services.TryAddSingleton<ICryptoTelemetry, DefaultCryptoTelemetry>();

        // Register secure memory management
        services.TryAddSingleton<ISecureMemoryManager, DefaultSecureMemoryManager>();

        // Register hashing services
        services.TryAddScoped<IHashingService, Argon2HashingService>();
        services.TryAddScoped<IBlake2bService, Blake2bHashingService>();

        // Register key derivation services
        services.TryAddScoped<IKeyDerivationService, KeyDerivationService>();

        // Register cryptography services
        services.TryAddScoped<ICryptographyService, PgpCryptographyService>();
        services.TryAddScoped<IKeyGenerationService, PgpCryptographyService>();
        services.TryAddScoped<IDigitalSignatureService, RsaDigitalSignatureService>();
        services.TryAddScoped<ICryptographicKeyGenerationService, CryptographicKeyGenerationService>();

        // Register modern cryptography services
        services.TryAddScoped<IEllipticCurveService, EllipticCurveService>();
        services.TryAddScoped<IAeadService, AeadService>();

        // Register fluent API builders
        services.TryAddScoped<IArgon2FluentBuilder, Argon2FluentBuilder>();
        services.TryAddScoped<IPgpFluentBuilder, PgpFluentBuilder>();

        // Register the main HeroCrypt facade
        services.TryAddScoped<IHeroCrypt, HeroCryptService>();

        return services;
    }

    /// <summary>
    /// Adds HeroCrypt services with security level-based configuration
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="securityLevel">The security level to use</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddHeroCrypt(this IServiceCollection services, SecurityLevel securityLevel)
    {
        return services.AddHeroCrypt(options =>
        {
            options.DefaultSecurityLevel = securityLevel;
            options.DefaultArgon2Options = SecurityPolicies.GetArgon2Policy(securityLevel);
            options.DefaultRsaKeySize = SecurityPolicies.GetRsaKeySize(securityLevel);
        });
    }

    /// <summary>
    /// Adds hardware acceleration services
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddHeroCryptHardwareAcceleration(this IServiceCollection services)
    {
        services.TryAddSingleton<IHardwareAccelerator>(provider =>
        {
            return HardwareAccelerationDetector.CreateAccelerator();
        });

        return services;
    }

    /// <summary>
    /// Adds custom hardware accelerator
    /// </summary>
    /// <typeparam name="T">The hardware accelerator implementation type</typeparam>
    /// <param name="services">The service collection</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddHeroCryptHardwareAccelerator<T>(this IServiceCollection services)
        where T : class, IHardwareAccelerator
    {
        services.TryAddSingleton<IHardwareAccelerator, T>();
        return services;
    }
}
