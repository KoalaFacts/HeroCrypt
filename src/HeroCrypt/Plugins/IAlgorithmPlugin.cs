using Microsoft.Extensions.DependencyInjection;

namespace HeroCrypt.Plugins;

/// <summary>
/// Interface for HeroCrypt algorithm plugins
///
/// Plugins allow extending HeroCrypt with custom cryptographic algorithms
/// while maintaining type safety and integration with dependency injection.
/// </summary>
public interface IAlgorithmPlugin
{
    /// <summary>
    /// Gets the unique name of the plugin
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Gets the version of the plugin (semantic versioning recommended)
    /// </summary>
    string Version { get; }

    /// <summary>
    /// Gets a human-readable description of the plugin's functionality
    /// </summary>
    string Description { get; }

    /// <summary>
    /// Gets the category of cryptographic algorithms provided by this plugin
    /// </summary>
    AlgorithmCategory Category { get; }

    /// <summary>
    /// Registers the plugin's services with the dependency injection container
    /// </summary>
    /// <param name="services">The service collection to register with</param>
    void Register(IServiceCollection services);
}

/// <summary>
/// Categories of cryptographic algorithms supported by the plugin system
/// </summary>
public enum AlgorithmCategory
{
    /// <summary>
    /// Cryptographic hash functions (e.g., BLAKE2b, SHA-3)
    /// </summary>
    Hashing,

    /// <summary>
    /// Symmetric and asymmetric encryption algorithms (e.g., AES, ChaCha20, RSA)
    /// </summary>
    Encryption,

    /// <summary>
    /// Key derivation functions (e.g., Argon2, PBKDF2, scrypt)
    /// </summary>
    KeyDerivation,

    /// <summary>
    /// Digital signature schemes (e.g., Ed25519, ECDSA, RSA-PSS)
    /// </summary>
    DigitalSignature,

    /// <summary>
    /// Key exchange protocols (e.g., X25519, ECDH)
    /// </summary>
    KeyExchange,

    /// <summary>
    /// Message authentication codes (e.g., HMAC, Poly1305, BLAKE2-MAC)
    /// </summary>
    MAC
}

/// <summary>
/// Optional metadata interface for plugins
///
/// Provides additional information about the plugin such as author,
/// license, and platform compatibility.
/// </summary>
public interface IPluginMetadata
{
    /// <summary>
    /// Gets the author or organization that created the plugin
    /// </summary>
    string Author { get; }

    /// <summary>
    /// Gets the license under which the plugin is distributed (e.g., MIT, Apache-2.0)
    /// </summary>
    string License { get; }

    /// <summary>
    /// Gets the URL to the plugin's project or documentation
    /// </summary>
    string ProjectUrl { get; }

    /// <summary>
    /// Gets the list of supported platforms (e.g., "Windows", "Linux", "macOS", "Any")
    /// </summary>
    string[] SupportedPlatforms { get; }

    /// <summary>
    /// Gets the list of plugin dependencies (names of other required plugins)
    /// </summary>
    string[] Dependencies { get; }
}