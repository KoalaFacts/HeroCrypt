using System.Diagnostics.CodeAnalysis;

namespace HeroCrypt.Protocols.KeyManagement;

/// <summary>
/// Supported symmetric algorithms for key generation.
/// </summary>
/// <remarks>
/// <para>
/// Use with <see cref="KeyManager"/> to generate appropriately-sized keys for each algorithm:
/// </para>
/// <list type="table">
///   <listheader>
///     <term>Algorithm</term>
///     <description>Key Size</description>
///   </listheader>
///   <item><term>Aes128</term><description>16 bytes (128 bits)</description></item>
///   <item><term>Aes192</term><description>24 bytes (192 bits)</description></item>
///   <item><term>Aes256</term><description>32 bytes (256 bits)</description></item>
///   <item><term>ChaCha20</term><description>32 bytes (256 bits)</description></item>
///   <item><term>ChaCha20Poly1305</term><description>32 bytes (256 bits)</description></item>
/// </list>
/// <para>
/// <b>Recommendation:</b> Use <c>Aes256</c> for hardware-accelerated encryption (AES-NI)
/// or <c>ChaCha20Poly1305</c> for software-only environments.
/// </para>
/// </remarks>
public enum CryptographicAlgorithm
{
    /// <summary>
    /// AES with a 128-bit key.
    /// </summary>
    Aes128,

    /// <summary>
    /// AES with a 192-bit key.
    /// </summary>
    Aes192,

    /// <summary>
    /// AES with a 256-bit key.
    /// </summary>
    Aes256,

    /// <summary>
    /// ChaCha20 stream cipher.
    /// </summary>
    ChaCha20,

    /// <summary>
    /// ChaCha20-Poly1305 AEAD cipher.
    /// </summary>
    ChaCha20Poly1305
}

/// <summary>
/// Supported algorithms that rely on nonces.
/// </summary>
/// <remarks>
/// <para>
/// Use with <see cref="KeyManager"/> to generate appropriately-sized nonces for each algorithm:
/// </para>
/// <list type="table">
///   <listheader>
///     <term>Algorithm</term>
///     <description>Nonce Size</description>
///   </listheader>
///   <item><term>ChaCha20</term><description>12 bytes (96 bits)</description></item>
///   <item><term>ChaCha20Poly1305</term><description>12 bytes (96 bits)</description></item>
///   <item><term>AesGcm</term><description>12 bytes (96 bits, recommended)</description></item>
/// </list>
/// <para>
/// <b>Important:</b> Nonces must never be reused with the same key. Use counter-based
/// nonces when possible, or ensure random nonces are generated with sufficient entropy.
/// For random nonces, consider XChaCha20-Poly1305 which has a 192-bit nonce space.
/// </para>
/// </remarks>
public enum NonceAlgorithm
{
    /// <summary>
    /// ChaCha20 stream cipher.
    /// </summary>
    ChaCha20,

    /// <summary>
    /// ChaCha20-Poly1305 AEAD cipher.
    /// </summary>
    ChaCha20Poly1305,

    /// <summary>
    /// AES in Galois/Counter Mode.
    /// </summary>
    AesGcm
}

/// <summary>
/// Hash algorithm names used by key derivation routines.
/// </summary>
/// <remarks>
/// <para>
/// This struct provides strongly-typed hash algorithm identifiers compatible with
/// <see cref="System.Security.Cryptography.HashAlgorithmName"/> but with additional
/// algorithms like Blake2b.
/// </para>
/// <para>
/// <b>Hash output sizes:</b>
/// </para>
/// <list type="bullet">
///   <item><term>SHA256</term><description>32 bytes (256 bits) - recommended default</description></item>
///   <item><term>SHA384</term><description>48 bytes (384 bits)</description></item>
///   <item><term>SHA512</term><description>64 bytes (512 bits)</description></item>
///   <item><term>SHA3-256/384/512</term><description>32/48/64 bytes (.NET 8+)</description></item>
///   <item><term>Blake2b</term><description>Configurable, up to 64 bytes</description></item>
/// </list>
/// </remarks>
public readonly struct CryptographicHashName : IEquatable<CryptographicHashName>
{
    private readonly string? name;

    private CryptographicHashName(string? name)
    {
        this.name = name;
    }

    /// <summary>
    /// SHA-256 hash algorithm.
    /// </summary>
    public static CryptographicHashName SHA256 { get; } = new("SHA256");

    /// <summary>
    /// SHA-384 hash algorithm.
    /// </summary>
    public static CryptographicHashName SHA384 { get; } = new("SHA384");

    /// <summary>
    /// SHA-512 hash algorithm.
    /// </summary>
    public static CryptographicHashName SHA512 { get; } = new("SHA512");

    /// <summary>
    /// SHA3-256 hash algorithm.
    /// </summary>
    public static CryptographicHashName SHA3256 { get; } = new("SHA3-256");

    /// <summary>
    /// SHA3-384 hash algorithm.
    /// </summary>
    public static CryptographicHashName SHA3384 { get; } = new("SHA3-384");

    /// <summary>
    /// SHA3-512 hash algorithm.
    /// </summary>
    public static CryptographicHashName SHA3512 { get; } = new("SHA3-512");

    /// <summary>
    /// Blake2b hash algorithm.
    /// </summary>
    public static CryptographicHashName Blake2b { get; } = new("Blake2b");

    /// <summary>
    /// Gets the canonical name of the hash algorithm.
    /// </summary>
    public string Name => name ?? "SHA256";

    /// <summary>
    /// Creates a hash algorithm name from a raw string.
    /// </summary>
    /// <param name="value">Algorithm name to wrap.</param>
    /// <returns>Wrapped hash algorithm name.</returns>
    public static CryptographicHashName Create(string value) => new(value);

    /// <inheritdoc />
    public override string ToString() => Name;

    /// <inheritdoc />
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is CryptographicHashName other && Equals(other);

    /// <summary>
    /// Compares two hash algorithm names using a case-insensitive comparison.
    /// </summary>
    /// <param name="other">Other instance to compare.</param>
    /// <returns><see langword="true" /> when the names match; otherwise <see langword="false" />.</returns>
    public bool Equals(CryptographicHashName other) =>
        string.Equals(name, other.name, StringComparison.OrdinalIgnoreCase);

    /// <inheritdoc />
    public override int GetHashCode()
    {
#if NETSTANDARD2_0
        return name?.ToUpperInvariant().GetHashCode() ?? 0;
#else
        return name?.GetHashCode(StringComparison.OrdinalIgnoreCase) ?? 0;
#endif
    }

    /// <summary>
    /// Determines whether two hash algorithm names are equal.
    /// </summary>
    /// <param name="left">Left value to compare.</param>
    /// <param name="right">Right value to compare.</param>
    /// <returns><see langword="true" /> when the names match; otherwise <see langword="false" />.</returns>
    public static bool operator ==(CryptographicHashName left, CryptographicHashName right) => left.Equals(right);

    /// <summary>
    /// Determines whether two hash algorithm names differ.
    /// </summary>
    /// <param name="left">Left value to compare.</param>
    /// <param name="right">Right value to compare.</param>
    /// <returns><see langword="true" /> when the names differ; otherwise <see langword="false" />.</returns>
    public static bool operator !=(CryptographicHashName left, CryptographicHashName right) => !left.Equals(right);
}

/// <summary>
/// Represents a public/private key pair.
/// </summary>
public class KeyPair
{
    /// <summary>
    /// Initializes a new instance of the <see cref="KeyPair"/> class.
    /// </summary>
    /// <param name="publicKey">Public key in textual form.</param>
    /// <param name="privateKey">Private key in textual form.</param>
    /// <exception cref="ArgumentNullException">Thrown when any argument is <see langword="null" />.</exception>
    public KeyPair(string publicKey, string privateKey)
    {
        PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        PrivateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
    }

    /// <summary>
    /// Gets the public key.
    /// </summary>
    public string PublicKey { get; }

    /// <summary>
    /// Gets the private key.
    /// </summary>
    public string PrivateKey { get; }
}
