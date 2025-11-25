using System;
using System.Diagnostics.CodeAnalysis;

namespace HeroCrypt.Cryptography.Protocols.KeyManagement;

/// <summary>
/// Supported symmetric algorithms for key generation.
/// </summary>
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
