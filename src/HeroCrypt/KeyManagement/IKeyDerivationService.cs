namespace HeroCrypt.KeyManagement;

/// <summary>
/// Interface for cryptographic key derivation operations.
/// </summary>
public interface IKeyDerivationService
{
    /// <summary>
    /// Derives a key from a password using PBKDF2 (Password-Based Key Derivation Function 2).
    /// </summary>
    /// <param name="password">The password to derive from.</param>
    /// <param name="salt">The salt value.</param>
    /// <param name="iterations">The number of iterations.</param>
    /// <param name="keyLength">The desired key length in bytes.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use (default: SHA256).</param>
    /// <returns>The derived key.</returns>
    byte[] DerivePbkdf2(
        byte[] password,
        byte[] salt,
        int iterations,
        int keyLength,
        HashAlgorithmName hashAlgorithm = default);

    /// <summary>
    /// Derives a key from a password using PBKDF2 asynchronously.
    /// </summary>
    /// <param name="password">The password to derive from.</param>
    /// <param name="salt">The salt value.</param>
    /// <param name="iterations">The number of iterations.</param>
    /// <param name="keyLength">The desired key length in bytes.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The derived key.</returns>
    Task<byte[]> DerivePbkdf2Async(
        byte[] password,
        byte[] salt,
        int iterations,
        int keyLength,
        HashAlgorithmName hashAlgorithm = default,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Derives a key using HKDF (HMAC-based Key Derivation Function).
    /// </summary>
    /// <param name="ikm">The input keying material.</param>
    /// <param name="keyLength">The desired key length in bytes.</param>
    /// <param name="salt">Optional salt value.</param>
    /// <param name="info">Optional context/application specific information.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    /// <returns>The derived key.</returns>
    byte[] DeriveHkdf(
        byte[] ikm,
        int keyLength,
        byte[]? salt = null,
        byte[]? info = null,
        HashAlgorithmName hashAlgorithm = default);

    /// <summary>
    /// Derives a key using HKDF asynchronously.
    /// </summary>
    /// <param name="ikm">The input keying material.</param>
    /// <param name="keyLength">The desired key length in bytes.</param>
    /// <param name="salt">Optional salt value.</param>
    /// <param name="info">Optional context/application specific information.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The derived key.</returns>
    Task<byte[]> DeriveHkdfAsync(
        byte[] ikm,
        int keyLength,
        byte[]? salt = null,
        byte[]? info = null,
        HashAlgorithmName hashAlgorithm = default,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Derives a key using scrypt algorithm.
    /// </summary>
    /// <param name="password">The password to derive from.</param>
    /// <param name="salt">The salt value.</param>
    /// <param name="n">The CPU/memory cost parameter (must be power of 2).</param>
    /// <param name="r">The block size parameter.</param>
    /// <param name="p">The parallelization parameter.</param>
    /// <param name="keyLength">The desired key length in bytes.</param>
    /// <returns>The derived key.</returns>
    byte[] DeriveScrypt(
        byte[] password,
        byte[] salt,
        int n,
        int r,
        int p,
        int keyLength);

    /// <summary>
    /// Derives a key for a specific context/purpose from a master key.
    /// </summary>
    /// <param name="masterKey">The master key.</param>
    /// <param name="context">The derivation context/purpose.</param>
    /// <param name="keyLength">The desired key length in bytes.</param>
    /// <returns>The derived key.</returns>
    byte[] DeriveKey(byte[] masterKey, string context, int keyLength);
}

/// <summary>
/// Represents a hash algorithm name for key derivation.
/// </summary>
public readonly struct HashAlgorithmName : IEquatable<HashAlgorithmName>
{
    private readonly string? name;

    private HashAlgorithmName(string? name)
    {
        this.name = name;
    }

    /// <summary>Gets SHA256 hash algorithm.</summary>
    public static HashAlgorithmName SHA256 { get; } = new("SHA256");

    /// <summary>Gets SHA384 hash algorithm.</summary>
    public static HashAlgorithmName SHA384 { get; } = new("SHA384");

    /// <summary>Gets SHA512 hash algorithm.</summary>
    public static HashAlgorithmName SHA512 { get; } = new("SHA512");

    /// <summary>Gets SHA3-256 hash algorithm.</summary>
    public static HashAlgorithmName SHA3256 { get; } = new("SHA3-256");

    /// <summary>Gets SHA3-384 hash algorithm.</summary>
    public static HashAlgorithmName SHA3384 { get; } = new("SHA3-384");

    /// <summary>Gets SHA3-512 hash algorithm.</summary>
    public static HashAlgorithmName SHA3512 { get; } = new("SHA3-512");

    /// <summary>Gets Blake2b hash algorithm.</summary>
    public static HashAlgorithmName Blake2b { get; } = new("Blake2b");

    /// <summary>Gets the algorithm name.</summary>
    public string Name => name ?? "SHA256";

    /// <summary>
    /// Creates a custom hash algorithm name.
    /// </summary>
    /// <param name="name">The algorithm name.</param>
    /// <returns>A new HashAlgorithmName instance.</returns>
    public static HashAlgorithmName Create(string name) => new(name);

    /// <inheritdoc/>
    public override string ToString() => Name;

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is HashAlgorithmName other && Equals(other);

    /// <inheritdoc/>
    public bool Equals(HashAlgorithmName other) => string.Equals(name, other.name, StringComparison.OrdinalIgnoreCase);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
#if NETSTANDARD2_0
        return name?.ToUpperInvariant().GetHashCode() ?? 0;
#else
        return name?.GetHashCode(StringComparison.OrdinalIgnoreCase) ?? 0;
#endif
    }

    /// <summary>Equality operator.</summary>
    public static bool operator ==(HashAlgorithmName left, HashAlgorithmName right) => left.Equals(right);

    /// <summary>Inequality operator.</summary>
    public static bool operator !=(HashAlgorithmName left, HashAlgorithmName right) => !left.Equals(right);
}
