namespace HeroCrypt.Abstractions;

/// <summary>
/// Interface for elliptic curve cryptographic operations
/// </summary>
public interface IEllipticCurveService
{
    /// <summary>
    /// Generates a new key pair for the specified curve
    /// </summary>
    /// <param name="curve">The elliptic curve to use</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Generated key pair</returns>
    Task<EccKeyPair> GenerateKeyPairAsync(EccCurve curve, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs ECDH key agreement
    /// </summary>
    /// <param name="privateKey">Local private key</param>
    /// <param name="publicKey">Remote public key</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Shared secret</returns>
    Task<byte[]> PerformEcdhAsync(byte[] privateKey, byte[] publicKey, CancellationToken cancellationToken = default);

    /// <summary>
    /// Signs data using ECDSA
    /// </summary>
    /// <param name="data">Data to sign</param>
    /// <param name="privateKey">Private key for signing</param>
    /// <param name="curve">Elliptic curve to use</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Digital signature</returns>
    Task<byte[]> SignAsync(byte[] data, byte[] privateKey, EccCurve curve, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a digital signature using ECDSA
    /// </summary>
    /// <param name="data">Original data</param>
    /// <param name="signature">Signature to verify</param>
    /// <param name="publicKey">Public key for verification</param>
    /// <param name="curve">Elliptic curve to use</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if signature is valid</returns>
    Task<bool> VerifyAsync(byte[] data, byte[] signature, byte[] publicKey, EccCurve curve, CancellationToken cancellationToken = default);

    /// <summary>
    /// Derives a public key from a private key
    /// </summary>
    /// <param name="privateKey">Private key</param>
    /// <param name="curve">Elliptic curve to use</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Corresponding public key</returns>
    Task<byte[]> DerivePublicKeyAsync(byte[] privateKey, EccCurve curve, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates that a point lies on the specified curve
    /// </summary>
    /// <param name="point">Point to validate</param>
    /// <param name="curve">Elliptic curve</param>
    /// <returns>True if point is valid</returns>
    bool ValidatePoint(byte[] point, EccCurve curve);

    /// <summary>
    /// Compresses a public key point
    /// </summary>
    /// <param name="uncompressedPoint">Uncompressed public key</param>
    /// <param name="curve">Elliptic curve</param>
    /// <returns>Compressed public key</returns>
    byte[] CompressPoint(byte[] uncompressedPoint, EccCurve curve);

    /// <summary>
    /// Decompresses a public key point
    /// </summary>
    /// <param name="compressedPoint">Compressed public key</param>
    /// <param name="curve">Elliptic curve</param>
    /// <returns>Uncompressed public key</returns>
    byte[] DecompressPoint(byte[] compressedPoint, EccCurve curve);
}

/// <summary>
/// Supported elliptic curves
/// </summary>
public enum EccCurve
{
    /// <summary>
    /// Curve25519 - Montgomery curve for key agreement
    /// </summary>
    Curve25519,

    /// <summary>
    /// Ed25519 - Edwards curve for digital signatures
    /// </summary>
    Ed25519,

    /// <summary>
    /// secp256k1 - Used by Bitcoin and Ethereum
    /// </summary>
    Secp256k1,

    /// <summary>
    /// secp256r1 (P-256) - NIST standard curve
    /// </summary>
    Secp256r1,

    /// <summary>
    /// secp384r1 (P-384) - NIST standard curve
    /// </summary>
    Secp384r1,

    /// <summary>
    /// secp521r1 (P-521) - NIST standard curve
    /// </summary>
    Secp521r1
}

/// <summary>
/// Elliptic curve key pair
/// </summary>
public readonly struct EccKeyPair
{
    /// <summary>
    /// Initializes a new ECC key pair
    /// </summary>
    /// <param name="privateKey">Private key bytes</param>
    /// <param name="publicKey">Public key bytes</param>
    /// <param name="curve">Elliptic curve</param>
    public EccKeyPair(byte[] privateKey, byte[] publicKey, EccCurve curve)
    {
        PrivateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
        PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        Curve = curve;
    }

    /// <summary>
    /// Private key bytes
    /// </summary>
    public byte[] PrivateKey { get; }

    /// <summary>
    /// Public key bytes
    /// </summary>
    public byte[] PublicKey { get; }

    /// <summary>
    /// Elliptic curve used
    /// </summary>
    public EccCurve Curve { get; }

    /// <summary>
    /// Gets the private key size in bytes for the curve
    /// </summary>
    public int PrivateKeySize => GetPrivateKeySize(Curve);

    /// <summary>
    /// Gets the public key size in bytes for the curve
    /// </summary>
    public int PublicKeySize => GetPublicKeySize(Curve);

    /// <summary>
    /// Gets the private key size for a specific curve
    /// </summary>
    public static int GetPrivateKeySize(EccCurve curve) => curve switch
    {
        EccCurve.Curve25519 => 32,
        EccCurve.Ed25519 => 32,
        EccCurve.Secp256k1 => 32,
        EccCurve.Secp256r1 => 32,
        EccCurve.Secp384r1 => 48,
        EccCurve.Secp521r1 => 66,
        _ => throw new ArgumentException($"Unknown curve: {curve}")
    };

    /// <summary>
    /// Gets the public key size for a specific curve (uncompressed)
    /// </summary>
    public static int GetPublicKeySize(EccCurve curve) => curve switch
    {
        EccCurve.Curve25519 => 32,
        EccCurve.Ed25519 => 32,
        EccCurve.Secp256k1 => 65, // Uncompressed: 0x04 + x + y
        EccCurve.Secp256r1 => 65,
        EccCurve.Secp384r1 => 97,
        EccCurve.Secp521r1 => 133,
        _ => throw new ArgumentException($"Unknown curve: {curve}")
    };

    /// <summary>
    /// Gets the compressed public key size for a specific curve
    /// </summary>
    public static int GetCompressedPublicKeySize(EccCurve curve) => curve switch
    {
        EccCurve.Curve25519 => 32,
        EccCurve.Ed25519 => 32,
        EccCurve.Secp256k1 => 33, // Compressed: 0x02/0x03 + x
        EccCurve.Secp256r1 => 33,
        EccCurve.Secp384r1 => 49,
        EccCurve.Secp521r1 => 67,
        _ => throw new ArgumentException($"Unknown curve: {curve}")
    };
}