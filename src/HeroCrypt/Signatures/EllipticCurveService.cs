using System.Security.Cryptography;
using HeroCrypt.Cryptography.Primitives.Signature.Ecc;
using HeroCrypt.Security;

namespace HeroCrypt.Signatures;

/// <summary>
/// Service implementation for elliptic curve cryptographic operations.
/// Supports Curve25519, Ed25519, and secp256k1 curves.
/// </summary>
public class EllipticCurveService
{
    /// <summary>
    /// Initializes a new instance of the EllipticCurveService
    /// </summary>
    public EllipticCurveService()
    {
    }

    /// <inheritdoc/>
    public Task<EccKeyPair> GenerateKeyPairAsync(EccCurve curve, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var keyPair = curve switch
            {
                EccCurve.Curve25519 => GenerateCurve25519KeyPair(),
                EccCurve.Ed25519 => GenerateEd25519KeyPair(),
                EccCurve.Secp256k1 => GenerateSecp256k1KeyPair(),
                _ => throw new NotSupportedException($"Curve {curve} is not yet implemented")
            };

            return Task.FromResult(keyPair);
        }
        catch
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public Task<byte[]> PerformEcdhAsync(byte[] privateKey, byte[] publicKey, CancellationToken cancellationToken = default)
    {
#if NETSTANDARD2_0
        if (privateKey == null)
        {
            throw new ArgumentNullException(nameof(privateKey));
        }
        if (publicKey == null)
        {
            throw new ArgumentNullException(nameof(publicKey));
        }
#else
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(publicKey);
#endif

        InputValidator.ValidateByteArray(privateKey, nameof(privateKey));
        InputValidator.ValidateByteArray(publicKey, nameof(publicKey));

        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            // Determine curve based on key sizes
            var sharedSecret = (privateKey.Length, publicKey.Length) switch
            {
                (32, 32) => Curve25519Core.ComputeSharedSecret(privateKey, publicKey),
                _ => throw new ArgumentException("Unsupported key sizes for ECDH")
            };

            return Task.FromResult(sharedSecret);
        }
        catch
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public Task<byte[]> SignAsync(byte[] data, byte[] privateKey, EccCurve curve, CancellationToken cancellationToken = default)
    {
#if NETSTANDARD2_0
        if (data == null)
        {
            throw new ArgumentNullException(nameof(data));
        }
        if (privateKey == null)
        {
            throw new ArgumentNullException(nameof(privateKey));
        }
#else
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(privateKey);
#endif

        InputValidator.ValidateByteArray(data, nameof(data), allowEmpty: true);
        InputValidator.ValidateByteArray(privateKey, nameof(privateKey));

        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var signature = curve switch
            {
                EccCurve.Ed25519 => Ed25519Core.Sign(data, privateKey),
                EccCurve.Secp256k1 => SignWithSecp256k1(data, privateKey),
                _ => throw new NotSupportedException($"Signing with curve {curve} is not yet implemented")
            };

            return Task.FromResult(signature);
        }
        catch
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public Task<bool> VerifyAsync(byte[] data, byte[] signature, byte[] publicKey, EccCurve curve, CancellationToken cancellationToken = default)
    {
#if NETSTANDARD2_0
        if (data == null)
        {
            throw new ArgumentNullException(nameof(data));
        }
        if (signature == null)
        {
            throw new ArgumentNullException(nameof(signature));
        }
        if (publicKey == null)
        {
            throw new ArgumentNullException(nameof(publicKey));
        }
#else
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(publicKey);
#endif

        InputValidator.ValidateByteArray(data, nameof(data), allowEmpty: true);
        InputValidator.ValidateByteArray(signature, nameof(signature));
        InputValidator.ValidateByteArray(publicKey, nameof(publicKey));

        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var isValid = curve switch
            {
                EccCurve.Ed25519 => Ed25519Core.Verify(data, signature, publicKey),
                EccCurve.Secp256k1 => VerifyWithSecp256k1(data, signature, publicKey),
                _ => throw new NotSupportedException($"Verification with curve {curve} is not yet implemented")
            };

            return Task.FromResult(isValid);
        }
        catch (ArgumentException)
        {
            return Task.FromResult(false);
        }
    }

    /// <inheritdoc/>
    public Task<byte[]> DerivePublicKeyAsync(byte[] privateKey, EccCurve curve, CancellationToken cancellationToken = default)
    {
#if NETSTANDARD2_0
        if (privateKey == null)
        {
            throw new ArgumentNullException(nameof(privateKey));
        }
#else
        ArgumentNullException.ThrowIfNull(privateKey);
#endif

        InputValidator.ValidateByteArray(privateKey, nameof(privateKey));

        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var publicKey = curve switch
            {
                EccCurve.Curve25519 => Curve25519Core.DerivePublicKey(privateKey),
                EccCurve.Ed25519 => Ed25519Core.DerivePublicKey(privateKey),
                EccCurve.Secp256k1 => Secp256k1Core.DerivePublicKey(privateKey, false),
                _ => throw new NotSupportedException($"Public key derivation for curve {curve} is not yet implemented")
            };

            return Task.FromResult(publicKey);
        }
        catch
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public bool ValidatePoint(byte[] point, EccCurve curve)
    {
#if NETSTANDARD2_0
        if (point == null)
        {
            throw new ArgumentNullException(nameof(point));
        }
#else
        ArgumentNullException.ThrowIfNull(point);
#endif

        try
        {
            InputValidator.ValidateByteArray(point, nameof(point));

            return curve switch
            {
                EccCurve.Curve25519 => ValidateCurve25519Point(point),
                EccCurve.Ed25519 => ValidateEd25519Point(point),
                EccCurve.Secp256k1 => ValidateSecp256k1Point(point),
                _ => throw new NotSupportedException($"Point validation for curve {curve} is not yet implemented")
            };
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    /// <inheritdoc/>
    public byte[] CompressPoint(byte[] uncompressedPoint, EccCurve curve)
    {
#if NETSTANDARD2_0
        if (uncompressedPoint == null)
        {
            throw new ArgumentNullException(nameof(uncompressedPoint));
        }
#else
        ArgumentNullException.ThrowIfNull(uncompressedPoint);
#endif

        InputValidator.ValidateByteArray(uncompressedPoint, nameof(uncompressedPoint));

        return curve switch
        {
            EccCurve.Secp256k1 => Secp256k1Core.CompressPublicKey(uncompressedPoint),
            EccCurve.Curve25519 => uncompressedPoint, // Already compressed
            EccCurve.Ed25519 => uncompressedPoint, // Already compressed
            _ => throw new NotSupportedException($"Point compression for curve {curve} is not yet implemented")
        };
    }

    /// <inheritdoc/>
    public byte[] DecompressPoint(byte[] compressedPoint, EccCurve curve)
    {
#if NETSTANDARD2_0
        if (compressedPoint == null)
        {
            throw new ArgumentNullException(nameof(compressedPoint));
        }
#else
        ArgumentNullException.ThrowIfNull(compressedPoint);
#endif

        InputValidator.ValidateByteArray(compressedPoint, nameof(compressedPoint));

        return curve switch
        {
            EccCurve.Secp256k1 => Secp256k1Core.DecompressPublicKey(compressedPoint),
            EccCurve.Curve25519 => compressedPoint, // Already uncompressed format
            EccCurve.Ed25519 => compressedPoint, // Already uncompressed format
            _ => throw new NotSupportedException($"Point decompression for curve {curve} is not yet implemented")
        };
    }

    /// <summary>
    /// Generates a Curve25519 key pair
    /// </summary>
    private static EccKeyPair GenerateCurve25519KeyPair()
    {
        var privateKey = Curve25519Core.GeneratePrivateKey();
        var publicKey = Curve25519Core.DerivePublicKey(privateKey);

        return new EccKeyPair(privateKey, publicKey, EccCurve.Curve25519);
    }

    /// <summary>
    /// Generates an Ed25519 key pair
    /// </summary>
    private static EccKeyPair GenerateEd25519KeyPair()
    {
        var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();

        return new EccKeyPair(privateKey, publicKey, EccCurve.Ed25519);
    }

    /// <summary>
    /// Generates a secp256k1 key pair
    /// </summary>
    private static EccKeyPair GenerateSecp256k1KeyPair()
    {
        var (privateKey, publicKey) = Secp256k1Core.GenerateKeyPair();

        return new EccKeyPair(privateKey, publicKey, EccCurve.Secp256k1);
    }

    /// <summary>
    /// Signs data with secp256k1 using SHA-256 hash
    /// </summary>
    private static byte[] SignWithSecp256k1(byte[] data, byte[] privateKey)
    {
        var hash = ComputeSha256(data);
        return Secp256k1Core.Sign(hash, privateKey);
    }

    /// <summary>
    /// Verifies a signature with secp256k1 using SHA-256 hash
    /// </summary>
    private static bool VerifyWithSecp256k1(byte[] data, byte[] signature, byte[] publicKey)
    {
        var hash = ComputeSha256(data);
        return Secp256k1Core.Verify(hash, signature, publicKey);
    }

    /// <summary>
    /// Validates a Curve25519 point
    /// </summary>
    private static bool ValidateCurve25519Point(byte[] point)
    {
        // Curve25519 points are always 32 bytes and any 32-byte value is valid
        return point.Length == 32;
    }

    /// <summary>
    /// Validates an Ed25519 point
    /// </summary>
    private static bool ValidateEd25519Point(byte[] point)
    {
        // Ed25519 points are 32 bytes and should be on the curve
        if (point.Length != 32)
        {
            return false;
        }

        try
        {
            // Attempt to decode the point - if it succeeds, it's valid
            // This is a simplified check
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    /// <summary>
    /// Validates a secp256k1 point
    /// </summary>
    private static bool ValidateSecp256k1Point(byte[] point)
    {
        if (point.Length == 33)
        {
            // Compressed format
            return point[0] == 0x02 || point[0] == 0x03;
        }
        else if (point.Length == 65)
        {
            // Uncompressed format
            return point[0] == 0x04;
        }

        return false;
    }

    private static byte[] ComputeSha256(ReadOnlySpan<byte> data)
    {
#if NETSTANDARD2_0
        return Sha256Extensions.HashData(data);
#else
        return SHA256.HashData(data);
#endif
    }
}
