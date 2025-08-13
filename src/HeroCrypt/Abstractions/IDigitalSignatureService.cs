using System.Threading.Tasks;

namespace HeroCrypt.Abstractions;

/// <summary>
/// Interface for digital signature services
/// </summary>
public interface IDigitalSignatureService
{
    /// <summary>
    /// Generate a new key pair for digital signatures
    /// </summary>
    /// <returns>Private key and public key pair</returns>
    (byte[] privateKey, byte[] publicKey) GenerateKeyPair();

    /// <summary>
    /// Derive public key from private key
    /// </summary>
    /// <param name="privateKey">The private key</param>
    /// <returns>The corresponding public key</returns>
    byte[] DerivePublicKey(byte[] privateKey);

    /// <summary>
    /// Sign data with a private key
    /// </summary>
    /// <param name="data">Data to sign</param>
    /// <param name="privateKey">Private key for signing</param>
    /// <returns>Digital signature</returns>
    byte[] Sign(byte[] data, byte[] privateKey);

    /// <summary>
    /// Sign data asynchronously
    /// </summary>
    /// <param name="data">Data to sign</param>
    /// <param name="privateKey">Private key for signing</param>
    /// <returns>Digital signature</returns>
    Task<byte[]> SignAsync(byte[] data, byte[] privateKey);

    /// <summary>
    /// Verify a digital signature
    /// </summary>
    /// <param name="signature">Signature to verify</param>
    /// <param name="data">Original data that was signed</param>
    /// <param name="publicKey">Public key for verification</param>
    /// <returns>True if signature is valid, false otherwise</returns>
    bool Verify(byte[] signature, byte[] data, byte[] publicKey);

    /// <summary>
    /// Verify a digital signature asynchronously
    /// </summary>
    /// <param name="signature">Signature to verify</param>
    /// <param name="data">Original data that was signed</param>
    /// <param name="publicKey">Public key for verification</param>
    /// <returns>True if signature is valid, false otherwise</returns>
    Task<bool> VerifyAsync(byte[] signature, byte[] data, byte[] publicKey);

    /// <summary>
    /// Get the name of the signature algorithm
    /// </summary>
    string AlgorithmName { get; }

    /// <summary>
    /// Get the key size in bits
    /// </summary>
    int KeySizeBits { get; }

    /// <summary>
    /// Get the signature size in bytes
    /// </summary>
    int SignatureSize { get; }
}