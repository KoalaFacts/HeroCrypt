using HeroCrypt.Encryption;
using HeroCrypt.Hashing;
using HeroCrypt.KeyManagement;
using HeroCrypt.Signatures;
using Microsoft.Extensions.DependencyInjection;
using System.Diagnostics.CodeAnalysis;

namespace HeroCrypt;

/// <summary>
/// Primary entry point for all HeroCrypt cryptographic operations.
/// This class is DI-aware and works with the plugin-based architecture.
/// </summary>
/// <remarks>
/// <para>
/// HeroCryptBuilder provides a unified API for all cryptographic operations in HeroCrypt.
/// It integrates with dependency injection and supports plugin-based extensibility.
/// </para>
///
/// <para><strong>Usage Patterns:</strong></para>
/// <list type="bullet">
///   <item><description><strong>With DI Container:</strong> Resolve IHeroCrypt from the service provider</description></item>
///   <item><description><strong>Direct Static Access:</strong> Use static methods for quick operations</description></item>
///   <item><description><strong>Service-Based:</strong> Create instance with IServiceProvider for full plugin support</description></item>
/// </list>
/// </remarks>
/// <example>
/// <code>
/// // Method 1: Using DI Container (recommended for applications)
/// services.AddHeroCrypt();
/// var heroCrypt = serviceProvider.GetRequiredService&lt;IHeroCrypt&gt;();
///
/// // Method 2: Direct static access (for simple scenarios)
/// var hash = HeroCryptBuilder.Hash.Compute(data, HashAlgorithm.Sha256);
/// var signature = HeroCryptBuilder.Signature.Sign(data, privateKey, SignatureAlgorithm.EdDsa);
///
/// // Method 3: Service-based builder (for plugin support without full DI)
/// var builder = new HeroCryptBuilder(serviceProvider);
/// var blake2bService = builder.GetBlake2bService();
/// var hash = await blake2bService.ComputeHashAsync(data);
/// </code>
/// </example>
public sealed class HeroCryptBuilder
{
    private readonly IServiceProvider _serviceProvider;

    /// <summary>
    /// Creates a new HeroCryptBuilder with service provider
    /// </summary>
    /// <param name="serviceProvider">The service provider for resolving services</param>
    public HeroCryptBuilder(IServiceProvider serviceProvider)
    {
#if NET6_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(serviceProvider);
#else
        if (serviceProvider == null) throw new ArgumentNullException(nameof(serviceProvider));
#endif
        _serviceProvider = serviceProvider;
    }

    /// <summary>
    /// Gets the hashing service from DI container
    /// </summary>
    public IPasswordHashingService GetHashingService() =>
        _serviceProvider.GetRequiredService<IPasswordHashingService>();

    /// <summary>
    /// Gets the BLAKE2b service from DI container
    /// </summary>
    public IBlake2bService GetBlake2bService() =>
        _serviceProvider.GetRequiredService<IBlake2bService>();

    /// <summary>
    /// Gets the digital signature service from DI container
    /// </summary>
    public IDigitalSignatureService GetDigitalSignatureService() =>
        _serviceProvider.GetRequiredService<IDigitalSignatureService>();

    /// <summary>
    /// Gets the AEAD service from DI container
    /// </summary>
    public IAeadService GetAeadService() =>
        _serviceProvider.GetRequiredService<IAeadService>();

    /// <summary>
    /// Gets the elliptic curve service from DI container
    /// </summary>
    public IEllipticCurveService GetEllipticCurveService() =>
        _serviceProvider.GetRequiredService<IEllipticCurveService>();

    /// <summary>
    /// Gets the key derivation service from DI container
    /// </summary>
    public IKeyDerivationService GetKeyDerivationService() =>
        _serviceProvider.GetRequiredService<IKeyDerivationService>();

    /// <summary>
    /// Gets the cryptography service from DI container
    /// </summary>
    public ICryptographyService GetCryptographyService() =>
        _serviceProvider.GetRequiredService<ICryptographyService>();


    #region Static API for Direct Access

    /// <summary>
    /// Hashing operations (SHA-2, SHA-3, BLAKE2b, etc.)
    /// </summary>
    /// <remarks>
    /// These static methods provide direct access to low-level implementations.
    /// For plugin support and DI integration, use the instance methods instead.
    /// </remarks>
    public static class Hash
    {
        /// <summary>
        /// Computes a hash of the data using the specified algorithm
        /// </summary>
        /// <param name="data">The data to hash</param>
        /// <param name="algorithm">The hash algorithm to use</param>
        /// <returns>The computed hash</returns>
        public static byte[] Compute(byte[] data, Hashing.HashAlgorithm algorithm) =>
            Hashing.Hash.Compute(data, algorithm);

        /// <summary>
        /// Computes a keyed hash (HMAC) of the data
        /// </summary>
        /// <param name="data">The data to hash</param>
        /// <param name="key">The key for HMAC</param>
        /// <param name="algorithm">The hash algorithm to use</param>
        /// <returns>The computed keyed hash</returns>
        public static byte[] ComputeKeyed(byte[] data, byte[] key, Hashing.HashAlgorithm algorithm) =>
            Hashing.Hash.ComputeKeyed(data, key, algorithm);
    }

    /// <summary>
    /// Digital signature operations (RSA, ECDSA, EdDSA, HMAC)
    /// </summary>
    /// <remarks>
    /// These static methods provide direct access to low-level implementations.
    /// For plugin support and DI integration, use the instance methods instead.
    /// </remarks>
    public static class Signature
    {
        /// <summary>
        /// Signs data using the specified algorithm
        /// </summary>
        /// <param name="data">The data to sign</param>
        /// <param name="key">The signing key</param>
        /// <param name="algorithm">The signature algorithm to use</param>
        /// <returns>The signature</returns>
        public static byte[] Sign(byte[] data, byte[] key, Signatures.SignatureAlgorithm algorithm) =>
            Signatures.DigitalSignature.Sign(data, key, algorithm);

        /// <summary>
        /// Verifies a signature
        /// </summary>
        /// <param name="data">The data that was signed</param>
        /// <param name="signature">The signature to verify</param>
        /// <param name="key">The verification key</param>
        /// <param name="algorithm">The signature algorithm used</param>
        /// <returns>True if the signature is valid, false otherwise</returns>
        public static bool Verify(byte[] data, byte[] signature, byte[] key, Signatures.SignatureAlgorithm algorithm) =>
            Signatures.DigitalSignature.Verify(data, signature, key, algorithm);
    }

    /// <summary>
    /// Encryption and decryption operations (AES-GCM, ChaCha20-Poly1305, RSA-OAEP, etc.)
    /// </summary>
    /// <remarks>
    /// These static methods provide direct access to low-level implementations.
    /// For plugin support and DI integration, use the instance methods instead.
    /// </remarks>
    public static class Encryption
    {
        /// <summary>
        /// Encrypts data using the specified algorithm
        /// </summary>
        /// <param name="plaintext">The data to encrypt</param>
        /// <param name="key">The encryption key</param>
        /// <param name="algorithm">The encryption algorithm to use</param>
        /// <param name="associatedData">Optional authenticated associated data (for AEAD)</param>
        /// <returns>The encryption result containing ciphertext and nonce</returns>
        public static HeroCrypt.Encryption.EncryptionResult Encrypt(
            byte[] plaintext,
            byte[] key,
            HeroCrypt.Encryption.EncryptionAlgorithm algorithm,
            byte[]? associatedData = null) =>
            HeroCrypt.Encryption.Encryption.Encrypt(plaintext, key, algorithm, associatedData ?? Array.Empty<byte>());

        /// <summary>
        /// Decrypts data using the specified algorithm
        /// </summary>
        /// <param name="ciphertext">The encrypted data</param>
        /// <param name="key">The decryption key</param>
        /// <param name="nonce">The nonce used during encryption</param>
        /// <param name="algorithm">The encryption algorithm used</param>
        /// <param name="associatedData">Optional authenticated associated data (for AEAD)</param>
        /// <param name="keyCiphertext">For hybrid encryption, the encapsulated key ciphertext</param>
        /// <returns>The decrypted plaintext</returns>
        public static byte[] Decrypt(
            byte[] ciphertext,
            byte[] key,
            byte[] nonce,
            HeroCrypt.Encryption.EncryptionAlgorithm algorithm,
            byte[]? associatedData = null,
            byte[]? keyCiphertext = null) =>
            HeroCrypt.Encryption.Encryption.Decrypt(
                ciphertext,
                key,
                nonce,
                algorithm,
                associatedData ?? Array.Empty<byte>(),
                keyCiphertext);
    }

    /// <summary>
    /// Password hashing operations using Argon2 (RFC 9106)
    /// </summary>
    /// <remarks>
    /// These static methods provide direct access to low-level implementations.
    /// For plugin support and DI integration, use the instance methods instead.
    /// </remarks>
    public static class Argon2
    {
        /// <summary>
        /// Hashes a password using Argon2
        /// </summary>
        /// <param name="password">The password to hash</param>
        /// <param name="salt">The salt (recommended: 16 bytes minimum)</param>
        /// <param name="iterations">Number of iterations (time cost)</param>
        /// <param name="memorySize">Memory size in KB</param>
        /// <param name="parallelism">Degree of parallelism</param>
        /// <param name="hashLength">Output hash length in bytes</param>
        /// <param name="type">Argon2 variant (Argon2d, Argon2i, or Argon2id recommended)</param>
        /// <param name="associatedData">Optional associated data</param>
        /// <param name="secret">Optional secret key</param>
        /// <returns>The computed hash</returns>
        public static byte[] Hash(
            byte[] password,
            byte[] salt,
            int iterations,
            int memorySize,
            int parallelism,
            int hashLength,
            Cryptography.Primitives.Kdf.Argon2Type type,
            byte[]? associatedData = null,
            byte[]? secret = null) =>
            Cryptography.Primitives.Kdf.Argon2Core.Hash(
                password,
                salt,
                iterations,
                memorySize,
                parallelism,
                hashLength,
                type,
                associatedData,
                secret);
    }

    /// <summary>
    /// BLAKE2b hashing operations (RFC 7693)
    /// </summary>
    /// <remarks>
    /// These static methods provide direct access to low-level implementations.
    /// For plugin support and DI integration, use the instance methods instead.
    /// </remarks>
    public static class Blake2b
    {
        /// <summary>
        /// Computes BLAKE2b hash of the input data
        /// </summary>
        /// <param name="data">The data to hash</param>
        /// <param name="hashSize">The hash size in bytes (1-64)</param>
        /// <param name="key">Optional key for keyed hashing (0-64 bytes)</param>
        /// <returns>The computed hash</returns>
        public static byte[] Compute(byte[] data, int hashSize = 64, byte[]? key = null) =>
            Cryptography.Primitives.Hash.Blake2bCore.ComputeHash(data, hashSize, key);
    }

#if NET10_0_OR_GREATER
    /// <summary>
    /// Quick access to Post-Quantum Cryptography operations
    /// </summary>
    /// <remarks>
    /// These static methods provide direct access to low-level implementations.
    /// For plugin support and DI integration, use the instance methods instead.
    /// </remarks>
    public static class PostQuantum
    {
        /// <summary>
        /// Quick access to ML-KEM operations
        /// </summary>
        [Experimental("SYSLIB5006")]
        public static class MLKem
        {
            /// <summary>
            /// Creates a new ML-KEM builder
            /// </summary>
            [Experimental("SYSLIB5006")]
            public static Cryptography.Primitives.PostQuantum.Kyber.MLKemBuilder Create() =>
                Cryptography.Primitives.PostQuantum.Kyber.MLKemBuilder.Create();

            /// <summary>
            /// Generates a key pair with default security (ML-KEM-768)
            /// </summary>
            [Experimental("SYSLIB5006")]
            public static Cryptography.Primitives.PostQuantum.Kyber.MLKemWrapper.MLKemKeyPair GenerateKeyPair() =>
                Cryptography.Primitives.PostQuantum.Kyber.MLKem.GenerateKeyPair();

            /// <summary>
            /// Generates a key pair with specified security level
            /// </summary>
            [Experimental("SYSLIB5006")]
            public static Cryptography.Primitives.PostQuantum.Kyber.MLKemWrapper.MLKemKeyPair GenerateKeyPair(
                Cryptography.Primitives.PostQuantum.Kyber.MLKemWrapper.SecurityLevel level) =>
                Cryptography.Primitives.PostQuantum.Kyber.MLKem.GenerateKeyPair(level);
        }

        /// <summary>
        /// Quick access to ML-DSA operations
        /// </summary>
        [Experimental("SYSLIB5006")]
        public static class MLDsa
        {
            /// <summary>
            /// Creates a new ML-DSA builder
            /// </summary>
            [Experimental("SYSLIB5006")]
            public static Cryptography.Primitives.PostQuantum.Dilithium.MLDsaBuilder Create() =>
                Cryptography.Primitives.PostQuantum.Dilithium.MLDsaBuilder.Create();

            /// <summary>
            /// Generates a key pair with default security (ML-DSA-65)
            /// </summary>
            [Experimental("SYSLIB5006")]
            public static Cryptography.Primitives.PostQuantum.Dilithium.MLDsaWrapper.MLDsaKeyPair GenerateKeyPair() =>
                Cryptography.Primitives.PostQuantum.Dilithium.MLDsa.GenerateKeyPair();

            /// <summary>
            /// Verifies a signature
            /// </summary>
            [Experimental("SYSLIB5006")]
            public static bool Verify(string publicKeyPem, byte[] data, byte[] signature) =>
                Cryptography.Primitives.PostQuantum.Dilithium.MLDsa.Verify(publicKeyPem, data, signature);
        }

        /// <summary>
        /// Quick access to SLH-DSA operations
        /// </summary>
        [Experimental("SYSLIB5006")]
        public static class SlhDsa
        {
            /// <summary>
            /// Creates a new SLH-DSA builder
            /// </summary>
            [Experimental("SYSLIB5006")]
            public static Cryptography.Primitives.PostQuantum.Sphincs.SlhDsaBuilder Create() =>
                Cryptography.Primitives.PostQuantum.Sphincs.SlhDsaBuilder.Create();

            /// <summary>
            /// Generates a key pair with default security (SLH-DSA-128s)
            /// </summary>
            [Experimental("SYSLIB5006")]
            public static Cryptography.Primitives.PostQuantum.Sphincs.SlhDsaWrapper.SlhDsaKeyPair GenerateKeyPair() =>
                Cryptography.Primitives.PostQuantum.Sphincs.SlhDsa.GenerateKeyPair();
        }
    }
#endif

    #endregion
}
