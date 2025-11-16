namespace HeroCrypt.KeyManagement;

/// <summary>
/// Service for generating cryptographically secure keys and key material for various algorithms
/// </summary>
public interface ICryptographicKeyGenerator
{
    /// <summary>
    /// Generates cryptographically secure random bytes
    /// </summary>
    /// <param name="length">Number of bytes to generate</param>
    /// <returns>Array of cryptographically secure random bytes</returns>
    byte[] GenerateRandomBytes(int length);

    /// <summary>
    /// Asynchronously generates cryptographically secure random bytes
    /// </summary>
    /// <param name="length">Number of bytes to generate</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Array of cryptographically secure random bytes</returns>
    Task<byte[]> GenerateRandomBytesAsync(int length, CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates a symmetric encryption key of specified length
    /// </summary>
    /// <param name="keyLength">Key length in bytes</param>
    /// <returns>Symmetric encryption key</returns>
    byte[] GenerateSymmetricKey(int keyLength);

    /// <summary>
    /// Generates a symmetric encryption key for the specified algorithm
    /// </summary>
    /// <param name="algorithm">Symmetric algorithm (AES, ChaCha20, etc.)</param>
    /// <returns>Symmetric encryption key</returns>
    byte[] GenerateSymmetricKey(CryptographicAlgorithm algorithm);

    /// <summary>
    /// Generates an initialization vector (IV) of specified length
    /// </summary>
    /// <param name="ivLength">IV length in bytes</param>
    /// <returns>Initialization vector</returns>
    byte[] GenerateIV(int ivLength);

    /// <summary>
    /// Generates an initialization vector for the specified algorithm
    /// </summary>
    /// <param name="algorithm">Symmetric algorithm</param>
    /// <returns>Initialization vector</returns>
    byte[] GenerateIV(CryptographicAlgorithm algorithm);

    /// <summary>
    /// Generates a cryptographic salt for key derivation
    /// </summary>
    /// <param name="saltLength">Salt length in bytes (default: 32)</param>
    /// <returns>Cryptographic salt</returns>
    byte[] GenerateSalt(int saltLength = 32);

    /// <summary>
    /// Generates a random nonce for use with algorithms that require unique values
    /// </summary>
    /// <param name="nonceLength">Nonce length in bytes</param>
    /// <returns>Random nonce</returns>
    byte[] GenerateNonce(int nonceLength);

    /// <summary>
    /// Generates a random nonce for the specified algorithm
    /// </summary>
    /// <param name="algorithm">Algorithm that will use the nonce</param>
    /// <returns>Random nonce</returns>
    byte[] GenerateNonce(NonceAlgorithm algorithm);

    /// <summary>
    /// Generates an RSA key pair with the specified key size
    /// </summary>
    /// <param name="keySize">RSA key size in bits (1024, 2048, 3072, 4096)</param>
    /// <returns>RSA key pair (private key, public key)</returns>
    (byte[] privateKey, byte[] publicKey) GenerateRsaKeyPair(int keySize = 2048);

    /// <summary>
    /// Asynchronously generates an RSA key pair with the specified key size
    /// </summary>
    /// <param name="keySize">RSA key size in bits</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>RSA key pair (private key, public key)</returns>
    Task<(byte[] privateKey, byte[] publicKey)> GenerateRsaKeyPairAsync(int keySize = 2048, CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates key material for HMAC operations
    /// </summary>
    /// <param name="algorithm">Hash algorithm for HMAC</param>
    /// <returns>HMAC key</returns>
    byte[] GenerateHmacKey(HashAlgorithmName algorithm);

    /// <summary>
    /// Generates key material suitable for key derivation functions
    /// </summary>
    /// <param name="keyLength">Desired key length in bytes</param>
    /// <returns>Key derivation material</returns>
    byte[] GenerateKeyDerivationMaterial(int keyLength = 32);

    /// <summary>
    /// Validates that the provided key material meets cryptographic standards
    /// </summary>
    /// <param name="keyMaterial">Key material to validate</param>
    /// <param name="algorithm">Algorithm the key will be used with</param>
    /// <returns>True if key material is cryptographically suitable</returns>
    bool ValidateKeyMaterial(byte[] keyMaterial, string algorithm);

    /// <summary>
    /// Generates a secure password with specified parameters
    /// </summary>
    /// <param name="length">Password length</param>
    /// <param name="includeSymbols">Include special symbols</param>
    /// <param name="includeNumbers">Include numbers</param>
    /// <param name="includeUppercase">Include uppercase letters</param>
    /// <param name="includeLowercase">Include lowercase letters</param>
    /// <returns>Secure password string</returns>
    string GenerateSecurePassword(int length = 32, bool includeSymbols = true, bool includeNumbers = true,
        bool includeUppercase = true, bool includeLowercase = true);
}

/// <summary>
/// Supported symmetric algorithms for key generation
/// </summary>
public enum CryptographicAlgorithm
{
    /// <summary>AES-128 (16 byte key, 16 byte IV)</summary>
    Aes128,
    /// <summary>AES-192 (24 byte key, 16 byte IV)</summary>
    Aes192,
    /// <summary>AES-256 (32 byte key, 16 byte IV)</summary>
    Aes256,
    /// <summary>ChaCha20 (32 byte key, 12 byte nonce)</summary>
    ChaCha20,
    /// <summary>ChaCha20-Poly1305 (32 byte key, 12 byte nonce)</summary>
    ChaCha20Poly1305
}

/// <summary>
/// Supported algorithms that use nonces
/// </summary>
public enum NonceAlgorithm
{
    /// <summary>ChaCha20 (12 byte nonce)</summary>
    ChaCha20,
    /// <summary>ChaCha20-Poly1305 (12 byte nonce)</summary>
    ChaCha20Poly1305,
    /// <summary>AES-GCM (12 byte nonce recommended)</summary>
    AesGcm
}

