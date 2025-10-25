namespace HeroCrypt.Abstractions;

/// <summary>
/// Authenticated Encryption with Associated Data (AEAD) service interface
/// Provides modern symmetric encryption with built-in authentication
/// </summary>
public interface IAeadService
{
    /// <summary>
    /// Encrypts data using AEAD with the specified algorithm
    /// </summary>
    /// <param name="plaintext">Data to encrypt</param>
    /// <param name="key">Encryption key</param>
    /// <param name="nonce">Nonce/IV (must be unique per key)</param>
    /// <param name="associatedData">Optional associated data to authenticate but not encrypt</param>
    /// <param name="algorithm">AEAD algorithm to use</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Encrypted data with authentication tag</returns>
    Task<byte[]> EncryptAsync(
        byte[] plaintext,
        byte[] key,
        byte[] nonce,
        byte[]? associatedData = null,
        AeadAlgorithm algorithm = AeadAlgorithm.ChaCha20Poly1305,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypts and verifies AEAD data
    /// </summary>
    /// <param name="ciphertext">Encrypted data with authentication tag</param>
    /// <param name="key">Decryption key</param>
    /// <param name="nonce">Nonce/IV used during encryption</param>
    /// <param name="associatedData">Associated data used during encryption</param>
    /// <param name="algorithm">AEAD algorithm used</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Decrypted plaintext</returns>
    /// <exception cref="UnauthorizedAccessException">Authentication failed</exception>
    Task<byte[]> DecryptAsync(
        byte[] ciphertext,
        byte[] key,
        byte[] nonce,
        byte[]? associatedData = null,
        AeadAlgorithm algorithm = AeadAlgorithm.ChaCha20Poly1305,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Encrypts a stream of data using AEAD
    /// </summary>
    /// <param name="plaintext">Input stream</param>
    /// <param name="ciphertext">Output stream</param>
    /// <param name="key">Encryption key</param>
    /// <param name="nonce">Base nonce (will be incremented for each chunk)</param>
    /// <param name="associatedData">Optional associated data</param>
    /// <param name="algorithm">AEAD algorithm to use</param>
    /// <param name="chunkSize">Size of each encrypted chunk</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Task representing the operation</returns>
    Task EncryptStreamAsync(
        System.IO.Stream plaintext,
        System.IO.Stream ciphertext,
        byte[] key,
        byte[] nonce,
        byte[]? associatedData = null,
        AeadAlgorithm algorithm = AeadAlgorithm.ChaCha20Poly1305,
        int chunkSize = 64 * 1024,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypts a stream of AEAD data
    /// </summary>
    /// <param name="ciphertext">Input stream</param>
    /// <param name="plaintext">Output stream</param>
    /// <param name="key">Decryption key</param>
    /// <param name="nonce">Base nonce used during encryption</param>
    /// <param name="associatedData">Associated data used during encryption</param>
    /// <param name="algorithm">AEAD algorithm used</param>
    /// <param name="chunkSize">Size of each encrypted chunk</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Task representing the operation</returns>
    Task DecryptStreamAsync(
        System.IO.Stream ciphertext,
        System.IO.Stream plaintext,
        byte[] key,
        byte[] nonce,
        byte[]? associatedData = null,
        AeadAlgorithm algorithm = AeadAlgorithm.ChaCha20Poly1305,
        int chunkSize = 64 * 1024,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates a random key for the specified algorithm
    /// </summary>
    /// <param name="algorithm">AEAD algorithm</param>
    /// <returns>Random key of appropriate length</returns>
    byte[] GenerateKey(AeadAlgorithm algorithm = AeadAlgorithm.ChaCha20Poly1305);

    /// <summary>
    /// Generates a random nonce for the specified algorithm
    /// </summary>
    /// <param name="algorithm">AEAD algorithm</param>
    /// <returns>Random nonce of appropriate length</returns>
    byte[] GenerateNonce(AeadAlgorithm algorithm = AeadAlgorithm.ChaCha20Poly1305);

    /// <summary>
    /// Gets the key size for the specified algorithm
    /// </summary>
    /// <param name="algorithm">AEAD algorithm</param>
    /// <returns>Key size in bytes</returns>
    int GetKeySize(AeadAlgorithm algorithm);

    /// <summary>
    /// Gets the nonce size for the specified algorithm
    /// </summary>
    /// <param name="algorithm">AEAD algorithm</param>
    /// <returns>Nonce size in bytes</returns>
    int GetNonceSize(AeadAlgorithm algorithm);

    /// <summary>
    /// Gets the authentication tag size for the specified algorithm
    /// </summary>
    /// <param name="algorithm">AEAD algorithm</param>
    /// <returns>Tag size in bytes</returns>
    int GetTagSize(AeadAlgorithm algorithm);
}

/// <summary>
/// Supported AEAD algorithms
/// </summary>
public enum AeadAlgorithm
{
    /// <summary>
    /// ChaCha20-Poly1305 (RFC 8439) - Modern, fast, constant-time
    /// Key: 32 bytes, Nonce: 12 bytes, Tag: 16 bytes
    /// </summary>
    ChaCha20Poly1305 = 1,

    /// <summary>
    /// AES-256-GCM - Hardware accelerated on modern CPUs
    /// Key: 32 bytes, Nonce: 12 bytes, Tag: 16 bytes
    /// </summary>
    Aes256Gcm = 2,

    /// <summary>
    /// AES-128-GCM - Faster variant for less security requirements
    /// Key: 16 bytes, Nonce: 12 bytes, Tag: 16 bytes
    /// </summary>
    Aes128Gcm = 3,

    /// <summary>
    /// XChaCha20-Poly1305 - Extended nonce variant of ChaCha20-Poly1305
    /// Key: 32 bytes, Nonce: 24 bytes, Tag: 16 bytes
    /// </summary>
    XChaCha20Poly1305 = 4,

    /// <summary>
    /// AES-128-CCM (Counter with CBC-MAC) - RFC 3610, IoT/Embedded optimized
    /// Key: 16 bytes, Nonce: 7-13 bytes (typically 13), Tag: 4-16 bytes (even)
    /// Used in: Bluetooth LE, Zigbee, Thread, 802.15.4
    /// </summary>
    Aes128Ccm = 5,

    /// <summary>
    /// AES-256-CCM (Counter with CBC-MAC) - RFC 3610, higher security variant
    /// Key: 32 bytes, Nonce: 7-13 bytes (typically 13), Tag: 4-16 bytes (even)
    /// Used in: Bluetooth LE, Zigbee, Thread, 802.15.4
    /// </summary>
    Aes256Ccm = 6,

    /// <summary>
    /// AES-SIV-256 (Synthetic IV) - RFC 5297, nonce-misuse resistant
    /// Key: 64 bytes (32+32 for MAC+CTR), Nonce: any length, SIV: 16 bytes
    /// Deterministic AEAD, safe with nonce reuse
    /// Used in: Key wrapping, deduplication, high-security scenarios
    /// </summary>
    Aes256Siv = 7,

    /// <summary>
    /// AES-SIV-512 (Synthetic IV with AES-256) - RFC 5297, maximum security
    /// Key: 128 bytes (64+64 for MAC+CTR), Nonce: any length, SIV: 16 bytes
    /// Nonce-misuse resistant with AES-256 strength
    /// </summary>
    Aes512Siv = 8
}

/// <summary>
/// AEAD operation result with metadata
/// </summary>
public readonly struct AeadResult
{
    /// <summary>
    /// The encrypted or decrypted data
    /// </summary>
    public byte[] Data { get; }

    /// <summary>
    /// Algorithm used for the operation
    /// </summary>
    public AeadAlgorithm Algorithm { get; }

    /// <summary>
    /// Size of the original data before encryption/decryption
    /// </summary>
    public int OriginalSize { get; }

    /// <summary>
    /// Whether hardware acceleration was used
    /// </summary>
    public bool HardwareAccelerated { get; }

    /// <summary>
    /// Operation duration in milliseconds
    /// </summary>
    public double DurationMs { get; }

    public AeadResult(byte[] data, AeadAlgorithm algorithm, int originalSize, bool hardwareAccelerated, double durationMs)
    {
        Data = data;
        Algorithm = algorithm;
        OriginalSize = originalSize;
        HardwareAccelerated = hardwareAccelerated;
        DurationMs = durationMs;
    }
}