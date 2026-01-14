namespace HeroCrypt.Cryptography.Primitives.Cipher.Aead;

/// <summary>
/// Interface for Authenticated Encryption with Associated Data (AEAD) ciphers.
/// Provides a unified API for AEAD operations across different cipher implementations.
/// </summary>
public interface IAeadCipher
{
    /// <summary>
    /// Gets the name of this AEAD cipher algorithm.
    /// </summary>
    string AlgorithmName { get; }

    /// <summary>
    /// Gets the required key size in bytes.
    /// </summary>
    int KeySize { get; }

    /// <summary>
    /// Gets the required nonce size in bytes.
    /// </summary>
    int NonceSize { get; }

    /// <summary>
    /// Gets the authentication tag size in bytes.
    /// </summary>
    int TagSize { get; }

    /// <summary>
    /// Encrypts plaintext and computes authentication tag.
    /// </summary>
    /// <param name="ciphertext">Output buffer for ciphertext (must include space for tag)</param>
    /// <param name="plaintext">Input plaintext</param>
    /// <param name="key">Encryption key</param>
    /// <param name="nonce">Unique nonce for this encryption</param>
    /// <param name="associatedData">Optional associated data to authenticate but not encrypt</param>
    /// <returns>Total length of ciphertext including tag</returns>
    int Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData = default);

    /// <summary>
    /// Decrypts ciphertext and verifies authentication tag.
    /// </summary>
    /// <param name="plaintext">Output buffer for plaintext</param>
    /// <param name="ciphertext">Input ciphertext with tag</param>
    /// <param name="key">Decryption key</param>
    /// <param name="nonce">Nonce used during encryption</param>
    /// <param name="associatedData">Associated data used during encryption</param>
    /// <returns>Plaintext length on success, or -1 if authentication fails</returns>
    int Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData = default);

    /// <summary>
    /// Gets the ciphertext length for a given plaintext length.
    /// </summary>
    /// <param name="plaintextLength">Length of plaintext</param>
    /// <returns>Required ciphertext buffer size including tag</returns>
    int GetCiphertextLength(int plaintextLength);

    /// <summary>
    /// Gets the maximum plaintext length for a given ciphertext length.
    /// </summary>
    /// <param name="ciphertextLength">Length of ciphertext including tag</param>
    /// <returns>Maximum plaintext length, or -1 if ciphertext is too short</returns>
    int GetPlaintextLength(int ciphertextLength);
}
