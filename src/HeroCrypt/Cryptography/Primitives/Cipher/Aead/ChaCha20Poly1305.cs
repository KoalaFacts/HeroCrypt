namespace HeroCrypt.Cryptography.Primitives.Cipher.Aead;

/// <summary>
/// ChaCha20-Poly1305 AEAD cipher implementation.
/// Provides authenticated encryption according to RFC 8439.
/// </summary>
public sealed class ChaCha20Poly1305 : IAeadCipher
{
    /// <summary>
    /// Gets the singleton instance of ChaCha20-Poly1305.
    /// </summary>
    public static ChaCha20Poly1305 Instance { get; } = new();

    /// <inheritdoc />
    public string AlgorithmName => "ChaCha20-Poly1305";

    /// <inheritdoc />
    public int KeySize => ChaCha20Poly1305Core.KEY_SIZE;

    /// <inheritdoc />
    public int NonceSize => ChaCha20Poly1305Core.NONCE_SIZE;

    /// <inheritdoc />
    public int TagSize => ChaCha20Poly1305Core.TAG_SIZE;

    private ChaCha20Poly1305() { }

    /// <inheritdoc />
    public int Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData = default)
    {
        return ChaCha20Poly1305Core.Encrypt(ciphertext, plaintext, key, nonce, associatedData);
    }

    /// <inheritdoc />
    public int Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData = default)
    {
        return ChaCha20Poly1305Core.Decrypt(plaintext, ciphertext, key, nonce, associatedData);
    }

    /// <inheritdoc />
    public int GetCiphertextLength(int plaintextLength)
    {
        return ChaCha20Poly1305Core.GetCiphertextLength(plaintextLength);
    }

    /// <inheritdoc />
    public int GetPlaintextLength(int ciphertextLength)
    {
        return ChaCha20Poly1305Core.GetPlaintextLength(ciphertextLength);
    }
}
