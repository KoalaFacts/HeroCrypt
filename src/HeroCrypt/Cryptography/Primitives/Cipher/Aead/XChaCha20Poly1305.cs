namespace HeroCrypt.Cryptography.Primitives.Cipher.Aead;

/// <summary>
/// XChaCha20-Poly1305 AEAD cipher implementation with extended 24-byte nonces.
/// Provides the same security as ChaCha20-Poly1305 but with larger nonce space,
/// suitable for randomly generated nonces without collision risk.
/// </summary>
public sealed class XChaCha20Poly1305 : IAeadCipher
{
    /// <summary>
    /// Gets the singleton instance of XChaCha20-Poly1305.
    /// </summary>
    public static XChaCha20Poly1305 Instance { get; } = new();

    /// <inheritdoc />
    public string AlgorithmName => "XChaCha20-Poly1305";

    /// <inheritdoc />
    public int KeySize => XChaCha20Poly1305Core.KEY_SIZE;

    /// <inheritdoc />
    public int NonceSize => XChaCha20Poly1305Core.NONCE_SIZE;

    /// <inheritdoc />
    public int TagSize => XChaCha20Poly1305Core.TAG_SIZE;

    private XChaCha20Poly1305() { }

    /// <inheritdoc />
    public int Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData = default)
    {
        return XChaCha20Poly1305Core.Encrypt(ciphertext, plaintext, key, nonce, associatedData);
    }

    /// <inheritdoc />
    public int Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData = default)
    {
        return XChaCha20Poly1305Core.Decrypt(plaintext, ciphertext, key, nonce, associatedData);
    }

    /// <inheritdoc />
    public int GetCiphertextLength(int plaintextLength)
    {
        return XChaCha20Poly1305Core.GetCiphertextLength(plaintextLength);
    }

    /// <inheritdoc />
    public int GetPlaintextLength(int ciphertextLength)
    {
        return XChaCha20Poly1305Core.GetPlaintextLength(ciphertextLength);
    }
}
