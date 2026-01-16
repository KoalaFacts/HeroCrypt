using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using HeroCrypt.Polyfills;
using HeroCrypt.Primitives.ChaCha20;
using HeroCrypt.Primitives.ChaCha20Poly1305;
using HeroCrypt.Primitives.Common;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.XChaCha20Poly1305;

/// <summary>
/// Result of an XChaCha20-Poly1305 encryption operation.
/// </summary>
public readonly struct XChaCha20Poly1305EncryptionResult
{
    /// <summary>The encrypted ciphertext including authentication tag.</summary>
    public readonly byte[] Ciphertext { get; init; }

    /// <summary>The nonce used for encryption (needed for decryption).</summary>
    public readonly byte[] Nonce { get; init; }

    /// <summary>Size of the authentication tag in bytes (always 16).</summary>
    public readonly int TagSize { get; init; }

    /// <summary>Length of the ciphertext portion (excluding tag).</summary>
    public readonly int CiphertextLength => Ciphertext.Length - TagSize;
}

/// <summary>
/// XChaCha20-Poly1305 AEAD implementation with extended 24-byte nonces
/// Provides the same security as ChaCha20-Poly1305 but with larger nonce space
/// </summary>
internal static class XChaCha20Poly1305Core
{
    private const int KEY_SIZE = 32;
    private const int NONCE_SIZE = 24;
    private const int TAG_SIZE = 16;

    private static readonly uint[] HChaCha20Constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

    /// <summary>
    /// Encrypts plaintext using XChaCha20-Poly1305.
    /// </summary>
    /// <param name="plaintext">Input plaintext.</param>
    /// <param name="key">32-byte key.</param>
    /// <param name="nonce">Nonce (24 bytes). Default: auto-generated random nonce.</param>
    /// <param name="associatedData">Additional authenticated data. Default: empty.</param>
    /// <param name="deterministicMode">When true and nonce is empty, uses zero nonce (dangerous - only for testing). Default: false.</param>
    /// <returns>Encryption result containing ciphertext, nonce, and metadata.</returns>
    public static XChaCha20Poly1305EncryptionResult Encrypt(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce = default,
        ReadOnlySpan<byte> associatedData = default,
        bool deterministicMode = false)
    {
        // Validate key
        if (key.Length != KEY_SIZE)
        {
            throw new ArgumentException($"Key must be {KEY_SIZE} bytes, but was {key.Length} bytes", nameof(key));
        }

        // Generate random nonce if not provided and not in deterministic mode
        byte[] nonceArray;
        if (nonce.IsEmpty)
        {
            if (deterministicMode)
            {
                // Deterministic mode: use zero nonce (WARNING: dangerous for production)
                nonceArray = new byte[NONCE_SIZE];
            }
            else
            {
                // Secure default: auto-generate random nonce
                nonceArray = new byte[NONCE_SIZE];
                SecureRandomNumberGenerator.Fill(nonceArray);
            }
        }
        else
        {
            if (nonce.Length != NONCE_SIZE)
            {
                throw new ArgumentException($"Nonce must be {NONCE_SIZE} bytes, but was {nonce.Length} bytes", nameof(nonce));
            }
            nonceArray = nonce.ToArray();
        }

        // Derive ChaCha20 key and nonce from XChaCha20 parameters
        Span<byte> derivedKey = stackalloc byte[32];
        Span<byte> derivedNonce = stackalloc byte[12];
        DeriveKeyAndNonce(derivedKey, derivedNonce, key, nonceArray);

        try
        {
            // Allocate ciphertext buffer
            var ciphertext = new byte[plaintext.Length + TAG_SIZE];

            var ciphertextWithoutTag = ciphertext.AsSpan(0, plaintext.Length);
            var tag = ciphertext.AsSpan(plaintext.Length, TAG_SIZE);

            // Generate Poly1305 key using the derived ChaCha20 key
            Span<byte> poly1305Key = stackalloc byte[32];
            Span<byte> zeroBlock = stackalloc byte[32];
            ChaCha20Core.Transform(poly1305Key, zeroBlock, derivedKey, derivedNonce, 0);

            // Encrypt plaintext using ChaCha20 with counter=1
            ChaCha20Core.Transform(ciphertextWithoutTag, plaintext, derivedKey, derivedNonce, 1);

            // Compute authentication tag
            ComputeTag(tag, associatedData, ciphertextWithoutTag, poly1305Key);

            // Clear sensitive data
            SecureMemoryOperations.SecureClear(poly1305Key);
            SecureMemoryOperations.SecureClear(zeroBlock);

            return new XChaCha20Poly1305EncryptionResult
            {
                Ciphertext = ciphertext,
                Nonce = nonceArray,
                TagSize = TAG_SIZE
            };
        }
        finally
        {
            // Clear derived key and nonce
            SecureMemoryOperations.SecureClear(derivedKey);
            SecureMemoryOperations.SecureClear(derivedNonce);
        }
    }

    /// <summary>
    /// Decrypts ciphertext using XChaCha20-Poly1305.
    /// </summary>
    /// <param name="ciphertext">Input ciphertext including authentication tag.</param>
    /// <param name="key">32-byte key.</param>
    /// <param name="nonce">Nonce used during encryption (24 bytes).</param>
    /// <param name="associatedData">Additional authenticated data used during encryption. Default: empty.</param>
    /// <returns>The decrypted plaintext.</returns>
    /// <exception cref="CryptographicException">Thrown when authentication fails.</exception>
    public static byte[] Decrypt(
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (key.Length != KEY_SIZE)
        {
            throw new ArgumentException($"Key must be {KEY_SIZE} bytes, but was {key.Length} bytes", nameof(key));
        }
        if (nonce.Length != NONCE_SIZE)
        {
            throw new ArgumentException($"Nonce must be {NONCE_SIZE} bytes, but was {nonce.Length} bytes", nameof(nonce));
        }
        if (ciphertext.Length < TAG_SIZE)
        {
            throw new ArgumentException($"Ciphertext must be at least {TAG_SIZE} bytes, but was {ciphertext.Length} bytes", nameof(ciphertext));
        }

        // Derive ChaCha20 key and nonce from XChaCha20 parameters
        Span<byte> derivedKey = stackalloc byte[32];
        Span<byte> derivedNonce = stackalloc byte[12];
        DeriveKeyAndNonce(derivedKey, derivedNonce, key, nonce);

        try
        {
            var ciphertextLength = ciphertext.Length - TAG_SIZE;
            var plaintext = new byte[ciphertextLength];

            var ciphertextWithoutTag = ciphertext[..ciphertextLength];
            var receivedTag = ciphertext.Slice(ciphertextLength, TAG_SIZE);

            // Generate Poly1305 key using the derived ChaCha20 key
            Span<byte> poly1305Key = stackalloc byte[32];
            Span<byte> zeroBlock = stackalloc byte[32];
            ChaCha20Core.Transform(poly1305Key, zeroBlock, derivedKey, derivedNonce, 0);

            // Compute expected authentication tag
            Span<byte> expectedTag = stackalloc byte[TAG_SIZE];
            ComputeTag(expectedTag, associatedData, ciphertextWithoutTag, poly1305Key);

            // Verify tag in constant time
            var tagValid = SecureMemoryOperations.ConstantTimeEquals(receivedTag, expectedTag);

            // Clear computed tag and Poly1305 key
            SecureMemoryOperations.SecureClear(expectedTag);
            SecureMemoryOperations.SecureClear(poly1305Key);
            SecureMemoryOperations.SecureClear(zeroBlock);

            if (!tagValid)
            {
                throw new CryptographicException("XChaCha20-Poly1305 decryption failed: authentication tag mismatch.");
            }

            // Decrypt ciphertext using ChaCha20 with counter=1
            ChaCha20Core.Transform(plaintext, ciphertextWithoutTag, derivedKey, derivedNonce, 1);

            return plaintext;
        }
        finally
        {
            // Clear derived key and nonce
            SecureMemoryOperations.SecureClear(derivedKey);
            SecureMemoryOperations.SecureClear(derivedNonce);
        }
    }

    /// <summary>
    /// Derives ChaCha20 key and nonce from XChaCha20 parameters using HChaCha20
    /// </summary>
    /// <param name="derivedKey">Output 32-byte derived key</param>
    /// <param name="derivedNonce">Output 12-byte derived nonce</param>
    /// <param name="originalKey">Input 32-byte original key</param>
    /// <param name="extendedNonce">Input 24-byte extended nonce</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void DeriveKeyAndNonce(Span<byte> derivedKey, Span<byte> derivedNonce,
        ReadOnlySpan<byte> originalKey, ReadOnlySpan<byte> extendedNonce)
    {
        // HChaCha20 takes the first 16 bytes of the nonce
        var hchacha20Nonce = extendedNonce[..16];

        // Derive new key using HChaCha20
        HChaCha20(derivedKey, originalKey, hchacha20Nonce);

        // The derived nonce is the last 8 bytes of the extended nonce + 4 zero bytes
        derivedNonce.Clear();
        extendedNonce.Slice(16, 8).CopyTo(derivedNonce.Slice(4, 8));
    }

    /// <summary>
    /// HChaCha20 key derivation function
    /// </summary>
    /// <param name="output">32-byte output key</param>
    /// <param name="key">32-byte input key</param>
    /// <param name="nonce">16-byte nonce</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void HChaCha20(Span<byte> output, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        if (output.Length != 32)
        {
            throw new ArgumentException($"Output must be 32 bytes, but was {output.Length} bytes", nameof(output));
        }
        if (key.Length != 32)
        {
            throw new ArgumentException($"Key must be 32 bytes, but was {key.Length} bytes", nameof(key));
        }
        if (nonce.Length != 16)
        {
            throw new ArgumentException($"Nonce must be 16 bytes, but was {nonce.Length} bytes", nameof(nonce));
        }

        // Initialize HChaCha20 state
        Span<uint> state = stackalloc uint[16];

        // Constants
        state[0] = HChaCha20Constants[0];
        state[1] = HChaCha20Constants[1];
        state[2] = HChaCha20Constants[2];
        state[3] = HChaCha20Constants[3];

        // Key - use explicit little-endian reads for platform independence
        for (var i = 0; i < 8; i++)
        {
            state[4 + i] = BinaryHelpers.ReadUInt32LittleEndian(key.Slice(i * 4, 4));
        }

        // Nonce - use explicit little-endian reads for platform independence
        for (var i = 0; i < 4; i++)
        {
            state[12 + i] = BinaryHelpers.ReadUInt32LittleEndian(nonce.Slice(i * 4, 4));
        }

        // Perform 20 rounds (same as ChaCha20)
        ChaChaUtils.DoubleRound(state);

        // Output only state[0], state[1], state[2], state[3], state[12], state[13], state[14], state[15]
        // Use explicit little-endian writes for platform independence
        BinaryHelpers.WriteUInt32LittleEndian(output.Slice(0, 4), state[0]);
        BinaryHelpers.WriteUInt32LittleEndian(output.Slice(4, 4), state[1]);
        BinaryHelpers.WriteUInt32LittleEndian(output.Slice(8, 4), state[2]);
        BinaryHelpers.WriteUInt32LittleEndian(output.Slice(12, 4), state[3]);
        BinaryHelpers.WriteUInt32LittleEndian(output.Slice(16, 4), state[12]);
        BinaryHelpers.WriteUInt32LittleEndian(output.Slice(20, 4), state[13]);
        BinaryHelpers.WriteUInt32LittleEndian(output.Slice(24, 4), state[14]);
        BinaryHelpers.WriteUInt32LittleEndian(output.Slice(28, 4), state[15]);

        // Clear state
        SecureMemoryOperations.SecureClear(state);
    }

    /// <summary>
    /// Computes the Poly1305 authentication tag (same as ChaCha20-Poly1305).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> poly1305Key)
    {
        Poly1305TagComputation.ComputeTag(tag, associatedData, ciphertext, poly1305Key);
    }
}
