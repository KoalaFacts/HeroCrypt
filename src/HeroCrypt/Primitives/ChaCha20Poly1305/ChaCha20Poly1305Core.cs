using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using HeroCrypt.Primitives.ChaCha20;
#if NETSTANDARD2_0
using HeroCrypt.Polyfills;
#endif
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.ChaCha20Poly1305;

/// <summary>
/// Result of a ChaCha20-Poly1305 encryption operation.
/// </summary>
public readonly struct ChaCha20Poly1305EncryptionResult
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
/// ChaCha20-Poly1305 AEAD implementation according to RFC 8439
/// Provides authenticated encryption with associated data
/// </summary>
internal sealed class ChaCha20Poly1305Core
{
    private readonly SecurityPolicyOptions policy;
    private readonly ChaCha20Core chaCha20Core;

    private const int KEY_SIZE = 32;
    private const int NONCE_SIZE = 12;
    private const int TAG_SIZE = 16;

    /// <summary>
    /// Initializes a ChaCha20Poly1305Core with the effective security policy.
    /// </summary>
    /// <param name="policy">Optional policy; uses the current policy when omitted.</param>
    public ChaCha20Poly1305Core(SecurityPolicyOptions? policy = null)
    {
        this.policy = policy ?? SecurityPolicy.CurrentPolicy;
        chaCha20Core = new ChaCha20Core(this.policy);
    }

    /// <summary>
    /// Encrypts plaintext using ChaCha20-Poly1305.
    /// </summary>
    /// <param name="plaintext">Input plaintext.</param>
    /// <param name="key">32-byte key.</param>
    /// <param name="nonce">Nonce (12 bytes). Default: auto-generated random nonce.</param>
    /// <param name="associatedData">Additional authenticated data. Default: empty.</param>
    /// <param name="deterministicMode">When true and nonce is empty, uses zero nonce (dangerous - only for testing). Default: false.</param>
    /// <returns>Encryption result containing ciphertext, nonce, and metadata.</returns>
    public ChaCha20Poly1305EncryptionResult Encrypt(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce = default,
        ReadOnlySpan<byte> associatedData = default,
        bool deterministicMode = false)
    {
        policy.ValidateSymmetric("CHACHA20-POLY1305");

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

        // Allocate ciphertext buffer
        var ciphertext = new byte[plaintext.Length + TAG_SIZE];

        var ciphertextWithoutTag = ciphertext.AsSpan(0, plaintext.Length);
        var tag = ciphertext.AsSpan(plaintext.Length, TAG_SIZE);

        // Generate the RFC 8439 Poly1305 one-time key from ChaCha20 block 0.
        Span<byte> poly1305Key = stackalloc byte[32];
        Span<byte> zeroBlock = stackalloc byte[32];
        try
        {
            // stackalloc contents are unspecified; block-0 input must be all zero.
            zeroBlock.Clear();
            chaCha20Core.Transform(poly1305Key, zeroBlock, key, nonceArray, 0);

            // Encrypt plaintext using ChaCha20 with counter=1.
            chaCha20Core.Transform(ciphertextWithoutTag, plaintext, key, nonceArray, 1);

            // Compute authentication tag.
            ComputeTag(tag, associatedData, ciphertextWithoutTag, poly1305Key);

            return new ChaCha20Poly1305EncryptionResult
            {
                Ciphertext = ciphertext,
                Nonce = nonceArray,
                TagSize = TAG_SIZE
            };
        }
        finally
        {
            // Best-effort cleanup, including failed encryption and MAC operations.
            SecureMemoryOperations.SecureClear(poly1305Key);
            SecureMemoryOperations.SecureClear(zeroBlock);
        }
    }

    /// <summary>
    /// Decrypts ciphertext using ChaCha20-Poly1305.
    /// </summary>
    /// <param name="ciphertext">Input ciphertext including authentication tag.</param>
    /// <param name="key">32-byte key.</param>
    /// <param name="nonce">Nonce used during encryption (12 bytes).</param>
    /// <param name="associatedData">Additional authenticated data used during encryption. Default: empty.</param>
    /// <returns>The decrypted plaintext.</returns>
    /// <exception cref="CryptographicException">Thrown when authentication fails.</exception>
    public byte[] Decrypt(
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData = default)
    {
        policy.ValidateSymmetric("CHACHA20-POLY1305");

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

        var ciphertextLength = ciphertext.Length - TAG_SIZE;

        var ciphertextWithoutTag = ciphertext[..ciphertextLength];
        var receivedTag = ciphertext.Slice(ciphertextLength, TAG_SIZE);

        // Derive the RFC 8439 Poly1305 one-time key from ChaCha20 block 0.
        Span<byte> poly1305Key = stackalloc byte[32];
        Span<byte> zeroBlock = stackalloc byte[32];
        Span<byte> expectedTag = stackalloc byte[TAG_SIZE];
        try
        {
            // stackalloc contents are unspecified; block-0 input must be all zero.
            zeroBlock.Clear();
            chaCha20Core.Transform(poly1305Key, zeroBlock, key, nonce, 0);

            // Verify the authentication tag before decrypting.
            ComputeTag(expectedTag, associatedData, ciphertextWithoutTag, poly1305Key);
            if (!SecureMemoryOperations.ConstantTimeEquals(receivedTag, expectedTag))
            {
                throw new CryptographicException("ChaCha20-Poly1305 decryption failed: authentication tag mismatch.");
            }

            // Allocate plaintext only after authenticating the untrusted ciphertext.
            // A forged tag must not force a message-sized plaintext allocation.
            var plaintext = new byte[ciphertextLength];
            chaCha20Core.Transform(plaintext, ciphertextWithoutTag, key, nonce, 1);
            return plaintext;
        }
        finally
        {
            // Best-effort cleanup also runs on authentication or cipher failures.
            SecureMemoryOperations.SecureClear(expectedTag);
            SecureMemoryOperations.SecureClear(poly1305Key);
            SecureMemoryOperations.SecureClear(zeroBlock);
        }
    }

    /// <summary>
    /// Computes the Poly1305 authentication tag.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> poly1305Key)
    {
        var tagComputation = new Poly1305TagComputation(policy);
        tagComputation.ComputeTag(tag, associatedData, ciphertext, poly1305Key);
    }
}
