using System.Security.Cryptography;
using HeroCrypt.Polyfills;

namespace HeroCrypt.Primitives.AesCfb;

/// <summary>
/// Provides AES-CFB (Cipher Feedback) encryption and decryption.
/// </summary>
/// <remarks>
/// <para>
/// This implements standard CFB mode as used for OpenPGP secret key encryption (RFC 4880).
/// Note: This is NOT the same as OpenPGP's CFB mode for message encryption, which uses
/// a special "resync" mechanism described in RFC 4880 Section 13.9.
/// </para>
/// <para>
/// CFB mode converts a block cipher into a stream cipher. Each block of ciphertext
/// is used as the input to the block cipher, and the output is XORed with the plaintext
/// to produce the ciphertext.
/// </para>
/// </remarks>
public static class AesCfbCore
{
    /// <summary>
    /// AES block size in bytes.
    /// </summary>
    public const int BlockSize = 16;

    /// <summary>
    /// Encrypts data using AES-CFB mode.
    /// </summary>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <param name="key">The encryption key (16, 24, or 32 bytes for AES-128/192/256).</param>
    /// <param name="iv">The initialization vector (16 bytes).</param>
    /// <returns>The encrypted data.</returns>
    /// <exception cref="ArgumentNullException">If any parameter is null.</exception>
    /// <exception cref="ArgumentException">If IV length is not 16 bytes.</exception>
    public static byte[] Encrypt(byte[] plaintext, byte[] key, byte[] iv)
    {
        ArgumentHelper.ThrowIfNull(plaintext);
        ArgumentHelper.ThrowIfNull(key);
        ArgumentHelper.ThrowIfNull(iv);

        if (iv.Length != BlockSize)
        {
            throw new ArgumentException($"IV must be {BlockSize} bytes.", nameof(iv));
        }

        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB; // We implement CFB manually
        aes.Padding = PaddingMode.None;

        return EncryptCore(plaintext, aes, iv);
    }

    /// <summary>
    /// Encrypts data using AES-CFB mode.
    /// </summary>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <param name="key">The encryption key.</param>
    /// <param name="iv">The initialization vector.</param>
    /// <returns>The encrypted data.</returns>
    public static byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (iv.Length != BlockSize)
        {
            throw new ArgumentException($"IV must be {BlockSize} bytes.", nameof(iv));
        }

        using var aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        return EncryptCore(plaintext, aes, iv);
    }

    /// <summary>
    /// Decrypts data using AES-CFB mode.
    /// </summary>
    /// <param name="ciphertext">The data to decrypt.</param>
    /// <param name="key">The decryption key (16, 24, or 32 bytes for AES-128/192/256).</param>
    /// <param name="iv">The initialization vector (16 bytes).</param>
    /// <returns>The decrypted data.</returns>
    /// <exception cref="ArgumentNullException">If any parameter is null.</exception>
    /// <exception cref="ArgumentException">If IV length is not 16 bytes.</exception>
    public static byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] iv)
    {
        ArgumentHelper.ThrowIfNull(ciphertext);
        ArgumentHelper.ThrowIfNull(key);
        ArgumentHelper.ThrowIfNull(iv);

        if (iv.Length != BlockSize)
        {
            throw new ArgumentException($"IV must be {BlockSize} bytes.", nameof(iv));
        }

        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB; // We implement CFB manually
        aes.Padding = PaddingMode.None;

        return DecryptCore(ciphertext, aes, iv);
    }

    /// <summary>
    /// Decrypts data using AES-CFB mode.
    /// </summary>
    /// <param name="ciphertext">The data to decrypt.</param>
    /// <param name="key">The decryption key.</param>
    /// <param name="iv">The initialization vector.</param>
    /// <returns>The decrypted data.</returns>
    public static byte[] Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (iv.Length != BlockSize)
        {
            throw new ArgumentException($"IV must be {BlockSize} bytes.", nameof(iv));
        }

        using var aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        return DecryptCore(ciphertext, aes, iv);
    }

    private static byte[] EncryptCore(ReadOnlySpan<byte> plaintext, Aes aes, ReadOnlySpan<byte> iv)
    {
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] fr = new byte[BlockSize]; // Feedback register
        byte[] fre = new byte[BlockSize]; // Encrypted feedback register

        // Initialize FR with IV
        iv.CopyTo(fr);

        using var encryptor = aes.CreateEncryptor();

        int pos = 0;
        while (pos < plaintext.Length)
        {
            // Encrypt the feedback register
            encryptor.TransformBlock(fr, 0, BlockSize, fre, 0);

            // XOR plaintext with encrypted FR
            int bytesToProcess = Math.Min(BlockSize, plaintext.Length - pos);
            for (int i = 0; i < bytesToProcess; i++)
            {
                ciphertext[pos + i] = (byte)(plaintext[pos + i] ^ fre[i]);
            }

            // Update FR with ciphertext for next iteration
            Array.Copy(ciphertext, pos, fr, 0, bytesToProcess);
            if (bytesToProcess < BlockSize)
            {
                Array.Clear(fr, bytesToProcess, BlockSize - bytesToProcess);
            }

            pos += bytesToProcess;
        }

        return ciphertext;
    }

    private static byte[] DecryptCore(ReadOnlySpan<byte> ciphertext, Aes aes, ReadOnlySpan<byte> iv)
    {
        byte[] plaintext = new byte[ciphertext.Length];
        byte[] fr = new byte[BlockSize]; // Feedback register
        byte[] fre = new byte[BlockSize]; // Encrypted feedback register

        // Initialize FR with IV
        iv.CopyTo(fr);

        using var encryptor = aes.CreateEncryptor(); // CFB decrypt uses encrypt operation

        int pos = 0;
        while (pos < ciphertext.Length)
        {
            // Encrypt the feedback register
            encryptor.TransformBlock(fr, 0, BlockSize, fre, 0);

            // XOR ciphertext with encrypted FR to get plaintext
            int bytesToProcess = Math.Min(BlockSize, ciphertext.Length - pos);
            for (int i = 0; i < bytesToProcess; i++)
            {
                plaintext[pos + i] = (byte)(ciphertext[pos + i] ^ fre[i]);
            }

            // Update FR with ciphertext for next iteration
            ciphertext.Slice(pos, bytesToProcess).CopyTo(fr);
            if (bytesToProcess < BlockSize)
            {
                Array.Clear(fr, bytesToProcess, BlockSize - bytesToProcess);
            }

            pos += bytesToProcess;
        }

        return plaintext;
    }
}
