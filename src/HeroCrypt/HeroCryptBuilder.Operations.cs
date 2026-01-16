using HeroCrypt.Operations;

namespace HeroCrypt;

/// <inheritdoc/>
public static partial class HeroCryptBuilder
{
    /// <summary>
    /// Starts building an encryption operation with algorithm selection.
    /// </summary>
    /// <example>
    /// <code>
    /// var result = HeroCryptBuilder.Encrypt()
    ///     .WithChaCha20Poly1305()
    ///     .WithKey(key)
    ///     .Encrypt(plaintext);
    /// </code>
    /// </example>
    /// <returns>An encryption builder instance.</returns>
    public static EncryptionBuilder Encrypt() => new();

    /// <summary>
    /// Starts building a decryption operation with algorithm selection.
    /// </summary>
    /// <returns>A decryption builder instance.</returns>
    public static DecryptionBuilder Decrypt() => new();

    /// <summary>
    /// Starts building a hash operation with algorithm selection.
    /// </summary>
    /// <example>
    /// <code>
    /// var hash = HeroCryptBuilder.Hash()
    ///     .WithSha256()
    ///     .ComputeHash(data);
    /// </code>
    /// </example>
    /// <returns>A hash builder instance.</returns>
    public static HashBuilder Hash() => new();

    /// <summary>
    /// Starts building a signature operation with algorithm selection.
    /// </summary>
    /// <example>
    /// <code>
    /// var signature = HeroCryptBuilder.Sign()
    ///     .WithEd25519()
    ///     .WithPrivateKey(privateKey)
    ///     .Sign(data);
    /// </code>
    /// </example>
    /// <returns>A signature builder instance.</returns>
    public static SignatureBuilder Sign() => new();

    /// <summary>
    /// Starts building a signature verification operation with algorithm selection.
    /// </summary>
    /// <returns>A verification builder instance.</returns>
    public static VerificationBuilder Verify() => new();

    /// <summary>
    /// Starts building a key derivation operation with algorithm selection.
    /// </summary>
    /// <example>
    /// <code>
    /// var key = HeroCryptBuilder.DeriveKey()
    ///     .WithArgon2id()
    ///     .WithPassword(password)
    ///     .WithSalt(salt)
    ///     .DeriveKey();
    /// </code>
    /// </example>
    /// <returns>A key derivation builder instance.</returns>
    public static KeyDerivationBuilder DeriveKey() => new();
}
