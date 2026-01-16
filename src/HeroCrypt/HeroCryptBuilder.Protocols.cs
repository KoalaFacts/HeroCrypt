using HeroCrypt.Protocols.HdWallet;
using HeroCrypt.Protocols.MessageExchange;
using HeroCrypt.Protocols.SecretSharing;

namespace HeroCrypt;

/// <inheritdoc/>
public static partial class HeroCryptBuilder
{
#if !NETSTANDARD2_0
    // ═══════════════════════════════════════════════════════════════════════════
    // Message Exchange (Hybrid Encryption)
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Starts building a PGP-style hybrid encryption operation.
    /// </summary>
    /// <remarks>
    /// PGP-style encryption uses RSA for key exchange and a symmetric AEAD cipher
    /// for data encryption. This provides the benefits of asymmetric cryptography
    /// (key distribution) with the efficiency of symmetric encryption.
    /// </remarks>
    /// <example>
    /// <code>
    /// var encrypted = HeroCryptBuilder.Pgp()
    ///     .WithRecipientPublicKey(publicKey)
    ///     .Encrypt(plaintext);
    /// </code>
    /// </example>
    /// <returns>A new PGP builder.</returns>
    public static PgpBuilder Pgp() => new();

    // ═══════════════════════════════════════════════════════════════════════════
    // HD Wallets (BIP32/BIP39)
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Starts building an HD wallet operation for BIP32/BIP39 key derivation.
    /// </summary>
    /// <example>
    /// <code>
    /// var wallet = HeroCryptBuilder.HdWallet()
    ///     .GenerateMnemonic(wordCount: 24)
    ///     .WithPassphrase("optional")
    ///     .WithPath("m/44'/0'/0'/0/0")
    ///     .Derive();
    /// </code>
    /// </example>
    /// <returns>A new HD wallet builder.</returns>
    public static HdWalletBuilder HdWallet() => new();

    // ═══════════════════════════════════════════════════════════════════════════
    // Secret Sharing
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Starts building a Shamir's Secret Sharing operation.
    /// </summary>
    /// <example>
    /// <code>
    /// var shares = HeroCryptBuilder.SecretSharing()
    ///     .WithThreshold(3)
    ///     .WithShareCount(5)
    ///     .Split(secret);
    /// </code>
    /// </example>
    /// <returns>A new secret sharing builder.</returns>
    public static SecretSharingBuilder SecretSharing() => new();

    /// <summary>
    /// Starts building a threshold signature operation.
    /// </summary>
    /// <example>
    /// <code>
    /// var keys = HeroCryptBuilder.ThresholdSignature()
    ///     .WithParties(5)
    ///     .WithThreshold(3)
    ///     .GenerateKeys();
    /// </code>
    /// </example>
    /// <returns>A new threshold signature builder.</returns>
    public static ThresholdSignatureBuilder ThresholdSignature() => new();

    /// <summary>
    /// Starts building a secure multi-party computation operation.
    /// </summary>
    /// <example>
    /// <code>
    /// var result = HeroCryptBuilder.Mpc()
    ///     .WithThreshold(2)
    ///     .ComputeSum(partyInputs);
    /// </code>
    /// </example>
    /// <returns>A new MPC builder.</returns>
    public static MpcBuilder Mpc() => new();
#endif
}
