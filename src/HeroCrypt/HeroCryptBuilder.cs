namespace HeroCrypt;

/// <summary>
/// Main entry point for HeroCrypt cryptographic operations.
/// Provides three levels of API access:
///
/// <list type="number">
///   <item>
///     <term>Primitives (flat access)</term>
///     <description>
///       Direct access to algorithm builders: <c>HeroCryptBuilder.ChaCha20Poly1305()</c>, <c>HeroCryptBuilder.Blake2b()</c>
///     </description>
///   </item>
///   <item>
///     <term>Operations (nested facades)</term>
///     <description>
///       Algorithm-agnostic facades: <c>HeroCryptBuilder.Encrypt.WithChaCha20Poly1305()</c>, <c>HeroCryptBuilder.Hash.WithBlake2b()</c>
///     </description>
///   </item>
///   <item>
///     <term>Protocols</term>
///     <description>
///       Complex cryptographic constructions: <c>HeroCryptBuilder.Pgp()</c>, <c>HeroCryptBuilder.Bip32()</c>
///     </description>
///   </item>
/// </list>
/// </summary>
/// <example>
/// <code>
/// // Direct primitive access (Primitives)
/// using var cipher = HeroCryptBuilder.ChaCha20Poly1305()
///     .WithKey(key)
///     .WithRandomNonce();
/// var ciphertext = cipher.Encrypt(plaintext);
///
/// // Operation-based access (Operations)
/// using var cipher = HeroCryptBuilder.Encrypt.WithChaCha20Poly1305()
///     .WithKey(key)
///     .WithRandomNonce();
/// var ciphertext = cipher.Encrypt(plaintext);
///
/// // Hashing with Blake2b
/// using var hasher = HeroCryptBuilder.Blake2b()
///     .WithOutputLength(32);
/// var hash = hasher.ComputeHash(data);
///
/// // Signing with Ed25519
/// using var signer = HeroCryptBuilder.Ed25519();
/// var (privateKey, publicKey) = signer.GenerateKeyPair();
/// var signature = signer.WithPrivateKey(privateKey)
///     .WithMessage(data)
///     .Sign();
///
/// // Key derivation with Argon2
/// using var kdf = HeroCryptBuilder.Argon2()
///     .WithPassword(password)
///     .WithRandomSalt()
///     .WithInteractivePreset();
/// var derivedKey = kdf.DeriveKey();
///
/// // PGP-style hybrid encryption (Protocols)
/// var pgp = HeroCryptBuilder.Pgp();
/// var keyPair = pgp.GenerateRsaKeyPair();
/// var envelope = pgp.Encrypt("Hello, World!", keyPair.PublicKey);
/// var plaintext = PgpBuilder.DecryptToString(envelope, keyPair.PrivateKey);
/// </code>
/// </example>
/// <remarks>
/// <para>
/// <b>Primitive Access:</b> Use for direct access to specific algorithms when you know
/// exactly which primitive you need.
/// </para>
/// <para>
/// <b>Operation Access:</b> Use for algorithm-agnostic interfaces where the operation
/// type (encrypt, hash, sign) is the primary concern.
/// </para>
/// <para>
/// <b>Protocol Access:</b> Use for complex cryptographic constructions that combine
/// multiple primitives (e.g., PGP combines RSA key exchange with symmetric encryption).
/// </para>
/// </remarks>
public static partial class HeroCryptBuilder
{
}
