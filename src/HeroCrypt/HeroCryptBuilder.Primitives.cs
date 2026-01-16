using HeroCrypt.Primitives.AesCcm;
using HeroCrypt.Primitives.AesCmac;
using HeroCrypt.Primitives.AesOcb;
using HeroCrypt.Primitives.AesSiv;
using HeroCrypt.Primitives.Argon2;
using HeroCrypt.Primitives.Blake2b;
using HeroCrypt.Primitives.ChaCha20;
using HeroCrypt.Primitives.ChaCha20Poly1305;
using HeroCrypt.Primitives.Curve25519;
using HeroCrypt.Primitives.Ed25519;
using HeroCrypt.Primitives.Hc128;
using HeroCrypt.Primitives.Hc256;
using HeroCrypt.Primitives.Hkdf;
using HeroCrypt.Primitives.Pbkdf2;
using HeroCrypt.Primitives.Poly1305;
using HeroCrypt.Primitives.Rabbit;
using HeroCrypt.Primitives.Rsa;
using HeroCrypt.Primitives.Scrypt;
using HeroCrypt.Primitives.Secp256k1;
using HeroCrypt.Primitives.XChaCha20Poly1305;
using HeroCrypt.Primitives.XSalsa20;
#if NET10_0_OR_GREATER
using HeroCrypt.Primitives.MLDsa;
using HeroCrypt.Primitives.MLKem;
using HeroCrypt.Primitives.SlhDsa;
#endif

namespace HeroCrypt;

/// <inheritdoc/>
public static partial class HeroCryptBuilder
{
    // ═══════════════════════════════════════════════════════════════════════════
    // AEAD Ciphers
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Creates a ChaCha20-Poly1305 AEAD cipher builder.
    /// </summary>
    /// <remarks>
    /// ChaCha20-Poly1305 is a fast, secure AEAD cipher ideal for general-purpose encryption.
    /// Uses a 256-bit key and 96-bit nonce.
    /// </remarks>
    /// <returns>A ChaCha20-Poly1305 builder instance.</returns>
    public static ChaCha20Poly1305Builder ChaCha20Poly1305() => ChaCha20Poly1305Builder.Create();

    /// <summary>
    /// Creates an XChaCha20-Poly1305 AEAD cipher builder.
    /// </summary>
    /// <remarks>
    /// XChaCha20-Poly1305 extends ChaCha20-Poly1305 with a 192-bit nonce,
    /// allowing safe random nonce generation for large message volumes.
    /// </remarks>
    /// <returns>An XChaCha20-Poly1305 builder instance.</returns>
    public static XChaCha20Poly1305Builder XChaCha20Poly1305() => XChaCha20Poly1305Builder.Create();

    /// <summary>
    /// Creates an AES-CCM AEAD cipher builder.
    /// </summary>
    /// <remarks>
    /// AES-CCM is widely used in IoT protocols (Bluetooth LE, Zigbee, Thread).
    /// Not supported on macOS.
    /// </remarks>
    /// <returns>An AES-CCM builder instance.</returns>
    public static AesCcmBuilder AesCcm() => AesCcmBuilder.Create();

    /// <summary>
    /// Creates an AES-OCB AEAD cipher builder.
    /// </summary>
    /// <remarks>
    /// AES-OCB provides high-performance authenticated encryption with minimal overhead.
    /// </remarks>
    /// <returns>An AES-OCB builder instance.</returns>
    public static AesOcbBuilder AesOcb() => AesOcbBuilder.Create();

    /// <summary>
    /// Creates an AES-SIV AEAD cipher builder.
    /// </summary>
    /// <remarks>
    /// AES-SIV is nonce-misuse resistant, providing security even if nonces are reused.
    /// Ideal for key wrapping and deterministic encryption scenarios.
    /// </remarks>
    /// <returns>An AES-SIV builder instance.</returns>
    public static AesSivBuilder AesSiv() => AesSivBuilder.Create();

    // ═══════════════════════════════════════════════════════════════════════════
    // Stream Ciphers
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Creates a ChaCha20 stream cipher builder.
    /// </summary>
    /// <remarks>
    /// ChaCha20 is a high-speed stream cipher. For authenticated encryption,
    /// prefer ChaCha20-Poly1305 instead.
    /// </remarks>
    /// <returns>A ChaCha20 builder instance.</returns>
    public static ChaCha20Builder ChaCha20() => ChaCha20Builder.Create();

    /// <summary>
    /// Creates an XSalsa20 stream cipher builder.
    /// </summary>
    /// <remarks>
    /// XSalsa20 extends Salsa20 with a 192-bit nonce for safe random nonce generation.
    /// </remarks>
    /// <returns>An XSalsa20 builder instance.</returns>
    public static XSalsa20Builder XSalsa20() => XSalsa20Builder.Create();

    /// <summary>
    /// Creates an HC-128 stream cipher builder.
    /// </summary>
    /// <remarks>
    /// HC-128 is an eSTREAM portfolio cipher optimized for software performance.
    /// </remarks>
    /// <returns>An HC-128 builder instance.</returns>
    public static Hc128Builder Hc128() => Hc128Builder.Create();

    /// <summary>
    /// Creates an HC-256 stream cipher builder.
    /// </summary>
    /// <remarks>
    /// HC-256 provides a higher security margin than HC-128 with 256-bit security.
    /// </remarks>
    /// <returns>An HC-256 builder instance.</returns>
    public static Hc256Builder Hc256() => Hc256Builder.Create();

    /// <summary>
    /// Creates a Rabbit stream cipher builder.
    /// </summary>
    /// <remarks>
    /// Rabbit is an eSTREAM portfolio cipher designed for high performance.
    /// </remarks>
    /// <returns>A Rabbit builder instance.</returns>
    public static RabbitBuilder Rabbit() => RabbitBuilder.Create();

    // ═══════════════════════════════════════════════════════════════════════════
    // Hash & MAC
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Creates a Blake2b hash builder.
    /// </summary>
    /// <remarks>
    /// Blake2b is a high-speed cryptographic hash function, faster than MD5 and SHA-1
    /// while providing security comparable to SHA-3. Supports variable output lengths
    /// from 1 to 64 bytes and optional keying for MAC functionality.
    /// </remarks>
    /// <returns>A Blake2b builder instance.</returns>
    public static Blake2bBuilder Blake2b() => Blake2bBuilder.Create();

    /// <summary>
    /// Creates an AES-CMAC builder.
    /// </summary>
    /// <remarks>
    /// AES-CMAC (RFC 4493) is a block cipher-based MAC providing strong authentication.
    /// Supports AES-128, AES-192, and AES-256 key sizes.
    /// </remarks>
    /// <returns>An AES-CMAC builder instance.</returns>
    public static AesCmacBuilder AesCmac() => AesCmacBuilder.Create();

    /// <summary>
    /// Creates a Poly1305 builder.
    /// </summary>
    /// <remarks>
    /// Poly1305 is a fast, one-time authenticator. Each key must only be used once.
    /// Commonly paired with ChaCha20 for authenticated encryption.
    /// </remarks>
    /// <returns>A Poly1305 builder instance.</returns>
    public static Poly1305Builder Poly1305() => Poly1305Builder.Create();

    // ═══════════════════════════════════════════════════════════════════════════
    // Key Derivation Functions
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Creates an Argon2 builder.
    /// </summary>
    /// <remarks>
    /// Argon2 (RFC 9106) is the winner of the Password Hashing Competition.
    /// Argon2id is recommended for password hashing, providing resistance against
    /// both GPU and side-channel attacks.
    /// </remarks>
    /// <returns>An Argon2 builder instance.</returns>
    public static Argon2Builder Argon2() => Argon2Builder.Create();

    /// <summary>
    /// Creates a PBKDF2 builder.
    /// </summary>
    /// <remarks>
    /// PBKDF2 (RFC 8018) is a widely-supported password-based key derivation function.
    /// While secure, Argon2 or Scrypt are preferred for new applications due to
    /// better resistance against hardware-accelerated attacks.
    /// </remarks>
    /// <returns>A PBKDF2 builder instance.</returns>
    public static Pbkdf2Builder Pbkdf2() => Pbkdf2Builder.Create();

    /// <summary>
    /// Creates a Scrypt builder.
    /// </summary>
    /// <remarks>
    /// Scrypt is a memory-hard password-based key derivation function designed to
    /// resist hardware-accelerated attacks by requiring large amounts of memory.
    /// </remarks>
    /// <returns>A Scrypt builder instance.</returns>
    public static ScryptBuilder Scrypt() => ScryptBuilder.Create();

    /// <summary>
    /// Creates an HKDF builder.
    /// </summary>
    /// <remarks>
    /// HKDF (RFC 5869) is designed for deriving keys from existing cryptographic material.
    /// It is NOT suitable for password hashing - use Argon2 or Scrypt for passwords.
    /// </remarks>
    /// <returns>An HKDF builder instance.</returns>
    public static HkdfBuilder Hkdf() => HkdfBuilder.Create();

    // ═══════════════════════════════════════════════════════════════════════════
    // Digital Signatures
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Creates an Ed25519 builder.
    /// </summary>
    /// <remarks>
    /// Ed25519 provides fast, secure digital signatures using the Edwards curve.
    /// Signatures are deterministic and provide 128-bit security.
    /// </remarks>
    /// <returns>An Ed25519 builder instance.</returns>
    public static Ed25519Builder Ed25519() => Ed25519Builder.Create();

    /// <summary>
    /// Creates a Secp256k1 builder.
    /// </summary>
    /// <remarks>
    /// Secp256k1 is the elliptic curve used by Bitcoin and Ethereum.
    /// Provides ECDSA signatures compatible with blockchain applications.
    /// </remarks>
    /// <returns>A Secp256k1 builder instance.</returns>
    public static Secp256k1Builder Secp256k1() => Secp256k1Builder.Create();

    /// <summary>
    /// Creates a Curve25519 builder.
    /// </summary>
    /// <remarks>
    /// Curve25519 provides Diffie-Hellman key exchange using the Montgomery curve.
    /// Ideal for establishing shared secrets between parties.
    /// </remarks>
    /// <returns>A Curve25519 builder instance.</returns>
    public static Curve25519Builder Curve25519() => Curve25519Builder.Create();

    /// <summary>
    /// Creates an RSA builder.
    /// </summary>
    /// <remarks>
    /// RSA provides asymmetric encryption and digital signatures.
    /// Supports key sizes from 2048 to 4096 bits. RSA-2048 is the minimum recommended.
    /// </remarks>
    /// <returns>An RSA builder instance.</returns>
    public static RsaBuilder Rsa() => RsaBuilder.Create();

    // ═══════════════════════════════════════════════════════════════════════════
    // Post-Quantum Cryptography
    // ═══════════════════════════════════════════════════════════════════════════

#if NET10_0_OR_GREATER
#pragma warning disable SYSLIB5006 // Post-quantum cryptography types are experimental
    /// <summary>
    /// Creates an ML-DSA (Module-Lattice Digital Signature Algorithm) builder.
    /// </summary>
    /// <remarks>
    /// ML-DSA (formerly Dilithium) is a post-quantum digital signature algorithm
    /// standardized by NIST. Provides quantum-resistant signatures.
    /// </remarks>
    /// <returns>An ML-DSA builder instance.</returns>
    public static MLDsaBuilder MLDsa() => MLDsaBuilder.Create();

    /// <summary>
    /// Creates an ML-KEM (Module-Lattice Key Encapsulation Mechanism) builder.
    /// </summary>
    /// <remarks>
    /// ML-KEM (formerly Kyber) is a post-quantum key encapsulation mechanism
    /// standardized by NIST. Provides quantum-resistant key exchange.
    /// </remarks>
    /// <returns>An ML-KEM builder instance.</returns>
    public static MLKemBuilder MLKem() => MLKemBuilder.Create();

    /// <summary>
    /// Creates an SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) builder.
    /// </summary>
    /// <remarks>
    /// SLH-DSA (formerly SPHINCS+) is a post-quantum digital signature algorithm
    /// based on hash functions. Provides conservative quantum-resistant signatures.
    /// </remarks>
    /// <returns>An SLH-DSA builder instance.</returns>
    public static SlhDsaBuilder SlhDsa() => SlhDsaBuilder.Create();
#pragma warning restore SYSLIB5006
#endif
}
