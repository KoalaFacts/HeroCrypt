namespace HeroCrypt.Operations;

/// <summary>
/// Symmetric and asymmetric encryption algorithms.
/// </summary>
/// <remarks>
/// <para><b>Platform Support Summary:</b></para>
/// <list type="table">
///   <listheader>
///     <term>Algorithm</term>
///     <description>Platform Support</description>
///   </listheader>
///   <item>
///     <term>AesGcm</term>
///     <description>Windows, Linux, macOS (.NET 6+). Not available on .NET Standard 2.0.</description>
///   </item>
///   <item>
///     <term>AesCcm</term>
///     <description>Windows, Linux only. macOS not supported. Not available on .NET Standard 2.0.</description>
///   </item>
///   <item>
///     <term>ChaCha20Poly1305</term>
///     <description>All platforms (pure managed implementation).</description>
///   </item>
///   <item>
///     <term>XChaCha20Poly1305</term>
///     <description>All platforms (pure managed implementation).</description>
///   </item>
///   <item>
///     <term>RsaOaepSha256</term>
///     <description>All platforms. Key import requires .NET 5+.</description>
///   </item>
///   <item>
///     <term>MLKem*</term>
///     <description>.NET 10+ only (post-quantum cryptography).</description>
///   </item>
/// </list>
/// <para>
/// Algorithms marked with <see cref="NotImplementedAttribute"/> are planned for future implementation.
/// </para>
/// </remarks>
public enum EncryptionAlgorithm
{
    // ─────────────────────────────────────────────────────────────────────────
    // AEAD Ciphers - Block Cipher Based
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// AES-GCM (Galois/Counter Mode) - AEAD cipher.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> NIST SP 800-38D</para>
    /// <para><b>Key sizes:</b> 128, 192, or 256 bits</para>
    /// <para><b>Nonce size:</b> 12 bytes (96 bits)</para>
    /// <para><b>Tag size:</b> 16 bytes (128 bits)</para>
    /// <para><b>Platform Support:</b></para>
    /// <list type="bullet">
    ///   <item><description>Windows: Fully supported via CNG.</description></item>
    ///   <item><description>Linux: Fully supported via OpenSSL.</description></item>
    ///   <item><description>macOS: Supported in .NET 6+.</description></item>
    ///   <item><description>.NET Standard 2.0: Not supported.</description></item>
    /// </list>
    /// </remarks>
    AesGcm,

    /// <summary>
    /// AES-CCM (Counter with CBC-MAC) - AEAD cipher.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 3610, NIST SP 800-38C</para>
    /// <para><b>Key sizes:</b> 128, 192, or 256 bits</para>
    /// <para><b>Nonce size:</b> 7-13 bytes (typically 13)</para>
    /// <para><b>Tag size:</b> 4-16 bytes (even numbers only)</para>
    /// <para><b>Use cases:</b> Bluetooth LE, Zigbee, Thread, IEEE 802.15.4</para>
    /// <para><b>Platform Support:</b></para>
    /// <list type="bullet">
    ///   <item><description>Windows: Fully supported via CNG.</description></item>
    ///   <item><description>Linux: Fully supported via OpenSSL.</description></item>
    ///   <item><description>macOS: <b>Not supported.</b> CommonCrypto does not implement CCM mode.</description></item>
    ///   <item><description>.NET Standard 2.0: Not supported.</description></item>
    /// </list>
    /// </remarks>
    AesCcm,

    /// <summary>
    /// AES-GCM-SIV (Synthetic Initialization Vector) - Nonce-misuse resistant AEAD.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 8452</para>
    /// <para><b>Key sizes:</b> 128 or 256 bits</para>
    /// <para><b>Nonce size:</b> 12 bytes (96 bits)</para>
    /// <para><b>Tag size:</b> 16 bytes (128 bits)</para>
    /// <para><b>Platform Support:</b> All platforms (pure managed implementation planned).</para>
    /// <para>
    /// Provides security even if a nonce is accidentally reused. If nonce reuse occurs,
    /// only reveals whether the same plaintext was encrypted twice (no key recovery).
    /// Recommended when nonce uniqueness cannot be guaranteed.
    /// </para>
    /// </remarks>
    [NotImplemented("Nonce-misuse resistant variant - high priority for safety", Priority = 1)]
    AesGcmSiv,

    /// <summary>
    /// AES-SIV (Synthetic Initialization Vector) - Deterministic AEAD.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 5297</para>
    /// <para><b>Key sizes:</b> 256, 384, or 512 bits (split into two keys)</para>
    /// <para><b>Nonce size:</b> Optional (can be zero for deterministic encryption)</para>
    /// <para><b>Tag size:</b> 16 bytes (128 bits, placed at beginning)</para>
    /// <para><b>Platform Support:</b> All platforms (pure managed implementation).</para>
    /// <para>
    /// Deterministic authenticated encryption - same plaintext always produces same ciphertext.
    /// Ideal for key wrapping, database encryption where determinism is needed, and
    /// scenarios where nonce generation is impractical.
    /// </para>
    /// </remarks>
    AesSiv,

    /// <summary>
    /// AES-OCB (Offset Codebook Mode) - High-performance AEAD.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 7253</para>
    /// <para><b>Key sizes:</b> 128, 192, or 256 bits</para>
    /// <para><b>Nonce size:</b> 1-15 bytes (typically 12)</para>
    /// <para><b>Tag size:</b> 16 bytes</para>
    /// <para><b>Platform Support:</b> All platforms (pure managed implementation).</para>
    /// <para>
    /// Fastest AEAD mode - single pass for both encryption and authentication.
    /// Patent-free since November 2021. Approximately 2x faster than GCM.
    /// </para>
    /// </remarks>
    AesOcb,

    // ─────────────────────────────────────────────────────────────────────────
    // AEAD Ciphers - Stream Cipher Based
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// ChaCha20-Poly1305 - AEAD stream cipher.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 8439</para>
    /// <para><b>Key size:</b> 256 bits (32 bytes)</para>
    /// <para><b>Nonce size:</b> 12 bytes (96 bits)</para>
    /// <para><b>Tag size:</b> 16 bytes (128 bits)</para>
    /// <para><b>Platform Support:</b> All platforms (pure managed implementation).</para>
    /// <para>
    /// Recommended alternative to AES-GCM when hardware AES acceleration is unavailable.
    /// Constant-time implementation resistant to timing attacks.
    /// </para>
    /// </remarks>
    ChaCha20Poly1305,

    /// <summary>
    /// XChaCha20-Poly1305 - Extended nonce AEAD stream cipher.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> draft-irtf-cfrg-xchacha</para>
    /// <para><b>Key size:</b> 256 bits (32 bytes)</para>
    /// <para><b>Nonce size:</b> 24 bytes (192 bits)</para>
    /// <para><b>Tag size:</b> 16 bytes (128 bits)</para>
    /// <para><b>Platform Support:</b> All platforms (pure managed implementation).</para>
    /// <para>
    /// Extended nonce variant allows safe random nonce generation without collision concerns.
    /// Recommended for scenarios where nonce uniqueness cannot be guaranteed.
    /// </para>
    /// </remarks>
    XChaCha20Poly1305,

    // ─────────────────────────────────────────────────────────────────────────
    // Lightweight AEAD (IoT/Constrained Devices)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Ascon-128 - Lightweight AEAD cipher.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> NIST Lightweight Cryptography Winner (2023)</para>
    /// <para><b>Key size:</b> 128 bits (16 bytes)</para>
    /// <para><b>Nonce size:</b> 128 bits (16 bytes)</para>
    /// <para><b>Tag size:</b> 128 bits (16 bytes)</para>
    /// <para><b>Platform Support:</b> All platforms (pure managed implementation planned).</para>
    /// <para>
    /// NIST's selected algorithm for lightweight cryptography standard.
    /// Designed for constrained devices (IoT, embedded systems, smart cards).
    /// Efficient in both software and hardware implementations.
    /// </para>
    /// </remarks>
    [NotImplemented("NIST lightweight crypto winner - important for IoT", Priority = 2)]
    Ascon128,

    /// <summary>
    /// Ascon-128a - High-throughput lightweight AEAD cipher.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> NIST Lightweight Cryptography Winner (2023)</para>
    /// <para><b>Key size:</b> 128 bits (16 bytes)</para>
    /// <para><b>Nonce size:</b> 128 bits (16 bytes)</para>
    /// <para><b>Tag size:</b> 128 bits (16 bytes)</para>
    /// <para><b>Platform Support:</b> All platforms (pure managed implementation planned).</para>
    /// <para>
    /// Higher throughput variant of Ascon for less constrained devices.
    /// Processes 128 bits per round instead of 64 bits.
    /// </para>
    /// </remarks>
    [NotImplemented("High-throughput Ascon variant", Priority = 3)]
    Ascon128a,

    // ─────────────────────────────────────────────────────────────────────────
    // Asymmetric Encryption - RSA
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// RSA-OAEP with SHA-256 - Asymmetric encryption.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> PKCS#1 v2.2 (RFC 8017)</para>
    /// <para><b>Key sizes:</b> 2048, 3072, or 4096 bits recommended</para>
    /// <para><b>Max plaintext:</b> (key_size_bytes - 66) bytes for SHA-256</para>
    /// <para><b>Platform Support:</b></para>
    /// <list type="bullet">
    ///   <item><description>All platforms: RSA operations supported.</description></item>
    ///   <item><description>Key import (PKCS#8/SPKI): Requires .NET 5+ or .NET Core 3.0+.</description></item>
    ///   <item><description>.NET Standard 2.0: Key import not supported.</description></item>
    /// </list>
    /// <para>
    /// Suitable for encrypting small amounts of data (e.g., symmetric keys).
    /// For larger data, use hybrid encryption with a symmetric algorithm.
    /// </para>
    /// </remarks>
    RsaOaepSha256,

    /// <summary>
    /// RSA-OAEP with SHA-384 - Asymmetric encryption with stronger hash.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> PKCS#1 v2.2 (RFC 8017)</para>
    /// <para><b>Key sizes:</b> 3072 or 4096 bits recommended</para>
    /// <para><b>Max plaintext:</b> (key_size_bytes - 98) bytes for SHA-384</para>
    /// <para><b>Platform Support:</b> Same as RSA-OAEP-SHA256.</para>
    /// <para>
    /// Higher security margin for long-term protection.
    /// Slightly smaller maximum plaintext size than SHA-256 variant.
    /// </para>
    /// </remarks>
    RsaOaepSha384,

    /// <summary>
    /// RSA-OAEP with SHA-512 - Asymmetric encryption with strongest hash.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> PKCS#1 v2.2 (RFC 8017)</para>
    /// <para><b>Key sizes:</b> 4096 bits recommended</para>
    /// <para><b>Max plaintext:</b> (key_size_bytes - 130) bytes for SHA-512</para>
    /// <para><b>Platform Support:</b> Same as RSA-OAEP-SHA256.</para>
    /// <para>
    /// Maximum security for highly sensitive applications.
    /// Requires larger keys due to reduced plaintext capacity.
    /// </para>
    /// </remarks>
    RsaOaepSha512,

    // ─────────────────────────────────────────────────────────────────────────
    // Hybrid Encryption - Elliptic Curve
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// X25519 + ChaCha20-Poly1305 hybrid encryption.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 7748 (X25519), RFC 8439 (ChaCha20-Poly1305)</para>
    /// <para><b>Key size:</b> 256 bits (32 bytes) for X25519</para>
    /// <para><b>Shared secret:</b> 32 bytes (derived via HKDF-SHA256)</para>
    /// <para><b>Platform Support:</b> .NET 6+ (pure managed implementation). Not supported on .NET Standard 2.0.</para>
    /// <para>
    /// Modern hybrid encryption used in TLS 1.3, Signal Protocol, WireGuard, and Noise Protocol.
    /// Fast ECDH key exchange combined with efficient AEAD.
    /// Recommended for most modern applications.
    /// </para>
    /// </remarks>
    X25519ChaCha20Poly1305,

    /// <summary>
    /// X25519 + XChaCha20-Poly1305 hybrid encryption with extended nonce.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 7748 (X25519), draft-irtf-cfrg-xchacha</para>
    /// <para><b>Key size:</b> 256 bits (32 bytes) for X25519</para>
    /// <para><b>Nonce size:</b> 24 bytes (192 bits)</para>
    /// <para><b>Platform Support:</b> .NET 6+ (pure managed implementation). Not supported on .NET Standard 2.0.</para>
    /// <para>
    /// Extended nonce variant for scenarios where random nonces are preferred.
    /// Used by libsodium's crypto_box_seal.
    /// </para>
    /// </remarks>
    X25519XChaCha20Poly1305,

    /// <summary>
    /// X25519 + AES-GCM hybrid encryption.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 7748 (X25519), NIST SP 800-38D (AES-GCM)</para>
    /// <para><b>Key size:</b> 256 bits (32 bytes) for X25519</para>
    /// <para><b>Shared secret:</b> 32 bytes (derived via HKDF-SHA256)</para>
    /// <para><b>Platform Support:</b> .NET 6+ (X25519 managed, AES-GCM via platform). Not supported on .NET Standard 2.0.</para>
    /// <para>
    /// Alternative to ChaCha20 variant for environments with AES hardware acceleration.
    /// Common in enterprise environments with hardware security modules.
    /// </para>
    /// </remarks>
    X25519AesGcm,

    /// <summary>
    /// ECIES with P-256 curve - Elliptic Curve Integrated Encryption Scheme.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> IEEE 1363a, SECG SEC 1</para>
    /// <para><b>Curve:</b> NIST P-256 (secp256r1)</para>
    /// <para><b>KDF:</b> HKDF-SHA256</para>
    /// <para><b>AEAD:</b> AES-256-GCM</para>
    /// <para><b>Platform Support:</b> All platforms (ECDiffieHellman via platform).</para>
    /// <para>
    /// Standard elliptic curve encryption using NIST curves.
    /// Widely supported in enterprise and government applications.
    /// </para>
    /// </remarks>
    [NotImplemented("NIST curve ECIES for enterprise/government use", Priority = 3)]
    EciesP256,

    /// <summary>
    /// ECIES with P-384 curve - Higher security ECIES variant.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> IEEE 1363a, SECG SEC 1</para>
    /// <para><b>Curve:</b> NIST P-384 (secp384r1)</para>
    /// <para><b>KDF:</b> HKDF-SHA384</para>
    /// <para><b>AEAD:</b> AES-256-GCM</para>
    /// <para><b>Platform Support:</b> All platforms (ECDiffieHellman via platform).</para>
    /// <para>
    /// Higher security variant for sensitive applications.
    /// Required by some government standards (e.g., NSA Suite B).
    /// </para>
    /// </remarks>
    [NotImplemented("P-384 ECIES for higher security requirements", Priority = 4)]
    EciesP384,

    // ─────────────────────────────────────────────────────────────────────────
    // Hybrid Encryption - HPKE (RFC 9180)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// HPKE with X25519 and ChaCha20-Poly1305.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 9180</para>
    /// <para><b>KEM:</b> DHKEM(X25519, HKDF-SHA256)</para>
    /// <para><b>AEAD:</b> ChaCha20-Poly1305</para>
    /// <para><b>Platform Support:</b> All platforms (pure managed implementation planned).</para>
    /// <para>
    /// Modern RFC-standardized hybrid public key encryption.
    /// Supports single-shot encryption, authenticated modes, and secret export.
    /// Used in TLS Encrypted Client Hello (ECH) and MLS protocol.
    /// </para>
    /// </remarks>
    [NotImplemented("RFC 9180 HPKE - modern standard for hybrid encryption", Priority = 1)]
    HpkeX25519ChaCha20Poly1305,

    /// <summary>
    /// HPKE with X25519 and AES-GCM-128.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 9180</para>
    /// <para><b>KEM:</b> DHKEM(X25519, HKDF-SHA256)</para>
    /// <para><b>AEAD:</b> AES-128-GCM</para>
    /// <para><b>Platform Support:</b> All platforms.</para>
    /// <para>
    /// HPKE variant with AES-GCM for hardware acceleration scenarios.
    /// </para>
    /// </remarks>
    [NotImplemented("HPKE with AES-128-GCM", Priority = 3)]
    HpkeX25519AesGcm128,

    /// <summary>
    /// HPKE with X25519 and AES-GCM-256.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 9180</para>
    /// <para><b>KEM:</b> DHKEM(X25519, HKDF-SHA256)</para>
    /// <para><b>AEAD:</b> AES-256-GCM</para>
    /// <para><b>Platform Support:</b> All platforms.</para>
    /// <para>
    /// HPKE variant with AES-256-GCM for maximum symmetric security.
    /// </para>
    /// </remarks>
    [NotImplemented("HPKE with AES-256-GCM", Priority = 3)]
    HpkeX25519AesGcm256,

    /// <summary>
    /// HPKE with P-256 and AES-GCM-128.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 9180</para>
    /// <para><b>KEM:</b> DHKEM(P-256, HKDF-SHA256)</para>
    /// <para><b>AEAD:</b> AES-128-GCM</para>
    /// <para><b>Platform Support:</b> All platforms.</para>
    /// <para>
    /// HPKE with NIST P-256 curve for enterprise/government compliance.
    /// </para>
    /// </remarks>
    [NotImplemented("HPKE with NIST P-256 for compliance", Priority = 4)]
    HpkeP256AesGcm128,

    // ─────────────────────────────────────────────────────────────────────────
    // Post-Quantum Cryptography
    // ─────────────────────────────────────────────────────────────────────────

#if NET10_OR_GREATER
    /// <summary>
    /// ML-KEM-768 + AES-GCM hybrid encryption (post-quantum).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> FIPS 203 (ML-KEM), NIST SP 800-38D (AES-GCM)</para>
    /// <para><b>Security level:</b> ~192-bit classical, ~128-bit quantum</para>
    /// <para><b>Shared secret:</b> 32 bytes (used as AES-256 key)</para>
    /// <para><b>Platform Support:</b> .NET 10+ only.</para>
    /// <para>
    /// Post-quantum hybrid encryption combining ML-KEM key encapsulation with AES-GCM.
    /// Provides protection against both classical and quantum computer attacks.
    /// </para>
    /// </remarks>
    MLKem768AesGcm,

    /// <summary>
    /// ML-KEM-1024 + AES-GCM hybrid encryption (post-quantum).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> FIPS 203 (ML-KEM), NIST SP 800-38D (AES-GCM)</para>
    /// <para><b>Security level:</b> ~256-bit classical, ~192-bit quantum</para>
    /// <para><b>Shared secret:</b> 32 bytes (used as AES-256 key)</para>
    /// <para><b>Platform Support:</b> .NET 10+ only.</para>
    /// <para>
    /// Highest security level ML-KEM variant for maximum protection.
    /// Recommended for long-term secrets and high-security applications.
    /// </para>
    /// </remarks>
    MLKem1024AesGcm,

    /// <summary>
    /// ML-KEM-768 + ChaCha20-Poly1305 hybrid encryption (post-quantum).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> FIPS 203 (ML-KEM), RFC 8439 (ChaCha20-Poly1305)</para>
    /// <para><b>Security level:</b> ~192-bit classical, ~128-bit quantum</para>
    /// <para><b>Platform Support:</b> .NET 10+ only.</para>
    /// <para>
    /// Post-quantum hybrid with ChaCha20-Poly1305 for software-only environments.
    /// </para>
    /// </remarks>
    MLKem768ChaCha20Poly1305,

    /// <summary>
    /// ML-KEM-1024 + ChaCha20-Poly1305 hybrid encryption (post-quantum).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> FIPS 203 (ML-KEM), RFC 8439 (ChaCha20-Poly1305)</para>
    /// <para><b>Security level:</b> ~256-bit classical, ~192-bit quantum</para>
    /// <para><b>Platform Support:</b> .NET 10+ only.</para>
    /// <para>
    /// Maximum security post-quantum hybrid with ChaCha20-Poly1305.
    /// </para>
    /// </remarks>
    MLKem1024ChaCha20Poly1305,
#endif

    // ─────────────────────────────────────────────────────────────────────────
    // Legacy Algorithms (Compatibility Only)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// AES-CBC with HMAC-SHA256 - Legacy authenticated encryption.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> NIST SP 800-38A (CBC), RFC 2104 (HMAC)</para>
    /// <para><b>Key sizes:</b> 256 bits AES + 256 bits HMAC = 512 bits total</para>
    /// <para><b>IV size:</b> 16 bytes (128 bits)</para>
    /// <para><b>Tag size:</b> 32 bytes (256 bits, can be truncated)</para>
    /// <para><b>Platform Support:</b> All platforms.</para>
    /// <para>
    /// <b>Legacy algorithm.</b> Use Encrypt-then-MAC construction.
    /// Prefer AEAD ciphers (AES-GCM, ChaCha20-Poly1305) for new applications.
    /// Provided for compatibility with legacy systems.
    /// </para>
    /// </remarks>
    [NotImplemented("Legacy - for compatibility with older systems only", Priority = 5)]
    AesCbcHmacSha256,

    /// <summary>
    /// RSA-PKCS1v15 - Legacy RSA encryption padding.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> PKCS#1 v1.5 (RFC 2313)</para>
    /// <para><b>Key sizes:</b> 2048+ bits</para>
    /// <para><b>Platform Support:</b> All platforms.</para>
    /// <para>
    /// <b>Legacy algorithm - NOT RECOMMENDED.</b>
    /// Vulnerable to padding oracle attacks (Bleichenbacher's attack).
    /// Only use for compatibility with legacy systems that cannot be upgraded.
    /// Prefer RSA-OAEP for new applications.
    /// </para>
    /// </remarks>
    RsaPkcs1v15,
}
