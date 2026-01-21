# OpenPGP RFC Full Compliance Implementation Plan

**Document Version**: 1.0
**Date**: 2026-01-21
**Target RFCs**: RFC 4880, RFC 9580, RFC 5581, RFC 6637

---

## Executive Summary

This plan outlines the implementation work required to achieve full OpenPGP RFC compliance. Items are prioritized by:
- **P1 (Critical)**: Blocks common use cases
- **P2 (High)**: RFC MUST requirements
- **P3 (Medium)**: Improves interoperability
- **P4 (Low)**: Optional features

---

## Phase 1: S2K (String-to-Key) Integration

**Priority**: P1 (Critical)
**Estimated Complexity**: Medium
**Dependencies**: Existing Argon2 implementation

### Background

S2K (String-to-Key) converts a passphrase into a symmetric key for:
1. Encrypting secret key material (Tag 5, 7)
2. Symmetric-Key Encrypted Session Key packets (Tag 3)

RFC 4880 Section 3.7 defines four S2K specifier types.

### 1.1 Simple S2K (Type 0)

**RFC Reference**: RFC 4880 Section 3.7.1.1

**Algorithm**:
```
key = Hash(passphrase)
```

**Implementation Steps**:

1. Create `src/HeroCrypt/Primitives/S2K/S2KSpecifier.cs`:
```csharp
namespace HeroCrypt.Primitives.S2K;

/// <summary>
/// S2K (String-to-Key) specifier types per RFC 4880 Section 3.7.
/// </summary>
public enum S2KType : byte
{
    /// <summary>Simple S2K - direct hash of passphrase.</summary>
    Simple = 0,

    /// <summary>Salted S2K - hash with 8-byte salt.</summary>
    Salted = 1,

    /// <summary>Reserved (not used).</summary>
    Reserved = 2,

    /// <summary>Iterated and Salted S2K - hash with salt and iteration count.</summary>
    IteratedAndSalted = 3,

    /// <summary>Argon2 - modern memory-hard KDF (RFC 9580).</summary>
    Argon2 = 4
}
```

2. Create `src/HeroCrypt/Primitives/S2K/SimpleS2K.cs`:
```csharp
/// <summary>
/// Simple S2K - RFC 4880 Section 3.7.1.1
/// WARNING: Not recommended for security. Use Iterated or Argon2 instead.
/// </summary>
[Obsolete("Simple S2K provides minimal security. Use IteratedS2K or Argon2S2K.")]
public static class SimpleS2K
{
    public static byte[] DeriveKey(
        ReadOnlySpan<byte> passphrase,
        HashAlgorithmName hashAlgorithm,
        int keyLength)
    {
        // Hash passphrase, repeat if needed for key length
        // See RFC 4880 Section 3.7.1.1 for multi-hash handling
    }
}
```

**Test Cases**:
- Empty passphrase handling
- Key length > hash output (requires multiple hashes with preload)
- All supported hash algorithms

---

### 1.2 Salted S2K (Type 1)

**RFC Reference**: RFC 4880 Section 3.7.1.2

**Algorithm**:
```
key = Hash(salt || passphrase)
```

**Implementation Steps**:

1. Create `src/HeroCrypt/Primitives/S2K/SaltedS2K.cs`:
```csharp
/// <summary>
/// Salted S2K - RFC 4880 Section 3.7.1.2
/// </summary>
public static class SaltedS2K
{
    public const int SaltLength = 8; // Fixed 8-byte salt per RFC

    public static byte[] DeriveKey(
        ReadOnlySpan<byte> passphrase,
        ReadOnlySpan<byte> salt,  // Must be 8 bytes
        HashAlgorithmName hashAlgorithm,
        int keyLength)
    {
        if (salt.Length != SaltLength)
            throw new ArgumentException("Salt must be exactly 8 bytes", nameof(salt));

        // Concatenate salt + passphrase, then hash
    }
}
```

**Test Cases**:
- Salt length validation
- Known test vectors from other implementations (GnuPG, OpenPGP.js)

---

### 1.3 Iterated and Salted S2K (Type 3)

**Priority**: P1 (Most commonly used)
**RFC Reference**: RFC 4880 Section 3.7.1.3

**Algorithm**:
```
data = salt || passphrase
repeat data until count bytes processed
key = Hash(repeated_data)
```

**Implementation Steps**:

1. Create `src/HeroCrypt/Primitives/S2K/IteratedS2K.cs`:
```csharp
/// <summary>
/// Iterated and Salted S2K - RFC 4880 Section 3.7.1.3
/// This is the most commonly used S2K type.
/// </summary>
public static class IteratedS2K
{
    public const int SaltLength = 8;

    /// <summary>
    /// Decodes the count byte to actual iteration count.
    /// RFC 4880: count = (16 + (c & 15)) << ((c >> 4) + 6)
    /// </summary>
    public static int DecodeCount(byte encodedCount)
    {
        return (16 + (encodedCount & 15)) << ((encodedCount >> 4) + 6);
    }

    /// <summary>
    /// Encodes an iteration count to the single-byte format.
    /// </summary>
    public static byte EncodeCount(int count)
    {
        // Find closest encodable value
        // Minimum: 1024 (0x00), Maximum: 65011712 (0xFF)
    }

    public static byte[] DeriveKey(
        ReadOnlySpan<byte> passphrase,
        ReadOnlySpan<byte> salt,
        byte encodedCount,
        HashAlgorithmName hashAlgorithm,
        int keyLength)
    {
        int count = DecodeCount(encodedCount);

        // Create buffer: salt || passphrase
        // Hash 'count' bytes of repeated buffer
    }
}
```

2. **Count encoding table** (for reference):

| Encoded | Decoded Count | Approx. Iterations |
|---------|---------------|-------------------|
| 0x00 | 1,024 | 1K |
| 0x60 | 65,536 | 64K |
| 0x90 | 262,144 | 256K |
| 0xC0 | 1,048,576 | 1M |
| 0xFF | 65,011,712 | 65M |

**Test Cases**:
- Count encoding/decoding round-trip
- Minimum count (0x00 = 1024)
- Maximum count (0xFF = 65011712)
- GnuPG interoperability test vectors

---

### 1.4 Argon2 S2K (Type 4) - RFC 9580

**Priority**: P2 (Modern best practice)
**RFC Reference**: RFC 9580 Section 3.7.1.4

**Algorithm**:
```
key = Argon2id(passphrase, salt, t, p, m)
```

**Implementation Steps**:

1. Create `src/HeroCrypt/Primitives/S2K/Argon2S2K.cs`:
```csharp
/// <summary>
/// Argon2 S2K - RFC 9580 Section 3.7.1.4
/// Modern memory-hard key derivation for OpenPGP.
/// </summary>
public static class Argon2S2K
{
    public const int SaltLength = 16; // RFC 9580 requires 16 bytes

    public static byte[] DeriveKey(
        ReadOnlySpan<byte> passphrase,
        ReadOnlySpan<byte> salt,      // 16 bytes
        byte timePasses,              // t parameter (1-255)
        byte parallelism,             // p parameter (1-255)
        byte memoryExponent,          // m = 2^memoryExponent KiB
        int keyLength)
    {
        // Use existing Argon2Core with Argon2id variant
        int memorySizeKiB = 1 << memoryExponent;

        return Argon2Core.DeriveKey(
            Argon2Type.Argon2id,
            passphrase,
            salt,
            timePasses,
            memorySizeKiB,
            parallelism,
            keyLength);
    }
}
```

**Test Cases**:
- RFC 9580 test vectors
- Memory parameter encoding (2^m KiB)
- Integration with existing Argon2Core

---

### 1.5 Unified S2K Interface

Create a unified interface for all S2K types:

```csharp
// src/HeroCrypt/Primitives/S2K/S2KParameters.cs

/// <summary>
/// Parsed S2K parameters from OpenPGP packet data.
/// </summary>
public readonly struct S2KParameters
{
    public S2KType Type { get; init; }
    public HashAlgorithmName HashAlgorithm { get; init; }
    public ReadOnlyMemory<byte> Salt { get; init; }
    public byte EncodedCount { get; init; }  // For Type 3

    // Argon2 parameters (Type 4)
    public byte Argon2TimePasses { get; init; }
    public byte Argon2Parallelism { get; init; }
    public byte Argon2MemoryExponent { get; init; }

    public static S2KParameters Parse(ReadOnlySpan<byte> data);
    public byte[] Serialize();

    public byte[] DeriveKey(ReadOnlySpan<byte> passphrase, int keyLength);
}
```

---

### 1.6 Integration Points

After implementing S2K, integrate with:

1. **PgpSecretKeyPacket.cs** - Decrypt encrypted key material:
```csharp
// Add method to decrypt secret key with passphrase
public PgpSecretKeyPacket DecryptKeyMaterial(ReadOnlySpan<byte> passphrase)
{
    var s2k = S2KParameters.Parse(s2kData);
    var key = s2k.DeriveKey(passphrase, GetKeyLength(symmetricAlgorithm));
    // Decrypt and verify checksum
}
```

2. **PgpMessageDecryptor.cs** - Remove TODO at line 279:
```csharp
// Before:
// TODO: Decrypt key with passphrase (requires S2K key derivation)

// After:
var s2k = S2KParameters.Parse(secretKey.S2KData);
var derivedKey = s2k.DeriveKey(passphrase, keyLength);
var decryptedKey = DecryptSecretKeyMaterial(secretKey, derivedKey);
```

---

## Phase 2: SKESK Packet (Tag 3)

**Priority**: P1 (Critical)
**Estimated Complexity**: Medium
**Dependencies**: Phase 1 (S2K)

### Background

Symmetric-Key Encrypted Session Key (SKESK) enables password-only encryption without public keys. Essential for:
- Password-protected files
- Symmetric encryption workflows
- Backup scenarios

### 2.1 SKESK v4 (RFC 4880)

**RFC Reference**: RFC 4880 Section 5.3

**Packet Structure**:
```
- Version (1 byte): 4
- Symmetric Algorithm (1 byte)
- S2K Specifier (variable)
- [Optional] Encrypted Session Key
```

**Implementation**:

```csharp
// src/HeroCrypt/Primitives/OpenPgp/PgpSymmetricKeyEncryptedSessionKeyPacket.cs

/// <summary>
/// Symmetric-Key Encrypted Session Key Packet (Tag 3) - RFC 4880 Section 5.3
/// </summary>
public readonly struct PgpSymmetricKeyEncryptedSessionKeyPacket
{
    public byte Version { get; init; }  // 4 or 6
    public SymmetricCipherAlgorithm SymmetricAlgorithm { get; init; }
    public S2KParameters S2K { get; init; }
    public ReadOnlyMemory<byte>? EncryptedSessionKey { get; init; }

    /// <summary>
    /// Derives the session key from a passphrase.
    /// </summary>
    public byte[] DecryptSessionKey(ReadOnlySpan<byte> passphrase)
    {
        var keyLength = PgpKeyEncryption.GetSessionKeySize(SymmetricAlgorithm);
        var derivedKey = S2K.DeriveKey(passphrase, keyLength);

        if (EncryptedSessionKey == null)
        {
            // No encrypted key - derived key IS the session key
            return derivedKey;
        }

        // Decrypt the session key with the derived key
        return DecryptSessionKeyData(derivedKey, EncryptedSessionKey.Value.Span);
    }

    public static PgpSymmetricKeyEncryptedSessionKeyPacket Parse(ReadOnlySpan<byte> data);
    public byte[] Serialize();

    /// <summary>
    /// Creates a new SKESK packet for encrypting a message with a passphrase.
    /// </summary>
    public static PgpSymmetricKeyEncryptedSessionKeyPacket Create(
        ReadOnlySpan<byte> passphrase,
        SymmetricCipherAlgorithm algorithm,
        S2KType s2kType = S2KType.IteratedAndSalted,
        HashAlgorithmName hashAlgorithm = default,
        byte[]? sessionKey = null)  // null = use derived key directly
    {
        // Generate salt, create S2K parameters, optionally encrypt session key
    }
}
```

### 2.2 SKESK v6 (RFC 9580)

**RFC Reference**: RFC 9580 Section 5.3.2

**Additional Fields**:
```
- Version (1 byte): 6
- Symmetric Algorithm + S2K Length (variable)
- S2K Specifier
- AEAD Algorithm (if AEAD)
- IV (if AEAD)
- Encrypted Session Key + Tag
```

```csharp
public readonly struct PgpSymmetricKeyEncryptedSessionKeyPacketV6
{
    public SymmetricCipherAlgorithm SymmetricAlgorithm { get; init; }
    public AeadAlgorithm AeadAlgorithm { get; init; }
    public S2KParameters S2K { get; init; }
    public ReadOnlyMemory<byte> IV { get; init; }
    public ReadOnlyMemory<byte> EncryptedSessionKeyAndTag { get; init; }

    // AEAD-authenticated decryption
    public byte[] DecryptSessionKey(ReadOnlySpan<byte> passphrase);
}
```

### 2.3 Integration with Message Encryption/Decryption

Update `PgpMessageEncryptor` and `PgpMessageDecryptor`:

```csharp
// PgpMessageEncryptor.cs - Add password-based encryption

public PgpMessageEncryptor WithPassphrase(
    ReadOnlySpan<byte> passphrase,
    SymmetricCipherAlgorithm algorithm = SymmetricCipherAlgorithm.Aes256,
    S2KType s2kType = S2KType.IteratedAndSalted)
{
    // Create SKESK packet
    // Use session key for SEIPD encryption
}

// PgpMessageDecryptor.cs - Add password-based decryption

public byte[] DecryptWithPassphrase(ReadOnlySpan<byte> passphrase)
{
    var skesk = FindPacket<PgpSymmetricKeyEncryptedSessionKeyPacket>();
    var sessionKey = skesk.DecryptSessionKey(passphrase);
    return DecryptWithSessionKey(sessionKey);
}
```

---

## Phase 3: Legacy Symmetric Ciphers

**Priority**: P2 (RFC 4880 MUST)
**Estimated Complexity**: Medium
**Note**: These are marked `[Obsolete]` but required for interoperability

### 3.1 TripleDES (3DES) - Algorithm ID 2

**RFC Reference**: RFC 4880 Section 9.2
**Status**: MUST implement

**Specifications**:
- Key size: 192 bits (168 effective)
- Block size: 64 bits
- Mode: CFB (for OpenPGP)

**Implementation**:

```csharp
// src/HeroCrypt/Primitives/TripleDes/TripleDesCore.cs

/// <summary>
/// Triple DES implementation for OpenPGP compatibility.
/// </summary>
/// <remarks>
/// WARNING: 3DES has a 64-bit block size making it vulnerable to
/// birthday attacks after 2^32 blocks (~32GB). Use AES for new applications.
/// </remarks>
[Obsolete("3DES is deprecated. Use AES-256 for new applications.")]
public static class TripleDesCore
{
    public const int KeySize = 24;      // 192 bits
    public const int BlockSize = 8;     // 64 bits

    /// <summary>
    /// Encrypts data using 3DES-CFB mode (OpenPGP style).
    /// </summary>
    public static byte[] EncryptCfb(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv)
    {
        using var des = TripleDES.Create();
        des.Key = key.ToArray();
        des.IV = iv.ToArray();
        des.Mode = CipherMode.CFB;
        des.Padding = PaddingMode.None;
        des.FeedbackSize = 64; // Full block CFB

        // OpenPGP uses CFB with resync
    }

    /// <summary>
    /// Decrypts data using 3DES-CFB mode (OpenPGP style).
    /// </summary>
    public static byte[] DecryptCfb(
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv);
}
```

**Test Cases**:
- NIST test vectors
- OpenPGP CFB mode with resync
- Interoperability with GnuPG-encrypted messages

---

### 3.2 CAST5 (CAST-128) - Algorithm ID 3

**RFC Reference**: RFC 4880 Section 9.2, RFC 2144
**Status**: MUST implement

**Specifications**:
- Key size: 128 bits
- Block size: 64 bits
- Rounds: 16 (12 for keys ≤ 80 bits)

**Implementation**:

```csharp
// src/HeroCrypt/Primitives/Cast5/Cast5Core.cs

/// <summary>
/// CAST5 (CAST-128) implementation for OpenPGP compatibility.
/// </summary>
/// <remarks>
/// CAST5 was the default cipher in PGP 5.x and early GnuPG versions.
/// It has a 64-bit block size making it vulnerable to birthday attacks.
/// </remarks>
[Obsolete("CAST5 is deprecated. Use AES-256 for new applications.")]
public static class Cast5Core
{
    public const int KeySize = 16;      // 128 bits
    public const int BlockSize = 8;     // 64 bits
    public const int Rounds = 16;

    // S-boxes (RFC 2144 Appendix A)
    private static readonly uint[] S1 = { /* 256 entries */ };
    private static readonly uint[] S2 = { /* 256 entries */ };
    private static readonly uint[] S3 = { /* 256 entries */ };
    private static readonly uint[] S4 = { /* 256 entries */ };

    /// <summary>
    /// Expands the key into round subkeys.
    /// </summary>
    private static void ExpandKey(ReadOnlySpan<byte> key, Span<uint> km, Span<uint> kr);

    /// <summary>
    /// Encrypts a single 64-bit block.
    /// </summary>
    public static void EncryptBlock(
        ReadOnlySpan<byte> input,
        Span<byte> output,
        ReadOnlySpan<uint> km,
        ReadOnlySpan<uint> kr);

    /// <summary>
    /// Encrypts data using CAST5-CFB mode (OpenPGP style).
    /// </summary>
    public static byte[] EncryptCfb(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv);
}
```

**Test Cases**:
- RFC 2144 Appendix B test vectors
- OpenPGP CFB mode
- GnuPG interoperability (CAST5 was default for years)

---

### 3.3 Blowfish - Algorithm ID 4

**RFC Reference**: RFC 4880 Section 9.2
**Status**: Optional (but common)

**Specifications**:
- Key size: 32-448 bits (128 bits for OpenPGP)
- Block size: 64 bits
- Rounds: 16

**Implementation**:

```csharp
// src/HeroCrypt/Primitives/Blowfish/BlowfishCore.cs

[Obsolete("Blowfish is deprecated. Use AES-256 or ChaCha20 for new applications.")]
public static class BlowfishCore
{
    public const int KeySize = 16;      // 128 bits (OpenPGP default)
    public const int BlockSize = 8;     // 64 bits

    // P-array and S-boxes initialization
    private static readonly uint[] InitP = { /* 18 entries */ };
    private static readonly uint[] InitS = { /* 4 * 256 entries */ };

    public static byte[] EncryptCfb(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv);
}
```

---

### 3.4 IDEA - Algorithm ID 1

**RFC Reference**: RFC 4880 Section 9.2
**Status**: Optional (legacy PGP 2.x)
**Note**: Patent expired in 2012

**Specifications**:
- Key size: 128 bits
- Block size: 64 bits
- Rounds: 8.5

```csharp
// src/HeroCrypt/Primitives/Idea/IdeaCore.cs

[Obsolete("IDEA is deprecated. Use AES-256 for new applications.")]
public static class IdeaCore
{
    public const int KeySize = 16;      // 128 bits
    public const int BlockSize = 8;     // 64 bits

    // IDEA uses multiplication, addition, and XOR in GF(2^16+1)
    private static ushort Mul(ushort a, ushort b);  // Multiplication mod 2^16+1

    public static byte[] EncryptCfb(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv);
}
```

---

### 3.5 OpenPGP CFB Mode Integration

All legacy ciphers need OpenPGP-specific CFB mode:

```csharp
// src/HeroCrypt/Primitives/OpenPgp/OpenPgpCfb.cs

/// <summary>
/// OpenPGP CFB mode with resynchronization (RFC 4880 Section 13.9).
/// </summary>
public static class OpenPgpCfb
{
    /// <summary>
    /// Encrypts using OpenPGP CFB mode with prefix and resync.
    /// </summary>
    /// <remarks>
    /// OpenPGP CFB mode:
    /// 1. Encrypt block_size + 2 random bytes as prefix
    /// 2. Last two bytes of prefix repeated for quick check
    /// 3. After prefix, resync FR (feedback register)
    /// </remarks>
    public static byte[] Encrypt(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        SymmetricCipherAlgorithm algorithm)
    {
        var blockSize = GetBlockSize(algorithm);

        // Generate random prefix: block_size bytes + 2 repeated bytes
        var prefix = new byte[blockSize + 2];
        RandomNumberGenerator.Fill(prefix.AsSpan(0, blockSize));
        prefix[blockSize] = prefix[blockSize - 2];
        prefix[blockSize + 1] = prefix[blockSize - 1];

        // Encrypt with resync after prefix
    }
}
```

---

## Phase 4: Optional Ciphers

**Priority**: P3 (Interoperability)
**Estimated Complexity**: Medium

### 4.1 Twofish - Algorithm ID 10

**Specifications**:
- Key size: 256 bits
- Block size: 128 bits
- AES finalist

```csharp
// src/HeroCrypt/Primitives/Twofish/TwofishCore.cs

public static class TwofishCore
{
    public const int KeySize = 32;      // 256 bits
    public const int BlockSize = 16;    // 128 bits

    // Twofish uses key-dependent S-boxes
    private static void GenerateSboxes(ReadOnlySpan<byte> key, /* out params */);
}
```

### 4.2 Camellia - Algorithm IDs 11, 12, 13

**RFC Reference**: RFC 5581

**Specifications**:
- Key sizes: 128, 192, 256 bits
- Block size: 128 bits
- Japanese government standard

```csharp
// src/HeroCrypt/Primitives/Camellia/CamelliaCore.cs

public static class CamelliaCore
{
    public const int BlockSize = 16;    // 128 bits

    public static byte[] Encrypt(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key);  // 16, 24, or 32 bytes
}
```

---

## Phase 5: Additional Packet Types

**Priority**: P4 (Completeness)

### 5.1 Trust Packet (Tag 12)

Implementation-specific, can be simple placeholder.

### 5.2 Marker Packet (Tag 10)

Obsolete but should be recognized and ignored.

---

## Implementation Order Summary

| Order | Component | Priority | Complexity | Dependencies |
|-------|-----------|----------|------------|--------------|
| 1 | Simple S2K | P1 | Low | None |
| 2 | Salted S2K | P1 | Low | None |
| 3 | Iterated S2K | P1 | Medium | None |
| 4 | Argon2 S2K Integration | P2 | Low | Existing Argon2 |
| 5 | S2K Parameters Parser | P1 | Medium | S2K implementations |
| 6 | Secret Key Decryption | P1 | Medium | S2K |
| 7 | SKESK v4 | P1 | Medium | S2K |
| 8 | SKESK v6 | P2 | Medium | S2K, AEAD |
| 9 | TripleDES | P2 | Medium | None |
| 10 | CAST5 | P2 | High | None (custom impl) |
| 11 | OpenPGP CFB Mode | P2 | Medium | Legacy ciphers |
| 12 | Blowfish | P3 | High | None (custom impl) |
| 13 | IDEA | P3 | High | None (custom impl) |
| 14 | Twofish | P3 | High | None (custom impl) |
| 15 | Camellia | P3 | High | None (custom impl) |

---

## Testing Strategy

### Unit Tests

Each component should have:
1. **RFC Test Vectors**: Where available in RFCs
2. **Known Answer Tests (KAT)**: From other implementations
3. **Round-trip Tests**: Encrypt/decrypt verification
4. **Edge Cases**: Empty input, maximum sizes, etc.

### Integration Tests

1. **GnuPG Interoperability**:
   - Generate keys with GnuPG, decrypt with HeroCrypt
   - Encrypt with HeroCrypt, decrypt with GnuPG
   - Test each S2K type
   - Test each cipher

2. **OpenPGP.js Interoperability**:
   - Browser-based OpenPGP implementation
   - Good for cross-platform testing

3. **Sequoia-PGP Interoperability**:
   - Modern Rust implementation
   - Strict RFC compliance

### Test Vector Sources

| Component | Source |
|-----------|--------|
| S2K | GnuPG test suite |
| CAST5 | RFC 2144 Appendix B |
| Blowfish | Blowfish paper test vectors |
| IDEA | IDEA paper test vectors |
| Twofish | AES submission test vectors |
| Camellia | RFC 3713 |

---

## File Structure

```
src/HeroCrypt/Primitives/
├── S2K/
│   ├── S2KType.cs
│   ├── S2KParameters.cs
│   ├── SimpleS2K.cs
│   ├── SaltedS2K.cs
│   ├── IteratedS2K.cs
│   └── Argon2S2K.cs
├── TripleDes/
│   └── TripleDesCore.cs
├── Cast5/
│   └── Cast5Core.cs
├── Blowfish/
│   └── BlowfishCore.cs
├── Idea/
│   └── IdeaCore.cs
├── Twofish/
│   └── TwofishCore.cs
├── Camellia/
│   └── CamelliaCore.cs
└── OpenPgp/
    ├── OpenPgpCfb.cs
    ├── PgpSymmetricKeyEncryptedSessionKeyPacket.cs
    └── (existing files updated)

tests/HeroCrypt.Tests/
├── S2K/
│   ├── SimpleS2KTests.cs
│   ├── SaltedS2KTests.cs
│   ├── IteratedS2KTests.cs
│   └── Argon2S2KTests.cs
├── Ciphers/
│   ├── TripleDesTests.cs
│   ├── Cast5Tests.cs
│   ├── BlowfishTests.cs
│   ├── IdeaTests.cs
│   ├── TwofishTests.cs
│   └── CamelliaTests.cs
└── OpenPgp/
    ├── SkeskTests.cs
    └── InteroperabilityTests.cs
```

---

## Acceptance Criteria

### Phase 1 Complete When:
- [ ] All 4 S2K types implemented
- [ ] Can decrypt GnuPG-encrypted secret keys
- [ ] Unit tests pass with known test vectors

### Phase 2 Complete When:
- [ ] SKESK v4 and v6 packets implemented
- [ ] Can encrypt/decrypt messages with passphrase only
- [ ] GnuPG interoperability confirmed

### Phase 3 Complete When:
- [ ] TripleDES and CAST5 implemented (MUST per RFC 4880)
- [ ] Can decrypt messages encrypted with legacy ciphers
- [ ] OpenPGP CFB mode working correctly

### Phase 4 Complete When:
- [ ] All optional ciphers implemented
- [ ] Full RFC 4880 cipher support achieved

### Full Compliance When:
- [ ] All phases complete
- [ ] Interoperability tests pass with GnuPG, OpenPGP.js, Sequoia
- [ ] No `[NotImplemented]` attributes on RFC 4880 MUST items

---

*Document Created: 2026-01-21*
*Target Completion: TBD*
