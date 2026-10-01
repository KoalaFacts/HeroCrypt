# Migration Guide

This guide helps you migrate between HeroCrypt versions and from other cryptographic libraries.

## OpenPGP key-ring validation changes after v1.0.4

- `VerifySubkeyBindings()` and `FullValidation()` now reject subkeys without any
  binding signature. Previously this produced only a warning and `IsValid` was true.
  A binding must verify under the primary key for the exact subkey. Structural-only
  validation remains a presence check and does not establish cryptographic trust.
- `CheckRevocation()` now authenticates revocations under the primary key even when
  self-certification verification is disabled. Forged, malformed, misattributed or
  unsupported evidence produces `InvalidRevocationSignature` errors. Designated
  revokers are unsupported. A subkey revocation applies only to its signed subkey;
  unrelated subkeys are no longer reported revoked. Reasons come from verified
  signatures, and invalid evidence cannot erase a confirmed revocation warning.
- Genuine revocation and expiration remain warnings: `IsValid` means no validation
  errors, not permission to use an expired or revoked key. Callers must enforce their
  own trust, key-usage, freshness and acceptance policies. Expiration policy now
  requires authenticated current self-signatures as described below.
  Signing-subkey cross-certification and complete OpenPGP key-ring trust are not
  established by these checks.
- Preserve previously trusted revocation decisions during migration. Reissue legacy
  nonstandard revocation evidence through the trusted process described below;
  validation failure is not evidence that a previously revoked key is usable.

## OpenPGP expiration policy changes after v1.0.4

- `GetKeyLifetime()`, `GetExpirationTime()` and `IsExpiredAt()` now authenticate
  primary-key policy. Missing, ambiguous or unsupported evidence throws
  `InvalidOperationException`; `CheckExpiration()` reports `InvalidExpirationEvidence`
  instead. Do not catch this error and interpret it as an unlimited lifetime.
- Selection uses the newest authenticated self-signature for the actual signed
  object, ignoring signatures dated after the evaluation time or before key creation.
  Absent or zero key expiration in that selected signature means no expiration;
  an older expiration value is not a fallback. Equal-time conflicting signatures
  and an expired newest self-signature fail closed. Dates use encoded whole seconds.
- A current authenticated Direct Key self-signature supplies whole-key policy.
  V6 requires one; generation now includes it. Without a Direct Key policy, V4
  authenticated User ID policies must agree on expiration. Certification revocations
  and unsupported critical policy fields are rejected by this supported subset.
  This does not establish complete OpenPGP policy processing, key trust or protection
  against removal of newer signatures from imported key rings.
- Expiration updates now authenticate existing policy before copying key flags.
  Their creation timestamp must be strictly later, in encoded whole seconds, than
  the selected self-signature. An immediate update within the same second throws;
  use a later timestamp when that time has arrived. V6 and multiple-User-ID updates
  emit Direct Key signatures so the new expiration applies to the whole key.
- Preserve independently trusted keys, latest policy and revocation decisions.
  Historical V6 rings without a valid Direct Key signature need trusted regeneration
  or reissuance; the updater does not bootstrap unauthenticated policy. Validation
  failure is not evidence that an expired or revoked key has become usable.

## OpenPGP verification boundary changes after v1.0.4

- Successful verification now reports the actual verification key's raw fingerprint
  (without the subpacket's version byte) and key ID. Check trusted fingerprints
  independently; packet issuer claims cannot substitute for trust validation.
- Signature versions/algorithms and issuer hints must match the verification key.
  Weak/unsupported signature hashes, malformed or duplicate issuer/time fields,
  unsupported critical subpackets and noncanonical/trailing RSA signature data reject.
- Use dedicated verification methods for key/certification signatures. The document
  overload accepts only binary/text signatures. Inline messages require one literal
  packet and one signature in order, plus an optional matching one-pass packet.
  Multiple signatures, packet overwrites and unexpected critical packets reject.
- V6 signing keys automatically select V6 document signatures. Explicit V6 mode
  requires a V6 key; both configuration orders reject a V4 key. One-pass packets
  reuse the actual signature salt rather than generating a different salt.
- V6 salts now use RFC 9580 Table 23 lengths (16/24/32 bytes for SHA-256/384/512).
  Unknown or unsupported V6 hash IDs have no default salt size. Historical
  signatures using digest-sized salts are rejected by the verifier.
- These checks do not establish key trust, revocation, expiration or recipient-context
  policy. See [verification scope](../SECURITY.md#openpgp-signature-verification-scope).

## OpenPGP signature hash correction after v1.0.4

- Parsed signature subpackets now retain their original length encoding. Verification
  authenticates the received signed bytes rather than a normalized reconstruction.
  Changing a hashed subpacket's length form without re-signing is rejected; legitimate
  signatures over five-octet lengths are accepted. Rebuilding a parsed subpacket from
  semantic values can change its signed bytes and requires a new signature. Original
  wire encodings lost by earlier serialization cannot be recovered from the decoded
  values alone; retain originals or reissue signatures through a trusted process.
- V4 and V6 signatures now hash the complete signature header through hashed
  subpackets, followed by a six-byte trailer containing a four-byte header length.
  V6 key/certification signatures hash their salt first and use the V6 key-material
  prefix. This applies to document signing, certification, key generation, subkey
  binding, expiration updates, revocation and rotation.
- **Historical HeroCrypt signatures and key-ring certifications require migration.**
  Their nonstandard hashes are rejected. There is no automatic legacy retry.
  Preserve independently trusted keys and original data, then re-sign known trusted
  content and regenerate certifications/bindings using corrected APIs. For already
  revoked keys, preserve the revocation decision and reissue revocation evidence
  under the same trusted signing key. Do not treat historical signature acceptance
  as standards-based proof of authenticity or remove a revocation during migration.
- Canonical document signatures normalize CR, LF and CRLF to CRLF in both signing
  and verification. Trailing spaces/tabs are preserved and authenticated. Historical
  text signatures that trimmed whitespace must be reissued from trusted originals.
- Independent RFC constructions cover V4 RSA and V6 RSA/Ed25519 hashing; V4 RSA
  document signatures also cross-verify with Bouncy Castle. These checks cover the
  tested signature paths, not full OpenPGP interoperability or key-ring trust.

## Hybrid encryption hardening in v1.0.4

- RSA envelopes now require an explicit canonical `Algorithm` name (`AesGcm`,
  `ChaCha20Poly1305` or `XChaCha20Poly1305`), a 32-byte wrapped payload key, RSA
  keys of at least 2048 bits and exactly one correctly labelled SPKI/PKCS8 PEM block
  without trailing DER data. Invalid inputs previously accepted are now rejected.
  Valid generated envelopes retain their wire format. Recover malformed historical
  data only through a trusted migration process; do not guess algorithms from
  untrusted metadata or silently downgrade validation.
- X25519 rejects all-zero key agreement output and ignores the top input bit as
  required by RFC 7748. Normal generated keys/ciphertexts keep their derivation.
  Historical data created with a nonstandard high-bit public-key interpretation
  may no longer decrypt. Review such data using trusted key material; do not add
  a fallback to the incorrect interpretation. Low-order points are always rejected.
- .NET 10 now exposes the four ML-KEM operation suites that were accidentally
  excluded from compilation. Native platform support is still required. Imported
  ML-KEM keys must match the selected parameter set; `ImportPublicKey` now enforces
  its `level` argument (default 768). Pass 512/1024 explicitly when importing those
  primitive keys.
- None of these custom encryption compositions supplies sender authentication,
  replay protection or application context validation. `IsText` is untrusted metadata.
  See the [security model](../SECURITY.md#hybrid-encryption-security-model).
- X25519/ML-KEM operation suites now honor explicit `WithNonce` values and reject
  invalid nonce lengths. Remove testing-only deterministic mode from hybrid calls:
  it is now rejected, because randomized key contributions cannot provide the
  deterministic encryption behavior this option advertises.

## BIP39 wallet entry changes in v1.0.3

Earlier releases generated demonstration words such as `word0005` rather than the
official BIP39 English wordlist. Those phrases are not standard recovery phrases.
The corrected generator uses the official ordered 2048 words. **Generating a phrase
again from the same entropy can produce a different phrase and wallet.** Do not
translate placeholder words into their standard index equivalents and assume the
old wallet is preserved.

Preserve trusted existing seeds/private keys and verify the original wallet identity
before changing stored recovery material. `HdWalletBuilder.FromSeed` can use an
already recovered seed. For canonical ASCII placeholder phrases and ASCII
passphrases, raw `MnemonicToSeed` retains the same PBKDF2 input; it intentionally
does not validate a wordlist. It must not be treated as proof that such a phrase is
standard or valid. Historical Unicode passphrases or noncanonical text require
recovery using the original derivation rules or a trusted saved seed first.

`MnemonicToSeed` now follows the standard: NFKD normalization of mnemonic and
`"mnemonic" + passphrase`, PBKDF2-HMAC-SHA512 with 2048 iterations, 64-byte output.
It no longer lowercases or collapses raw mnemonic spaces. NFKD is not trimming,
case folding or password validation; a different passphrase still produces a valid
but different wallet. **Unicode or text normalization corrections can change the
seed for previously accepted inputs.**

`MnemonicToEntropy` now rejects invalid checksums, unknown English words and invalid
counts. `ValidateMnemonic` returns false for those inputs. The wallet builder checks
the same boundary and returns a canonical English phrase; accepted case, spacing
and NFKD-compatible English formatting are canonicalized before seed derivation.
Unknown words and legacy placeholder phrases reject instead of silently making a
wallet. Invalid-word errors no longer include the supplied recovery word.

English generation and validation are supported. Raw seed conversion can process
other Unicode mnemonic text, but this does not provide other language wordlists or
checksum validation. The standard's fixed 2048 iterations are an interoperability
requirement, not a recommendation for general password storage. Clear returned
seed/entropy arrays; managed mnemonic/passphrase strings cannot be reliably erased.

## BIP32 wallet boundary changes in v1.0.3

The corrected `Bip32HdWallet` parent fingerprint is the first four bytes of
RIPEMD160(SHA256(compressed public key)). Earlier fingerprints used double SHA-256
and are not standard BIP32 fingerprints. Recompute stored parent-fingerprint metadata
from trusted parent keys; the fingerprint correction does not change private key or
chain-code derivation. Fingerprints are identifiers with collisions, not authentication.

`ExtendedKey` now rejects invalid private scalars, malformed/off-curve public points,
non-four-byte fingerprints and nonzero root metadata. It owns copies of constructor
inputs, so `Clear` does not erase those input buffers; clear caller-owned originals
separately. Builder result seeds also own independent storage. Arrays remain mutable
and must not be changed concurrently with operations.

Builder source selection now follows the last call to `FromSeed`, `FromMnemonic`
or `GenerateMnemonic`. Null seed/mnemonic inputs and null, empty or whitespace paths
reject immediately instead of silently generating another wallet or returning the
master key. Use `WithPath("m")` to request the root explicitly.

Depth 255 cannot derive another child. Text paths require numeric components in
`0..2147483647`, with an apostrophe, `h` or `H` for hardening; whitespace, signs and
unmarked indices above this range reject. Replace raw high indices in paths with
their explicit hardened form, e.g. `2147483648` becomes `0'`. The raw `DeriveChild`
index API still accepts `uint` indices. Invalid derived scalars reject; retry the
next index and persist the actual chosen index rather than the originally requested one.

Private-parent derivation uses the portable secp256k1 core, including on macOS.
Public-parent child derivation remains unavailable and throws `NotSupportedException`.
xprv/xpub import/export is not implemented. Compliance policy now rejects the
secp256k1 wallet construction; earlier successful calls did not prove compliance.

Protect extended public material: combined with a non-hardened child private key it
can reveal the parent private key, as specified by BIP32. This audit provides no
managed-runtime constant-time, complete zeroization or module-certification guarantee.

## Shamir reconstruction changes in v1.0.3

Use `Reconstruct(shares, originalThreshold)` and
`Verify(shares, expectedSecret, originalThreshold)` with the threshold from trusted
split metadata. The legacy overloads only require two shares and cannot infer the
original threshold. Configure `SecretSharingBuilder.WithThreshold` explicitly when
recovering shares created with a threshold other than the default two.

Malformed, empty, duplicate-index, zero-index and mismatched-length shares now
reject before interpolation. A sufficient count does not establish authenticity
or that all shares belong to one session. Preserve trusted sharing-session metadata
and authenticate shares separately; this is not verifiable secret sharing.

## MPC security change in v1.0.2

`SecureMpc.SecureSum`, `SecureMultiply`, `PrivateSetIntersection`, and
`GenerateBeaverTriples` now throw `NotSupportedException`. The corresponding
configured `MpcBuilder` operations are also unsupported. No reviewed MPC or private
set intersection protocol is currently implemented. Security policies and models,
including `Malicious` and `Covert`, cannot enable these operations.

The former implementation gathered all parties' plaintext inputs or shares in one
process and did not authenticate participants or preprocessing material. Selecting
a security model did not enforce it. PSI was a local hash-based set comparison,
and multiplication accepted invalid thresholds and corrupted Beaver triples.
Unequal sum input lengths could silently discard trailing bytes.

Review applications that relied on these APIs for privacy or tamper detection.
Previously computed results do not prove that inputs remained private or that
participants and triples were authenticated. Independently revalidate results from
trusted inputs, and reassess any disclosure of party inputs to the executing process.
Use a reviewed distributed protocol with explicit participant and trust boundaries
before resuming MPC or PSI. Catching `NotSupportedException` and continuing with a
plaintext calculation does not restore those security guarantees.

## Threshold signature security change in v1.0.1

The threshold signature simulation has been removed. `ThresholdSignatures` and
configured `ThresholdSignatureBuilder` operations now throw `NotSupportedException`.
No secure threshold signing protocol is currently implemented.

Previously accepted threshold signatures were public hash values that anyone could
forge using only the public key and message. Do not use them as proof of approval
or authenticity. Re-establish approvals from an authoritative source and use a
reviewed signing protocol before accepting new signatures. Existing threshold
signature values cannot be converted into authentic signatures.

## Table of Contents

1. [Migrating to v1.0](#migrating-to-v10)
2. [New Text Encoding Methods](#new-text-encoding-methods)
3. [Fluent Builders Replace Services](#fluent-builders-replace-services)
4. [Deprecated and Removed](#deprecated-and-removed)
5. [Migrating from Other Libraries](#migrating-from-other-libraries)

---

## Migrating to v1.0

### Security: replace secp256k1 signatures from v0.1.0 through v0.3.0

HeroCrypt v0.1.0 through v0.3.0 produced a 64-byte value using a MAC key derived
from the public key instead of an ECDSA signature. Anyone with the public key
could forge that value. **Do not use signatures created by those versions as
proof of authenticity**, even if an older HeroCrypt verifier accepts them.

Version 1.0.0 signs with secp256k1 ECDSA and emits a 64-byte `r || s` signature
with a normalized low-S value. The unified builder hashes input data with
SHA-256 before signing or verifying it. The algorithm-specific
`Secp256k1Builder` accepts an already computed 32-byte message hash.

To migrate stored signatures:

1. Upgrade every signer and verifier to 1.0.0 before accepting new signatures.
2. Identify records signed with v0.1.0 through v0.3.0 using trusted version or
   creation metadata. Both formats are 64 bytes, so length cannot identify the
   old values.
3. Re-establish each original message from an authoritative source and sign it
   again with the private key. Do not automatically re-sign a message merely
   because its old signature verifies.
4. Replace the stored signature and record the new signature format or version.
   If the message cannot be authenticated independently, invalidate the old
   signature and request a new signed record.
5. Review any authorization decisions that relied solely on old signatures.

There is no safe conversion from an old signature to ECDSA. This flaw did not
expose the private key, so a key change alone cannot repair previously trusted
records.

```csharp
using var signer = HeroCryptBuilder.Sign()
    .WithSecp256k1()
    .WithPrivateKey(privateKey);
byte[] signature = signer.Sign(authenticatedMessage);

using var verifier = HeroCryptBuilder.Verify()
    .WithSecp256k1()
    .WithPublicKey(publicKey)
    .WithSignature(signature);
bool isValid = verifier.Verify(authenticatedMessage);
```

### Breaking Changes

- **Dropped .NET 6.0 and .NET 7.0 support** - Now requires .NET 8.0+ or .NET Standard 2.0
- Service layer removed - use fluent builders directly
- Interface abstractions removed - builders are the public surface

### Updated Method Names

Some builder methods have been renamed for consistency:

| Old Method | New Method |
|------------|------------|
| `UseArgon2()` | `WithArgon2id()` |
| `WithKeyLength(n)` | `WithOutputLength(n)` |
| `Build()` | `DeriveKey()` |

---

## New Text Encoding Methods

HeroCrypt now includes convenient text encoding methods on all operation builders. This eliminates manual `Convert.ToBase64String()` and `Convert.FromBase64String()` calls.

### Before (Manual Conversion)

```csharp
// Old approach - manual encoding
var hash = kdf.DeriveKey();
var hashBase64 = Convert.ToBase64String(hash);  // Manual

var storedSalt = Convert.FromBase64String(saltBase64);  // Manual
kdf.WithSalt(storedSalt);
```

### After (Built-in Encoding)

```csharp
// New approach - fluent encoding methods
var hashBase64 = kdf.DeriveKeyToBase64();  // Direct

kdf.WithSaltFromBase64(saltBase64);  // Direct
```

### Available Encoding Methods

| Builder | Output Methods | Input Methods |
|---------|----------------|---------------|
| EncryptionBuilder | `GetKeyAsHex/Base64/Base64Url()` | `WithKeyFromHex/Base64/Base64Url()` |
| DecryptionBuilder | `DecryptFromHex/Base64/Base64Url()` | `WithKeyFromHex/Base64/Base64Url()`, `WithNonceFromHex/Base64/Base64Url()` |
| HashBuilder | `ComputeHashToHex/Base64/Base64Url()` | `WithKeyFromHex/Base64/Base64Url()` |
| SignatureBuilder | `SignToHex/Base64/Base64Url()` | `WithKeyFromHex/Base64/Base64Url()` |
| VerificationBuilder | - | `WithKeyFromHex/Base64/Base64Url()`, `WithSignatureFromHex/Base64/Base64Url()` |
| KeyDerivationBuilder | `DeriveKeyToHex/Base64/Base64Url()`, `GetSaltAsHex/Base64/Base64Url()` | `WithSaltFromHex/Base64/Base64Url()` |

### Result Struct Properties

Encryption results have text encoding properties:

```csharp
var result = encryptor.Encrypt(plaintext);

// Text properties (no method call needed)
string ciphertextHex = result.CiphertextAsHex;
string nonceBase64 = result.NonceAsBase64;
string nonceBase64Url = result.NonceAsBase64Url;
```

### Choosing the Right Format

| Format | Use When |
|--------|----------|
| **Hex** | Logging, debugging, config files, human readability |
| **Base64** | Database storage, JSON payloads, file storage |
| **Base64Url** | URLs, query parameters, JWTs, HTTP headers, APIs |

---

## Fluent Builders Replace Services

The service layer has been removed. Use the fluent builders directly:

### Password Hashing (Argon2id)

```csharp
// New approach with fluent builders
using var kdf = HeroCryptBuilder.DeriveKey()
    .WithArgon2id()
    .WithPassword("password")
    .WithRandomSalt()
    .WithOutputLength(32);

var hashHex = kdf.DeriveKeyToHex();
var saltHex = kdf.GetSaltAsHex();
```

### Encryption (ChaCha20-Poly1305)

```csharp
using var encryptor = HeroCryptBuilder.Encrypt()
    .WithChaCha20Poly1305()
    .WithRandomKey();

var result = encryptor.Encrypt("secret data");
var keyBase64 = encryptor.GetKeyAsBase64();
var ciphertextBase64 = result.CiphertextAsBase64;
var nonceBase64 = result.NonceAsBase64;
```

### Hashing (SHA-256)

```csharp
using var hasher = HeroCryptBuilder.Hash()
    .WithSha256();

var hashHex = hasher.ComputeHashToHex("data to hash");
```

---

## Deprecated and Removed

### Removed Classes

- All `*Service` classes: `AeadService`, `Argon2HashingService`, `KeyDerivationService`, `RsaService`, `PgpService`, etc.
- Interface abstractions: `IAeadService`, `IHashingService`, etc.

### Replacement Mapping

| Removed | Replacement |
|---------|-------------|
| `Argon2HashingService.Hash()` | `HeroCryptBuilder.DeriveKey().WithArgon2id()` |
| `AeadService.Encrypt()` | `HeroCryptBuilder.Encrypt().WithAesGcm()` |
| `KeyDerivationService.DeriveKey()` | `HeroCryptBuilder.DeriveKey().WithHkdfSha256()` |
| `RsaService.Sign()` | `HeroCryptBuilder.Sign().WithRsaPssSha256()` |

---

## Migrating from Other Libraries

### From System.Security.Cryptography

```csharp
// Before: Manual HMAC-SHA256
using var hmac = new HMACSHA256(key);
var hash = hmac.ComputeHash(data);
var hashBase64 = Convert.ToBase64String(hash);

// After: HeroCrypt fluent API
using var hasher = HeroCryptBuilder.Hash()
    .WithSha256()
    .WithKey(key);
var hashBase64 = hasher.ComputeHashToBase64(data);
```

### From Libsodium / NaCl

```csharp
// HeroCrypt ChaCha20-Poly1305 is compatible with libsodium
using var encryptor = HeroCryptBuilder.Encrypt()
    .WithChaCha20Poly1305()
    .WithKey(key);
var result = encryptor.Encrypt(plaintext);
```

### From BouncyCastle

```csharp
// Argon2 with same parameters as BouncyCastle
using var kdf = HeroCryptBuilder.DeriveKey()
    .WithArgon2id()
    .WithPassword(password)
    .WithSalt(salt)
    .WithOutputLength(32);
// Note: Default parameters are 3 iterations, 64MB memory, 4 parallelism
```

---

## Dependency Injection

There are no service types to register. If you need DI, wrap the builders in your own service classes:

```csharp
public interface ICryptoService
{
    string HashPassword(string password);
    bool VerifyPassword(string password, string hash, string salt);
}

public class CryptoService : ICryptoService
{
    public string HashPassword(string password)
    {
        using var kdf = HeroCryptBuilder.DeriveKey()
            .WithArgon2id()
            .WithPassword(password)
            .WithRandomSalt()
            .WithOutputLength(32);
        return $"{kdf.GetSaltAsHex()}:{kdf.DeriveKeyToHex()}";
    }

    public bool VerifyPassword(string password, string hash, string salt)
    {
        using var kdf = HeroCryptBuilder.DeriveKey()
            .WithArgon2id()
            .WithPassword(password)
            .WithSaltFromHex(salt)
            .WithOutputLength(32);
        return kdf.DeriveKeyToHex() == hash;
    }
}
```

---

## Additional Resources

- [Getting Started](getting-started.md) - Quick start guide
- [API Patterns](api-patterns.md#text-encoding-conventions) - Text encoding naming conventions
- [Best Practices](best-practices.md) - Security recommendations
- [Troubleshooting](troubleshooting.md#text-encoding-issues) - Common encoding issues
