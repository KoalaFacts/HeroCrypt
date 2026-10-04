# Production Readiness Guide

HeroCrypt releases are qualified by API and deployment profile. A passing test
suite or a release number does not certify every algorithm, protocol composition
or application. No completed independent professional security audit or FIPS 140
validation is claimed.

Read [SECURITY.md](SECURITY.md) and the [migration guide](docs/migration-guide.md)
before upgrading. Security patches can intentionally reject previously accepted
keys, signatures or ciphertext. Pin the tested package version in production.

## Release qualification

The release process must establish these gates for the exact source commit:

- Release builds and tests on Windows, Linux and macOS for .NET 8, 9 and 10;
  compile the .NET Standard 2.0 library as well
- Standards-vector, independent-implementation and tamper/negative regressions
  for the supported cryptographic paths
- Dependency vulnerability checks, warnings-as-errors and formatting checks
- Package identity, source commit, target-framework contents, license and notices
- Package consumer smoke tests and repeated-build payload comparisons on Ubuntu
  and Windows for .NET 8/9/10
- An immutable new version, prepared migration notes and a verified publication

These are engineering release gates, not evidence that every execution path,
side channel or downstream application has been audited. See the linked workflow
results for each release; do not use an earlier commit's green checks as evidence.

## OpenPGP profile

OpenPGP support is a subset of RFC 9580. Applications must choose and test a
specific profile rather than infer interoperability from the library name.

| Path | Supported scope | Important limit |
|------|-----------------|-----------------|
| Signatures | Supported v4/v6 RSA and Ed25519 paths, RFC framing and salted v6 hashing | Trust in the actual signing key remains application policy |
| Ring encryption recipients | Current authenticated encryption flags, exact bindings, expiration and revocation | Caller authenticates primary identity and metadata freshness |
| Ring signature verification | Authenticated current Sign flags, exact subkey bindings and signing cross-certification; expiration/revocation checks | Metadata freshness, stripped evidence and historical acceptance require application policy |
| Encrypted envelopes | RSA/X25519 and AES session wrapping; SEIPD v1 and AES-GCM SEIPD v2 | ECDH v6 sessions and OpenPGP EAX/OCB are unsupported; see RSA decryption exposure limit below |
| SEIPD v2 | .NET 8/9/10 AES-GCM with authenticated chunks and final length tag | .NET Standard 2.0 throws; general AES-OCB primitive availability does not enable OpenPGP OCB |
| Message encryption/decryption | Literal-data payloads with integrity validation | Decryption does not verify an embedded sender signature or authenticate sender identity |
| Integrated signed-and-encrypted messages | No high-level combined API | Encrypting serialized signed-message bytes creates a nested literal payload, not a standard integrated packet stream |
| Key preferences | Authenticated preference getters and object association | Getters do not negotiate ciphers or establish external identity trust |

### RSA decryption exposure limit

RSA PKCS#1 v1.5 session unwrapping is retained for interoperable local/offline or
otherwise trusted-input use. Its native-provider and complete candidate-processing
timing has not been qualified against remote decryption oracles. Do not expose it
as an unauthenticated remotely observable decryption endpoint. Uniform public error
messages are not proof of constant-time decryption or implicit rejection. See
[RFC 9580 section 13.5](https://www.rfc-editor.org/rfc/rfc9580.html#section-13.5).

### Interoperability evidence

The repository includes RFC 9580 Appendix A.11 passphrase/GCM fixtures,
independently constructed RSA/X25519 envelope checks, independently computed v4/v6
signature framing, and v4 RSA signature/message interoperability with Bouncy Castle. These fixtures
are test data, not operational keys.

This evidence does not establish complete v6 signed-and-encrypted interoperability
with OpenPGP.js, GnuPG or every RFC 9580 implementation. Such a deployment needs
pinned-version, bidirectional integration tests for its complete wire profile.

Relevant regression suites include:

- `PgpEnvelopeInteropSecurityTests`
- `PgpSignatureInteroperabilityTests`
- `PgpAeadIntegritySecurityTests`
- `PgpSigningKeyPolicySecurityTests`
- `PgpEncryptionKeyPolicySecurityTests`
- `PgpMessageInteroperabilityTests`
- `PgpDecryptionFailureSecurityTests`

Before using a received public ring, authenticate its primary-key identity through
an independent trusted channel. Preserve known revocations and enforce metadata
freshness. A mathematically valid key is not necessarily an authorized recipient.

## Primitive and platform scope

| Category | Implementation scope | Deployment requirement |
|----------|----------------------|------------------------|
| Hashes and KDFs | SHA family, Blake2b, Argon2, PBKDF2, HKDF and Scrypt | Use the intended variant and resource limits; review standards-vector coverage |
| AEAD | AES and ChaCha-family implementations and platform backends | Unique nonces where required; verify associated context and handle authentication failure |
| Ed25519/X25519 | Managed implementations with test vectors | No blanket constant-time or independent-audit certification |
| RSA/ECDSA | Runtime cryptography; secp256k1 uses Bouncy Castle | Validate runtime support, key sizes, usage and provider behavior |
| ML-KEM/ML-DSA/SLH-DSA | .NET 10 native APIs, platform dependent | Probe support at runtime; a standardized primitive is not an audited application protocol |
| BIP39/BIP32 | Official English mnemonic list; checksum validation; private-parent HD derivation | No public-parent derivation or xprv/xpub import/export; review historical recovery guidance |
| Shamir sharing | Trusted-dealer confidentiality primitive | Authenticate shares and session metadata separately; enforce the original threshold |

.NET Standard 2.0 compatibility does not guarantee that all APIs work on every
.NET Standard consumer. Native and newer-runtime features may throw. The .NET
8/9/10 test matrix does not execute a .NET Framework consumer or every provider.

## Custom encryption compositions

RSA-OAEP + AEAD envelopes, X25519 + AEAD and ML-KEM + AEAD operations are custom
compositions. X25519 suites are not HPKE, and ML-KEM suites do not combine classical
and post-quantum key agreement. They provide no sender authentication or replay
prevention. Applications must independently validate expected associated context,
sender identity and freshness. See the [security model](SECURITY.md#hybrid-encryption-security-model).

## Educational disabled and external features

- Noise, Signal, OTR, OPAQUE, commitments and blind-signature demonstrations are
  educational/reference implementations and are not qualified production protocols
- Threshold signatures, MPC sum/multiplication, private set intersection and Beaver
  triple generation remain disabled; policy changes cannot enable them
- Ring signatures and zk-SNARKs are not implemented
- HSM, Key Vault, TPM, TEE and enterprise compliance abstractions need external
  implementations and their own security review; API names do not confer certification

Do not protect real user secrets with educational or disabled features. A future
production protocol implementation requires its own threat model, design review,
interop and negative tests, and independent security review.

## Upgrade and rollback

Keep a protected backup and test migrations against representative data before
changing a production dependency. Do not overwrite an existing package or release
tag. A corrective release uses a new version.

A rollback to an older vulnerable package can reintroduce forgery, policy bypass
or confidentiality defects. Prefer disabling the affected feature while preparing
a corrected release. Historical nonstandard ciphertext or signatures need the
trusted recovery process in the migration guide; do not add automatic insecure
fallbacks or silently relabel old data.
