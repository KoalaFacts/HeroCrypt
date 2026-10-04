# Security Policy

## 🔒 Security Commitment

HeroCrypt is a cryptographic library where security is paramount. We take all security vulnerabilities seriously and appreciate the efforts of security researchers and the community in responsibly disclosing issues.

## 📢 Reporting a Vulnerability

You can report security vulnerabilities through these channels:

1. **GitHub Security Advisories** (Recommended): Use the "Report a vulnerability" button in the Security tab
2. **Public issues**: Use only for already disclosed issues or non-sensitive security questions. Do not post undisclosed vulnerability details or operational secrets publicly.

Please include the following information in your report:

- **Type of vulnerability** (e.g., buffer overflow, timing attack, incorrect implementation)
- **Full path of source file(s)** related to the vulnerability
- **Location of the affected source code** (tag/branch/commit or direct URL)
- **Step-by-step instructions** to reproduce the issue
- **Proof-of-concept or exploit code** (if possible)
- **Impact of the issue**, including how an attacker might exploit it
- **Your assessment** of the severity (Critical, High, Medium, Low)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within 48 hours.
- **Updates**: We will provide regular updates on the progress of addressing the vulnerability.
- **Timeline**: We aim to release a fix within 90 days of disclosure, though critical issues will be prioritized.
- **Credit**: With your permission, we will publicly credit you for the discovery once the fix is released.

## 🛡️ Supported Versions

We provide security updates for the following versions:

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 1.0.x   | :white_check_mark: | Active support |
| < 1.0   | :x:                | Not supported |

**Note**: Security fixes will be backported to the latest minor version of supported major versions.

## 🔐 Security Best Practices

### Hybrid encryption security model

- `HybridEncryptionBuilder` wraps a fresh 32-byte AEAD key with RSA-OAEP-SHA256.
  Imported keys must be at least 2048 bits and use one SPKI `PUBLIC KEY` or PKCS8
  `PRIVATE KEY` PEM block. The envelope requires the exact algorithm name
  `AesGcm`, `ChaCha20Poly1305` or `XChaCha20Poly1305`; missing/unknown names are rejected.
- X25519 operation suites use an ephemeral sender key, reject all-zero agreement
  output and derive 32 bytes with HKDF-SHA256, empty salt and the fixed info string
  `X25519-Hybrid-Encryption`. This custom derivation does not bind public keys or
  suite identifiers into the KDF. These suites are not HPKE, TLS, Noise or libsodium
  sealed boxes. No authenticated key exchange or public-key identity binding is claimed.
- .NET 10 ML-KEM operation suites require native `MLKem.IsSupported` and enforce
  the selected 768/1024 parameter set for both public and private keys. They combine
  ML-KEM with AEAD, not a classical-plus-post-quantum KEM combiner. The primitive's
  one-argument encapsulation API continues to support all three ML-KEM parameter sets.
- AEAD verifies ciphertext, nonce and supplied associated data. Anyone with a
  recipient public key can create a valid encrypted message: these APIs do not
  authenticate sender identity, provide signatures, freshness or replay prevention.
  Recipients must compare authenticated associated data with an independently
  expected context and implement any required replay/sender checks separately.
  The RSA envelope's `IsText` flag is not authenticated.
- X25519/ML-KEM operation suites honor `WithNonce`; without an explicit nonce they
  generate one randomly. Deterministic mode is rejected even under testing policy,
  because ephemeral key generation and KEM encapsulation remain randomized.
- Owned temporary payload keys, private DER and plaintext byte buffers are cleared,
  and internal symmetric builders are disposed. Caller-owned arrays are preserved.
  Immutable private-key/plaintext strings and managed-runtime copies cannot be
  reliably erased. Algorithm policy checks do not establish FIPS module certification.

See [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748),
[RFC 9180](https://www.rfc-editor.org/rfc/rfc9180),
[FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) and
[.NET native cryptography support](https://learn.microsoft.com/en-us/dotnet/standard/security/cross-platform-cryptography).

When using HeroCrypt, please follow these security best practices:

### OpenPGP encryption and decryption scope

`AddRecipient(PgpPublicKeyRing)` retains a packet snapshot and selects a supported
recipient at encryption time using current authenticated encryption flags, exact
bindings, expiration and revocation checks. The primary key requires authenticated
current policy; a subkey requires its own primary-key binding. Adding the same key
through the raw packet overload cannot bypass a configured ring's policy. The raw
packet-only overload leaves identity and usage authorization to the caller.
Applications must still authenticate primary-key identity, preserve known revocations
and enforce freshness of externally supplied key metadata.

High-level message encryption supports AES-128/192/256 and GCM for SEIPD v2. Other
high-level data ciphers fail before producing mislabeled ciphertext. Decryption
returns authenticated literal bytes, not proof of sender identity; it is not a
combined signed-and-encrypted verifier. See [production scope](PRODUCTION_READINESS.md).

Session-key and integrity failures use a generic public error. SEIPD v1 verifies
its full MDC before reporting framing failure, and rejected temporary plaintext is
cleared. This does not establish constant-time RSA PKCS#1 v1.5 implicit rejection
across native providers. Do not expose that path as an unauthenticated remotely
observable decryption service. Review [RFC 9580 section 13.5](https://www.rfc-editor.org/rfc/rfc9580.html#section-13.5)
and the deployment-specific threat model.

### OpenPGP signature verification scope

The verifier checks cryptographic signatures under explicitly supplied keys. A valid
result reports the actual verification key's raw fingerprint and key ID; packet
issuer hints are not trusted identity evidence. Applications must establish trust
in that key independently. `WithPublicKey` alone performs cryptographic verification.
`WithPublicKeyRing` additionally requires current authenticated hashed Sign permission,
primary-key expiration/revocation checks and, for a signing subkey, a current exact
primary-key binding and independently verified embedded type-0x19 cross-certification.
Subkey expiration and revocation are checked against its exact signed target.
Adding the same key separately cannot bypass its configured ring policy. Results
identify the actual signing key, not a trusted primary-key identity.

`PgpKeyValidator.VerifySubkeyBindings()` requires an authenticated primary-key
binding for each supplied subkey, selecting current evidence at `AtTime` (or now).
Signing-only subkeys, signing-capable subkeys with Sign permission and those without
authenticated usage require cross-certification; explicit non-signing usage on an
encryption-capable subkey does not. `ValidateStructureOnly()` remains a presence check.
`CheckRevocation()` authenticates primary-key revocations and the exact target of
subkey revocations. Unsupported designated-revoker evidence fails validation.
Confirmed revocation remains a warning, so `IsValid` alone is not an acceptance
policy. Public and secret key-ring revocation status/reason getters also authenticate
primary-key self-revocations, and throw for invalid-only or unsupported evidence.
Genuine evidence is retained alongside invalid packets. Only authenticated hashed
reason fields affect the result; compromise dominates soft reasons, and ambiguous
or unsupported reasons are conservative. Candidate enumeration remains unverified.
These checks do not establish revocation effective times, historical signature
acceptance, freshness or detect stripped evidence. See the
[revocation migration notes](docs/migration-guide.md#openpgp-revocation-status-changes-after-v104).
The validator does not establish document acceptance, freshness or trust.
`CheckExpiration()` authenticates primary-key expiration
policy and reports `InvalidExpirationEvidence` when no supported unambiguous current
policy can be established. Expiration getters likewise throw instead of reporting
an unlimited lifetime without authenticated evidence.

Expiration selection uses the newest authenticated non-future self-signature for
each signed object. V6 requires a Direct Key self-signature. An authenticated Direct
Key policy takes precedence; otherwise V4 User ID policies must agree. Missing or
zero expiration in the selected signature means no expiration. Conflicting equal-time
signatures, an expired newest self-signature, certification revocations and unsupported
critical policy fields fail closed. This supported subset does not establish complete
OpenPGP policy handling or detect deletion of newer signatures from an imported ring.
Preserve independently trusted current policy and revocation decisions. See
[expiration migration](docs/migration-guide.md#openpgp-expiration-policy-changes-after-v104).

Signing policy uses the same current primary-policy selection as preferences and
the newest authenticated non-future binding for the exact subkey. Removed permission,
an expired newest binding or ambiguous equal-time policy never falls back to an older
binding. Only hashed Key Flags authorize usage; duplicate fields and unknown bits
are rejected. Invalid unhashed hints cannot hide authentic newer policy to restore
older permission; selected unsupported metadata fails closed. Zero extension octets
are supported. Exactly one embedded back signature
is accepted across the hashed and unhashed sections; either location requires its
own authentication and current creation/expiration checks. Critical policy fields
beyond the supported creation/issuer subset remain rejected. Ring verification
evaluates current supplied key evidence, not historical document acceptance or
document-signature expiration. See
[signing-policy migration](docs/migration-guide.md#openpgp-signing-key-policy-after-v104).

Algorithm preference getters authenticate current Direct Key or V4 User ID policy.
V6 requires Direct Key policy; conflicting V4 User ID preferences without an
authenticated primary marker fail closed. Missing authenticated policy throws;
missing fields in selected authenticated policy return null. Advertised IDs do not
perform algorithm negotiation or establish implementation support. Primary User ID
selection authenticates current self-certifications and Boolean markers.

User ID and subkey signature queries authenticate supported self-signatures over
the exact object. Raw third-party and unsupported signatures remain available.
Export retains each signature occurrence once, preferring cryptographic association
over imported position. Unverified imported layout is retained only for serialization,
including User Attribute signatures; it is not evidence of a valid certification.
Reserved legacy AEAD preference type 34 requires trusted re-signing with RFC type 39.
See [preference migration](docs/migration-guide.md#openpgp-preferences-and-object-association-after-v104).

Document verification accepts only binary/text document signature types. Key and
certification signatures use their dedicated methods. Unsupported critical semantics,
including critical notation and recipient-context constraints, are rejected. Only
critical creation-time and issuer fields are understood here. Non-critical expiry,
trust and application-context fields do not establish policy acceptance; callers must
evaluate them separately. Literal filenames, dates and formats are unsigned metadata.

The inline message API supports one signature and one literal-data packet, with an
optional matching one-pass packet. Ambiguous/multiple-signature streams and unexpected
critical packets are rejected rather than reduced to a selected signature.

Signature hashing uses RFC 9580 section 5.2.4: complete V4/V6 headers, six-byte
trailers, signature-version-specific key prefixes, and V6 salt before all signed
material. Independent RFC byte construction and Bouncy Castle V4 RSA cross-verification
cover the tested signature paths. This does not establish complete OpenPGP conformance
or key-ring trust. Historical HeroCrypt signatures used nonstandard framing and
require trusted re-signing/certification; no legacy verification fallback is provided.
See [migration guidance](docs/migration-guide.md#openpgp-signature-hash-correction-after-v104).

### 1. **Use Recommended Algorithms**
- **Password Hashing**: Use Argon2id (default) for password hashing
- **Encryption**: Use ChaCha20-Poly1305 or AES-GCM for AEAD
- **Signatures**: Use Ed25519 for digital signatures
- **Key Exchange**: Use X25519 for Diffie-Hellman key exchange
- **Hashing**: Use Blake2b or SHA-256/SHA-512 for general hashing

### 2. **Avoid Deprecated/Weak Algorithms**
- ❌ **Never use RC4** – removed from the library due to insecurity
- ⚠️ **Use caution with RSA** - Ensure key sizes ≥ 2048 bits, prefer 3072 or 4096 bits
- ⚠️ **Post-Quantum algorithms** - Current implementations are reference/educational only

### 3. **Key Management**
- **Never hardcode keys** in source code
- **Use secure key storage** (OS key stores, HSM, or encrypted at rest)
- **Rotate keys regularly** according to your security policy
- **Use appropriate key sizes**:
  - AES: 256-bit keys
  - RSA: ≥ 2048 bits (prefer 3072+)
  - ECC: 256-bit curves (Curve25519, secp256k1)
  - Argon2: Follow OWASP recommendations

### 4. **Random Number Generation**
- HeroCrypt uses `System.Security.Cryptography.RandomNumberGenerator`
- **Never** use `System.Random` for cryptographic operations
- Ensure your system has sufficient entropy

### 5. **Memory Security**
- HeroCrypt uses secure memory management for sensitive data
- Keys and secrets are zeroed after use
- Consider using `SecureString` for user-entered secrets where appropriate

### 6. **Side-Channel Attacks**
- HeroCrypt implements constant-time operations for critical paths
- Be aware of timing attacks when implementing custom logic
- Avoid branching on secret data

### 7. **Input Validation**
- Always validate and sanitize inputs before cryptographic operations
- Check key lengths and parameter ranges
- Validate ciphertext authenticity before decryption (use AEAD)

### 8. **Configuration**
- Use secure defaults (don't lower security parameters without good reason)
- For Argon2: Use at least the minimum recommended parameters
- For AES-GCM: Never reuse nonces with the same key
- For ChaCha20-Poly1305: Use random or counter-based nonces

## 🚨 Known Limitations & Warnings

### Platform-dependent and unqualified features

- **Post-quantum cryptography**: ML-KEM, ML-DSA and SLH-DSA use .NET 10 native
  cryptography APIs. Availability depends on the runtime and provider; probe support
  and test your deployment. A standardized primitive does not certify a composition.
- **Educational protocols**: Noise, Signal, OTR, OPAQUE, commitment and blind-signature
  reference implementations are not qualified production protocols.
- **Unavailable protocols**: Ring signatures and zk-SNARKs are not implemented.
  Their insecure prototypes were removed before the first release.
- **Disabled operations**: Threshold signatures throw `NotSupportedException` since
  1.0.1; MPC sum, multiplication, private set intersection and Beaver generation
  are disabled since 1.0.2. See the [migration guide](docs/migration-guide.md).

Future production protocol work requires a complete threat model, sound construction,
negative and interoperability tests, side-channel review and independent security
review. Changing a policy option cannot enable disabled functionality.

### Algorithm-Specific Warnings

- **RC4**: Removed; known vulnerabilities make it unsafe
- **AES-OCB**: Patent restrictions may apply for commercial use
- **Shamir's Secret Sharing**: GF(256) confidentiality with a trusted dealer; enforce the
  original threshold and authenticate shares and sharing-session metadata separately.
- **BIP39 Mnemonics**: The official English wordlist and checksum validation are present. Review the v1.0.3 migration guidance before using historical placeholder phrases.

## 🔍 Security Audits

### BIP39 wallet entry audit - 2026-09-30

Before product changes, 68 audit regressions produced 42 failures and 26 passes.
A separate run confirmed all 24 official English seed vectors already matched:
PBKDF2-HMAC-SHA512/2048 and 64-byte output were correct. Findings included the
demonstration placeholder wordlist, missing NFKD, unwanted raw text canonicalization,
unchecked entropy-decoder checksums, invalid wallet inputs and signed size overflow.

The corrected implementation embeds the official English list, uses NFKD-only raw
seed conversion, checks checksum in the shared entropy decoder and validates and
canonicalizes English wallet-builder input. Temporary entropy, bit, hash and UTF-8
buffers clear on normal/exceptional paths. Instance policy is passed to PBKDF2 and
checksum validation. Source review establishes those cleanup paths, without a
runtime-wide erasure or constant-time guarantee; strings remain managed secrets.

Old placeholder phrases are nonstandard. Replacing their words or correcting
historical Unicode/text processing can change the wallet. Preserve trusted existing
seed/private material and verify the original wallet identity before migration.
Raw text conversion does not validate recovery words or detect a wrong passphrase.
English checksum support does not imply other language wordlists, authentication
or compliance/module certification. See [Issue #131](https://github.com/KoalaFacts/HeroCrypt/issues/131),
the [BIP39 standard](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
and [migration guidance](docs/migration-guide.md#bip39-wallet-entry-changes-in-v103).

### BIP32 wallet boundary audit - 2026-09-30

Before product changes, 43 audit cases produced 38 failures and five passes. The
17 nodes in official BIP32 vectors 1-4 checked private/public keys, chain codes,
fingerprints, depth and child indices. Four master nodes passed; 13 child nodes
matched private keys and chain codes but failed parent fingerprints, which incorrectly
used double SHA-256. An independent integer reference confirmed scalar addition at
carry and reduction boundaries. Other failures covered invalid keys/metadata, depth
wrapping, ambiguous paths, ignored Compliance policy and caller-buffer aliasing.

A second builder audit added eight cases, seven of which failed before its fix:
null sources silently selected random generation, null/blank paths selected the
master key, and seed configuration took precedence over later mnemonic selection.
Source selection now follows the last setter, and invalid configuration rejects.

The corrected implementation computes HASH160 fingerprints, uses the portable
secp256k1 core, enforces instance policy, validates imported and mutable key material,
and rejects depth overflow and ambiguous path components. Owned temporary key/seed
buffers and intermediates clear on normal and exceptional paths; returned buffers
remain the caller's responsibility. This does not guarantee runtime-wide zeroization
or constant-time execution. Public-parent derivation and xprv/xpub import/export are
explicitly unsupported, rather than advertised as a complete BIP32 wallet.

An additional regression demonstrates the standard's non-hardened exposure boundary:
parent extended public material plus a non-hardened child private key can recover
the parent private key. Fingerprints identify keys but do not authenticate ancestry.
See [Issue #129](https://github.com/KoalaFacts/HeroCrypt/issues/129), the
[BIP32 specification](docs/CRYPTO_SPEC.md#81-bip32-hd-wallets), and the
[migration guidance](docs/migration-guide.md#bip32-wallet-boundary-changes-in-v103).

### Shamir share boundary audit - 2026-09-30

On the audited baseline, 14 of 21 new regression cases failed: uninitialized shares
caused null dereferences, empty shares could verify an empty secret, and builder
reconstruction and verification ignored the configured threshold. The seven passing
cases checked all 65,536 GF(256) multiplication pairs against independent polynomial
reduction, published FIPS 197 vectors, reordered/high indices, the maximum threshold,
and the absence of share provenance authentication under all security policy levels.

The corrected implementation validates shares before interpolation and the builder
enforces its configured threshold (default 2). The core overloads accepting `threshold`
enforce a trusted caller-supplied minimum. Raw shares do not encode their original
threshold; the overloads without `threshold` only require two shares and cannot detect
an undersized subset from a higher-threshold split.

Shamir is a trusted-dealer confidentiality primitive, not verifiable secret sharing.
`Verify` compares the reconstructed value with an expected secret; a match does not
authenticate participants, provenance, or membership in one sharing session. Tampered
or mixed shares can produce arbitrary values, including the expected value. Applications
must authenticate shares and bind the threshold, indices and session identity in trusted
metadata outside this API. `SecurityPolicyOptions` is reserved here and does not add
authentication, enforce algorithm restrictions, or provide compliance certification.

GF multiplication now uses fixed-round mask operations without secret-dependent source
branches. Arithmetic regressions do not establish constant-time behavior of the JIT or
runtime, and this API makes no such guarantee. Uniform coefficient sampling includes
zero: coincident share values are valid, and rejecting them would change the distribution.

See [Issue #127](https://github.com/KoalaFacts/HeroCrypt/issues/127) and the
[Shamir specification](docs/CRYPTO_SPEC.md#83-shamirs-secret-sharing) for scope and usage.

### MPC protocol boundary audit - 2026-09-30

The MPC API through 1.0.1 was a local simulation: one caller provided all plaintext
inputs or all shares. It had no authenticated participant communication or malicious
participant checks. `SecureSum` and `PrivateSetIntersection` ignored `SecurityModel`,
including `Malicious` and `Covert`; PSI performed ordinary local SHA-256 matching.
`SecureMultiply` ignored its threshold and consumed unauthenticated Beaver triples.
Triple generation and reconstruction used the global policy instead of the instance policy.

Package metadata inspection of all six public versions (0.1.0, 0.1.2, 0.2.0,
0.3.0, 1.0.0, and 1.0.1) confirmed that all four operations are exposed by
each .NET 8, 9, and 10 asset. The .NET Standard 2.0 assets do not expose MPC.

Regression tests against the former implementation reproduced successful execution
for unsupported security models, unequal input lengths that silently truncated the
sum, invalid multiplication thresholds, and a corrupted Beaver triple. The previous
product test with no result assertion was replaced by rejection coverage.

In 1.0.2 all four core operations throw `NotSupportedException` before processing
inputs or generating preprocessing material. Configured builder operations delegate
to the same rejection; missing builder configuration still reports a configuration
error. Changing security models or policies cannot enable MPC. Shamir secret sharing
remains a separate primitive and does not establish an authenticated MPC protocol.

See the [migration guide](docs/migration-guide.md#mpc-security-change-in-v102) for
reviewing uses of previous computation results and replacing protocol assumptions.

### Ring signature and zk-SNARK verification audit - 2026-09-30

**Current scope:** Ring signatures and Groth16 zk-SNARKs have no implementation,
builder entry point, or verification path in the current source. They were removed
by commit [f029b3c](https://github.com/KoalaFacts/HeroCrypt/commit/f029b3cc3813e55ca9c31961b20b9371db87a3f3)
on 2025-10-28, before the first release tag.

The original source immediately before removal was compiled and exercised:

| Historical path | Reproduced failure | Cause |
|-----------------|--------------------|-------|
| `RingSignature.Verify` (basic, linkable, traceable) | Accepted a signature constructed from public data with one-byte zero responses and no private key | Challenge was a public SHA-256 digest; the ring equation only checked nonempty components, and the key image only checked length |
| `Groth16ZkSnark.VerifyProof` (BN254, BLS12-381, BLS12-377) | Accepted all-zero proof components; changing public inputs or using the wrong input count still succeeded | The mock pairing check only checked nonempty arrays; the input contribution ignored public inputs |

**Published-package check:** All 24 library assemblies in the six versions
currently available from the public NuGet index (0.1.0, 0.1.2, 0.2.0, 0.3.0,
1.0.0, and 1.0.1) were downloaded and their type-definition metadata inspected.
None contained `RingSignature`, `Groth16ZkSnark`, or a `ZeroKnowledge` namespace.
The source trees of all release tags, including v0.1.1, also exclude these implementations.

**Action:** Correct the stale feature and readiness claims. These historical
failures are not an exposed verification path in the inspected NuGet versions.
Any future implementation needs real cryptographic verification and tests that
reject forged signatures, invalid proofs, and altered public statements.
This review does not establish the security of other protocols or primitives.

### Historical internal review

**Internal Security Audit - October 2025**
- **Date**: 2025-10-26
- **Type**: Comprehensive internal code audit
- **Scope**: All source files (~11,000 lines of code)
- **Scope limitation**: Historical internal review only; not an independent audit or current release certification

**Findings**:
- **CRITICAL-001**: Non-cryptographic Random in SecureBuffer (Line 271) - ✅ **FIXED**
- **CRITICAL-003**: Hardware RNG placeholder using Environment.TickCount - ✅ **FIXED** (secure fallback enforced)
- **HIGH-002**: NotImplementedException in 5 production code paths - ✅ **FIXED** (proper error handling)

**Actions Taken**:
- Replaced `new Random()` with `RandomNumberGenerator.Fill()` in SecureBuffer.cs
- Hardware RNG now safely falls back to cryptographic RNG (documented as reference)
- Removed NotImplementedException, added clear error messages for unsupported features
- Created PRODUCTION_READINESS.md to document feature status
- Updated security documentation

**Current interpretation**: This historical review does not establish the security of the current codebase or every composition. Later releases corrected additional security defects. Use the current [production scope](PRODUCTION_READINESS.md), version-specific migration notes and exact-release test evidence.

### Independent audit status

No completed independent professional audit report is provided with this release.
The historical Q2 2026 audit target is not evidence of a completed audit. Targeted
regression reviews, standards vectors, dependency scans and CI do not replace an
independent protocol and application security review.

## 📋 Security Checklist for Contributors

Before submitting code that touches cryptographic implementations:

- [ ] Implementation follows published standards (RFC, NIST FIPS, etc.)
- [ ] Test vectors from official specifications are included
- [ ] Constant-time operations used where necessary
- [ ] Memory is securely cleared after use
- [ ] No timing or side-channel vulnerabilities introduced
- [ ] Input validation is comprehensive
- [ ] Error handling doesn't leak sensitive information
- [ ] Documentation includes security warnings where appropriate
- [ ] Code has been reviewed by another developer
- [ ] All existing tests pass
- [ ] New tests added for new functionality

## 🎓 Security Research

We welcome security research on HeroCrypt. If you're conducting academic research:

- Please let us know about your research
- We're happy to provide clarification or assist with questions
- We appreciate advance notice before publishing findings
- Please follow responsible disclosure practices

## 📚 Resources

### Cryptographic Standards
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [IETF RFCs](https://www.ietf.org/standards/rfcs/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

### Security Tools
- [CodeQL](https://codeql.github.com/) - Semantic code analysis
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [Snyk](https://snyk.io/) - Vulnerability scanning

### Learning Resources
- [Cryptography I (Coursera)](https://www.coursera.org/learn/crypto)
- [Serious Cryptography](https://nostarch.com/seriouscrypto) by Jean-Philippe Aumasson
- [Real-World Cryptography](https://www.manning.com/books/real-world-cryptography) by David Wong

## 🔔 Security Advisories

Security advisories will be published via:
- GitHub Security Advisories
- NuGet package warnings
- Release notes with CVE identifiers (if applicable)
- Security mailing list (planned)

## 💬 Contact

For non-security questions:
- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For general questions and discussions

For security concerns:
- **GitHub Security Advisories**: Use the "Report a vulnerability" button
- **GitHub Issues**: Create an issue with the `security` label

---

**Thank you for helping keep HeroCrypt and the .NET cryptography community secure!**

*Last Updated: 2025-10-26*
