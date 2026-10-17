# OpenPGP Argon2 S2K resource limits

Argon2 S2K parameters are unauthenticated when message and secret-key decryption
begin. HeroCrypt validates nonzero passes and parallelism, and the RFC 9580
exponent range `3 + ceil(log2(parallelism))` through `31`, before derivation.
Malformed parameters throw `ArgumentException` (including its subclasses).
Invalid exponents are never masked, clamped, or substituted with cheaper values.

Parsing and parameter factories validate the encoded domain without deriving a
key. Exponent 31 is valid encoding, but derivation throws `NotSupportedException`:
the existing core uses signed 32-bit memory sizes. Other valid parameters can
exceed the caller's resource limits, producing `CryptographicException` before
Argon2 allocation or work. Message `TryDecrypt` returns false and no plaintext
when no candidate can be authenticated within those limits.

The immutable `S2KResourceLimits` defaults are **524288 KiB (512 MiB)** of requested
Argon2 memory and **1572864 KiB-passes** of work (`memoryKiB * passes`) per
derivation. These retain the existing private-key generation defaults (three
passes, four lanes, exponent 19) as well as the message/S2K defaults (exponent
16). Managed memory overhead is additional. These are per-derivation bounds,
not total process memory, wall-clock, concurrent-request, or aggregate
multi-candidate message limits. Applications must also bound request rates,
concurrency, input sizes, and candidate counts as appropriate.

Constrained applications should set lower limits explicitly:

```csharp
var limits = new S2KResourceLimits
{
    MaxArgon2MemoryKiB = 65536, // 64 MiB
    MaxArgon2WorkKiB = 196608  // three passes at 64 MiB
};
var policy = SecurityPolicyOptions.Default with { S2KLimits = limits };
using var decryptor = PgpMessageDecryptor.Create()
    .WithSecurityPolicy(policy)
    .WithMessagePassphrase(passphrase);
var message = decryptor.Decrypt(encodedMessage);

var secretKey = encryptedSecretKey.Decrypt(passphrase, limits);
var key = parameters.DeriveKey(passphraseBytes, 32, policy);
```

The same policy works with `S2KBuilder.Create(policy)`, message encryption, and
`PgpKeyGenerator.WithSecurityPolicy(policy)`. When using lower limits for key
generation, also select generation parameters within them, for example
`WithArgon2Passphrase(passphrase, passes: 3, parallelism: 4, memoryExponent: 16)`.
Raise limits deliberately for trusted higher-cost inputs; existing examples
with exponent 21 (2 GiB) require explicit limits. Both limits must be positive.
Testing/legacy algorithm policies and scoped level overrides retain the limits.

Existing public method signatures, valid derived bytes, algorithm choices, and
packet encodings are preserved. `Decrypt(string, S2KResourceLimits)` is additive;
the existing secret-key `Decrypt(string)` uses the current policy's limits and
continues its legacy hash-consumption behavior. This fix does not migrate the
historical 21-byte `PgpS2KSpecifier` secret-key representation; the 20-byte
`S2KParameters` representation remains unchanged too. Previously accepted
malformed or over-budget parameters now fail explicitly.

Regression tests use 8–32 KiB Argon2 fixtures, an independent Bouncy Castle
implementation, native AES message/secret-key fixtures, and parameter-only
checks for large costs. They cover parser/factory/manual-object bypasses,
memory and work boundaries, v4/v6 message decryption, encrypted recipient keys,
and caller policy propagation. The existing RFC 9106 vectors remain in the
full suite. No exhaustion experiment is needed.

Reference: [RFC 9580 section 3.7.1.4](https://www.rfc-editor.org/rfc/rfc9580.html#section-3.7.1.4).
