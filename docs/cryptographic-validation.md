# Cryptographic validation

This qualification extends functional validation of managed secp256k1 and the
classical HeroCrypt Double Ratchet profile. The tests run in the existing .NET
8/9/10 matrix. Bouncy Castle remains a private dependency of the test project,
used as an independent comparison implementation. No runtime algorithm, public
API or wire format changes are required by these additions.

## Independent inputs and implementations

| Area | Evidence added | What is checked |
| --- | --- | --- |
| secp256k1 verification | Pinned Wycheproof SHA-256 P1363 corpus | All 252 cases: 167 valid, 85 invalid, including 18 malformed signature lengths; both SEC 1 key encodings |
| Rare ECDSA branch | Independently constructed point with x = n + 2 | Verification reduces the point's x coordinate modulo n; BC also verifies the constructed signature |
| Double Ratchet | Test-only BC reference peer with its own state and wire/AD encoder | Both roles, four fixture seeds, 24 exchange epochs per case, 1,920 bidirectional payloads plus four bootstrap messages |
| Hostile delivery | Reversed five-message batches and messages delayed across DH turns | Old skipped keys remain usable; replay, bad tags and wrong metadata are rejected without breaking subsequent valid traffic |
| Wire authentication | Every bit of a 90-byte message flipped individually; every truncation of an 87-byte message | 720 mutations and 87 truncations are rejected, each followed by an authentic retry on the same receiver |
| X25519 low-order keys | All five canonical low-order u-coordinates, independently rejected by BC | Initiation and both initial/later DH receive reject the key; the original message remains decryptable |
| Key lifecycle | References to the original owned state buffers | Commit clears superseded keys during send, same-chain receive, skipped-key consumption and DH transition; failed authentication preserves original buffers and counters |

The [fixture provenance](../tests/HeroCrypt.Tests/Fixtures/Wycheproof/README.md)
records the exact upstream revision, SHA-256 and license. The fixture is embedded
only in the test assembly; validation does not fetch data from the network.
Its digest and result counts are checked before cases are enumerated. Correctly
sized invalid signatures must return false; malformed signature lengths must
raise `ArgumentException`, matching the API contract.

The reference peer uses BC X25519, HKDF-SHA-256, HMAC-SHA-256 and
ChaCha20-Poly1305. It does not invoke HeroCrypt primitives, KDFs, state or wire
encoding. Its deterministic keys and nonces are public test fixtures. It is a
comparison oracle for valid traffic, not a production protocol implementation;
all hostile packets are directed at the HeroCrypt session.

## Test sensitivity

Two deliberate mutations were built and exercised in a separate disposable
copy of the repository:

- Replacing ECDSA `result.X % order == r` with `result.X == r` fails
  `Verify_AcceptsRareVerificationPointWithXAboveOrder`.
- Removing `old.Dispose()` from ratchet state commit fails both
  `SuccessfulSend_ClearsSupersededOwnedKeyBuffers` and
  `SuccessfulReceives_ClearSupersededKeysAcrossChainsAndSkippedConsumption`.

All three selected tests fail against the deliberately broken copy. The working
production sources retain both protections. The new tests add 271 executed
cases to each framework's suite, including 252 external verification vectors.

## Reproduction

### Recorded result: 2026-10-13

Qualification on Linux with the pinned .NET SDK 10.0.401:

| Runtime | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| .NET 8 | 4,436 | 0 | 1 |
| .NET 9 | 4,445 | 0 | 1 |
| .NET 10 | 4,515 | 0 | 1 |

Each skip is the existing RFC 6070 16-million-iteration PBKDF2 case. No failures
were suppressed. The focused secp256k1/Double Ratchet run passes 357 cases.
Release builds for .NET Standard 2.0 and .NET 8/9/10 have zero warnings/errors;
format verification and all 36 Python release-validation tests pass. Production
and example lockfiles and the library package contain no Bouncy Castle runtime
dependency; the library package contains no Wycheproof fixture.

### Commands

Use the pinned SDK from `global.json` and install the .NET 8/9/10 runtimes. On
Linux, native post-quantum tests additionally require a supported OpenSSL
provider; the recorded qualification used OpenSSL 3.5.7.

```bash
dotnet restore --locked-mode
dotnet build --configuration Release --no-restore -m:3
for framework in net8.0 net9.0 net10.0; do
  dotnet test --project tests/HeroCrypt.Tests/HeroCrypt.Tests.csproj \
    --configuration Release --framework "$framework" --no-build --no-restore
done
python3 -m unittest discover -s scripts -p test_release_validation.py
```

For the focused crypto tests after building:

```bash
dotnet tests/HeroCrypt.Tests/bin/Release/net8.0/HeroCrypt.Tests.dll \
  -namespace 'HeroCrypt.Tests.Primitives.Secp256k1*' \
  -namespace 'HeroCrypt.Tests.Protocols.DoubleRatchet*' -noLogo -noColor
```

## Security boundaries

Independent source review found no actionable correctness defect in the
reviewed secp256k1/Double Ratchet changes or validation additions. This review
was performed by a separate coding agent; it is not a professional independent
cryptographic audit.

Functional vectors, interoperability and mutation checks do not establish
constant-time execution. secp256k1 scalar multiplication branches on secret
bits, point operations have exceptional-case branches, and `BigInteger`
arithmetic is variable-time. Immutable internal `BigInteger` secret storage
cannot be reliably erased. Cleanup tests establish clearing of specific owned
byte arrays, not all runtime copies or physical memory. These properties remain
limitations of the managed implementation; no timing-resistance claim is made.

Double Ratchet still requires an independently authenticated bootstrap, fresh
sessions after restart, and application-specific qualification. These tests do
not provide X3DH/PQXDH, identity management, state persistence, Signal wire
compatibility or post-quantum security. See the [protocol profile](double-ratchet.md)
and [security limits](../SECURITY.md).
