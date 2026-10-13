# X3DH identity handshake

HeroCrypt supports the classical X25519/SHA-256 X3DH construction with
normalized-sign-bit XEdDSA signatures, signed prekeys and optional one-time
prekeys. Successful first-message authentication produces an independently
owned [Double Ratchet session](double-ratchet.md). Library targets remain
.NET Standard 2.0 and .NET 8/9/10; no third-party runtime crypto dependency is
added. Bouncy Castle is used only by independent comparison tests.

This HeroCrypt wire/profile encoding is not Signal-compatible. It does not
provide PQXDH, account authentication, fingerprint storage, transport, prekey
leases, multi-device coordination or persistent stores. No completed independent
professional cryptographic audit, constant-time guarantee or complete managed
memory erasure is claimed.

## Trust and first message

Obtain each expected 32-byte identity public key through an independently trusted
channel, such as verified fingerprints. Pass that expected key explicitly on
both sides. Do not take the expected identity from the same untrusted bundle
being verified: a self-consistent attacker identity can sign its own prekeys.
Mismatch rejects rather than silently learning or replacing the identity.

The signed-prekey signature authenticates `0x05 || signedPreKeyPublicKey`,
using the same X25519 identity private scalar for XEdDSA. It does not authenticate
OPK availability or directory expiry metadata. A directory can withhold an OPK
before initiation, selecting the supported three-DH path. If four-DH is required,
check both optional OPK fields before initiating; a selected missing/invalid OPK
never falls back to three-DH.

```csharp
using HeroCrypt.Protocols.X3dh;

using var alice = X3dhIdentityKey.FromPrivateKey(alicePrivateKey);
using var bob = X3dhIdentityKey.FromPrivateKey(bobPrivateKey);
using var store = X3dhPreKeyStore.Create(bob);
var opkId = store.GenerateOneTimePreKey();
var published = store.GetBundle(opkId).ToBytes();

// The application transports published bytes through its prekey directory.
var bundle = X3dhPreKeyBundle.FromBytes(published);
if (!bundle.OneTimePreKeyId.HasValue || bundle.OneTimePreKeyPublicKey == null)
    throw new System.Security.Cryptography.CryptographicException("OPK required.");

// expectedBobIdentity / expectedAliceIdentity are independently verified keys.
using var outgoing = X3dhHandshake.Initiate(alice, bundle, expectedBobIdentity,
    applicationContext, "first message"u8, "expected metadata"u8);
var delivered = X3dhInitialMessage.FromBytes(outgoing.InitialMessage.ToBytes());
using var incoming = store.Accept(delivered, expectedAliceIdentity,
    applicationContext, "expected metadata"u8);

var firstPlaintext = incoming.Plaintext; // owned copy: caller must clear it
var reply = incoming.Session.Encrypt("reply"u8);
var replyPlaintext = outgoing.Session.Decrypt(reply); // caller must clear it
```

Alice verifies Bob's signed prekey before deriving the secret. Bob accepts only
after the nested first message authenticates. Alice receives responder key
confirmation only when a reply authenticates. Identities and all selected
handshake keys/IDs are bound to the ratchet session context. Application context
and expected metadata must match exactly; they are not learned from the packet.

`Generate` creates an in-memory identity with no private-key export. For a
persistent identity, generate/store its private material through the application's
protected mechanism, then import with `FromPrivateKey`. The application owns and
must clear its original private-key buffers; imported buffers are copied/clamped.

## Ownership, prekeys and replay

Stores own identity/key copies. Immutable packet objects expose copied public
data. Disposing identities or stores does not invalidate independently owned
active sessions. Disposing initiation/acceptance results closes their sessions;
acceptance also clears its owned first plaintext. Every `Plaintext` getter
returns a new copy; disposal cannot erase copies retained by the caller.

`GetBundle` publishes without consuming an OPK; a directory's allocation/lease
policy belongs to the application. `Accept` checks identity, selected keys and
replay/capacity, derives a candidate session and authenticates first message zero.
Only then does it record the transcript and remove/clear the OPK under a lock.
Failures leave keys and replay records intact; concurrent OPK acceptance can
succeed once. Both OPK and no-OPK paths reject accepted-transcript replay, even
with changed ciphertext. No unauthenticated plaintext is returned.

Replay storage is preallocated: 32 bytes per allowed acceptance, with no eviction
or hash-container growth. Membership scans occupied slots, bounded by the cap.
Default replay cap is 10000 (320000 bytes); allowed range is 1–10000. Once full,
create/publish a fresh store with fresh prekeys. An old envelope cannot authenticate
against its newly generated keys; existing independent sessions remain usable.

The OPK cap defaults to 1000 and permits 0–10000. Signed-prekey retention defaults
to 4 and permits 1–32 including the current key. Rotation retains old keys for
delayed initiations; retire a noncurrent key explicitly when its use window ends.
At the retention cap, retire an older key before rotating. Cap 1 disables in-place
rotation because the current key cannot be retired. IDs start at 1 in separate
namespaces, never wrap or repeat during a store lifetime, and exhaustion rejects.

Stores have no state export/import. After restart, retain identity only through
the application's protected mechanism and publish fresh signed/one-time prekeys.
Never restore old private prekeys with an empty replay cache. No-OPK exchanges
have the weaker forward-secrecy properties described by X3DH and should not be
presented as four-DH exchanges.

## Exact profile

`Encode(PK) = 0x05 || PK` for a canonical 32-byte X25519 u-coordinate. Reject
noncanonical keys and all-zero DH contributions. XEdDSA uses a clamped X25519
scalar directly, Edwards sign normalization to zero, SHA-512 and fresh 64-byte
signing randomness; it is not Ed25519 signing of the private bytes as a seed.

Alice concatenates `DH(IK_A,SPK_B) || DH(EK_A,IK_B) || DH(EK_A,SPK_B)` and, when
selected, `DH(EK_A,OPK_B)`. Bob computes the matching contributions. Derive a
32-byte SK with HKDF-SHA256, 32 zero salt bytes, input `0xff*32 || DH material`
and info ASCII `HeroCrypt.X3DH.v1`. SK and ephemeral private material are not
exported in results. Alice's initial ratchet key is fresh and separate from EK_A;
Bob's initial ratchet key is the selected SPK_B.

The session context is SHA-256 of ASCII `HeroCrypt.X3DH.DoubleRatchet.v1`, then
uint32be application-context length/context, encoded IK_A/IK_B/EK_A/SPK_B,
uint32be SPK ID, one-byte OPK flag and, if present, uint32be OPK ID/encoded OPK.
First-message AD is encoded IK_A/IK_B, uint32be metadata length and metadata.
Existing ratchet framing authenticates that AD, context and its complete header.

Bundle wire: `HCXB`, version 1, identity (32), SPK ID (4), SPK (32), signature (64),
OPK flag (1), optionally OPK ID (4)/OPK (32): exact size 138 or 174 bytes.
Initial wire: `HCXI`, version 1, IK_A (32), EK_A (32), SPK ID (4), OPK flag (1),
optional OPK ID (4), nested length (4), nested ratchet bytes: overhead 78 or 82.
Integers are unsigned big-endian. IDs are nonzero and flags are exactly 0/1.
Nested ratchet counters must be `N = PN = 0`; reject unknown formats, trailing
bytes and inconsistent lengths before key derivation.

Application context has 1–4096 bytes, initial plaintext at most 16 MiB, and
metadata at most `16*1024*1024 - 70` bytes. Ratchet skipped-key cap remains
0–10000. Factories capture the selected immutable policy; compliance policies
that reject the primitives reject this whole profile.

## Validation and example

The suite covers independent affine-Python XEdDSA vectors and BC verification,
canonical scalar/coordinate malleability, independently pinned three/four-DH SKs,
BC-composed first-message decryption, multi-epoch replies, every initial byte
mutation, low-order contributions, wrong identities/context/metadata, key limits,
rotation/retirement, concurrent acceptance/disposal, replay and owned-buffer
cleanup. Functional tests cannot certify timing resistance or all runtime copies.

```bash
dotnet run --project examples/HeroCrypt.Examples/HeroCrypt.Examples.csproj \
  --configuration Release --framework net10.0 -- --x3dh
```

For the design and implementation decisions, see the
[reviewed specification](superpowers/specs/2026-10-14-x3dh-design.md),
[plan](superpowers/plans/2026-10-14-x3dh.md) and
[cryptographic validation record](cryptographic-validation.md).
