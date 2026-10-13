# Double Ratchet session design

## Intent and constraints

Add a usable Double Ratchet API for two HeroCrypt endpoints, following the
[Signal Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/)
for the classical DH and symmetric-key ratchets. The user selected HeroCrypt-to-HeroCrypt
operation and requires no Bouncy Castle production dependency. Reuse HeroCrypt's
X25519, HKDF and ChaCha20-Poly1305 primitives and .NET HMAC-SHA256. No new runtime
package or native binary is required. Bouncy Castle may be used only as a test oracle.

Keep all four library targets: netstandard2.0, net8.0, net9.0 and net10.0.
This is a new in-memory protocol implementation, not qualification for production,
Signal wire interoperability, or an independently audited messaging system.

## Scope

Provide initiator/responder initialization, authenticated message encryption and
decryption, DH ratchet transitions, skipped-message keys, bounded out-of-order
delivery and replay rejection. Initialization consumes a previously authenticated
32-byte shared secret and the responder's authenticated X25519 public key; the
responder also supplies its corresponding private key. The application establishes
and authenticates those inputs and the session context through a separate mechanism.

X3DH/PQXDH, identity/prekey management, transport, group messaging, header encryption,
post-quantum ratchets and state persistence are separate features. Reusing or restoring
an old session state is unsafe; the first implementation exposes no state export,
import, clone or reset API. Applications establish a new authenticated session after
process restart. Document these boundaries explicitly.

## Public API and ownership

Add types in `HeroCrypt.Protocols.DoubleRatchet`:

- `DoubleRatchetSession.CreateInitiator(byte[] sharedSecret, byte[] responderPublicKey,
  byte[] sessionContext, int maxSkippedKeys = 1000)`.
- `DoubleRatchetSession.CreateResponder(byte[] sharedSecret, byte[] responderPrivateKey,
  byte[] sessionContext, int maxSkippedKeys = 1000)`.
- `DoubleRatchetMessage Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default)`.
- `byte[] Decrypt(DoubleRatchetMessage message, ReadOnlySpan<byte> associatedData = default)`.
- `DoubleRatchetMessage.FromBytes(byte[] encoded)` and `byte[] ToBytes()` for transport.
- Sessions implement `IDisposable`; their methods serialize access with a lock.

Session context is required, 1–4096 bytes, and must identify the expected peer pair
and protocol/application context. Each endpoint must supply identical context bytes.
Caller-provided arrays are copied. Public message objects own their data and expose
copies, preventing callers from mutating headers while an operation is in progress.
The caller owns and must clear returned plaintext and its original secret inputs.
Owned session keys, discarded candidate state, skipped keys and temporary buffers
are cleared when their lifetime ends. No complete managed-runtime zeroization or
constant-time guarantee is claimed for the underlying primitives.

## Cryptographic profile

Use X25519 for DH. Reject noncanonical public coordinates and reject every all-zero
shared secret through the existing primitive's validation. Use a fresh ratchet
key pair at initiator initialization and each receive-side DH transition.

`KDF_RK(RK, DH)` is HKDF-SHA256 with salt `RK`, input `DH`, info
`HeroCrypt.DoubleRatchet.Root.v1` encoded as ASCII, and a 64-byte output split into
the new root key and chain key. `KDF_CK(CK)` produces the message key with
HMAC-SHA256(CK, 0x01) and the next chain key with HMAC-SHA256(CK, 0x02).
Use the 32-byte message key directly with ChaCha20-Poly1305 and a fresh 12-byte nonce.
There is no algorithm negotiation in version 1.

Follow the specification's initiator/responder initialization: the initiator starts
with a sending chain derived from its new DH key and the responder's initial public
key; the responder starts with its supplied DH key and no sending chain. The responder
must receive and authenticate an initiator message before encrypting its first reply.

## Wire format and authentication

The version 1 header is exactly 53 bytes: version byte `1`, 32-byte sender ratchet
public key, 4-byte previous sending-chain length `PN`, 4-byte message number `N`, and
12-byte nonce. Both counters are unsigned big-endian. Follow the header immediately
with ciphertext and its appended 16-byte authentication tag. Reject unknown versions,
noncanonical public-key encodings, undersized messages, and payloads larger than
16 MiB plus tag. Reject low-order contributions when DH produces an all-zero secret.

AEAD associated data is ASCII `HeroCrypt.DoubleRatchet.v1`, then a 4-byte big-endian
session-context length and context bytes, then a 4-byte big-endian per-message
associated-data length and those bytes, then the full header. Limit per-message
associated data to 16 MiB as well. This authenticates DH keys, counters, nonce, expected
peer/session context, and application metadata with unambiguous framing.

This is a HeroCrypt encoding of the standard ratchet algorithm, not Signal's encoding.

## State transitions and failure behavior

Own root key, local DH key pair, remote DH public key, sending/receiving chain keys,
`Ns`, `Nr`, `PN`, and skipped keys indexed by `(remotePublicKey, messageNumber)`.

Apply transitions to a deep candidate copy. Commit only after encryption or successful
message authentication. Failed decryption must neither advance chains, rotate keys,
consume a skipped key, nor change counters. Dispose rejected candidates and replace
and clear old state when committing. Check skipped-key lookup before new DH handling.
Reject duplicate/stale messages when their key has already been consumed.

`maxSkippedKeys` is in 0–10000 inclusive. Enforce it both on each requested counter gap
and on total cached keys across DH chains before deriving missing keys. Retain old-chain
keys for late delivery; reject messages exceeding the budget rather than silently
evicting keys. Reject counter overflow before changing state. Authenticate `PN` and `N`
and bound work driven by either. Disposal clears all owned keys and is idempotent;
subsequent operations throw `ObjectDisposedException`.

Capture the selected existing security policy at creation and enforce it through
all underlying primitives. Compliance policies that reject X25519/ChaCha20 must
reject this profile consistently.

## Validation and documentation

Use test-driven implementation with independent deterministic fixtures for chain/root
KDF and reference ratchet transitions. Verify X25519 inputs and shared secrets against
the existing independently tested primitive. Test one-way streams, alternating DH
transitions, simultaneous/out-of-order delivery across old and new chains, replay,
wrong secret/context/associated data, modified header/ciphertext/tag, skipped-key
budget and retention, counter overflow, disposal, input ownership and concurrent calls.
After every rejected message, verify the authentic original still decrypts.

Build all four library targets; run the new suite and full existing suites on .NET
8/9/10. Report known unrelated SLH-DSA failures separately and do not suppress them.
Verify the actual NuGet package has no Bouncy Castle dependency. Add a runnable
two-party example and update README, API documentation and production limits to
describe the implemented scope accurately. Do not continue to advertise X3DH as
implemented when it remains outside this change.

## Review status

This design incorporates the user's selected compatibility scope and production
dependency constraint. Written-spec review is pending before implementation planning.
