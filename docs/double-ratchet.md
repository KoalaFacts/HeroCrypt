# Double Ratchet messaging

HeroCrypt implements the classical [Double Ratchet algorithm](https://signal.org/docs/specifications/doubleratchet/)
for two HeroCrypt endpoints. DH and symmetric ratchets derive single-use message
keys; ChaCha20-Poly1305 authenticates plaintext, header and expected context. The
API is available on .NET Standard 2.0 and .NET 8/9/10 and has no third-party runtime
cryptographic dependency.

This new profile has not received an independent security audit and is not a
qualified production messaging protocol. It is not Signal's wire format and does
not implement X3DH/PQXDH, identity/prekey management, header encryption, group
messaging, post-quantum ratchets or persistent state. The managed primitives do not
provide a blanket constant-time or complete zeroization guarantee.

## Establishing a session

Before constructing sessions, independently authenticate a high-entropy 32-byte
shared secret, the responder's X25519 public key and the identical session-context
bytes. Context must identify the intended peer pair and application/session; it
must contain 1–4096 bytes. Exchanging an unauthenticated shared secret/public key
does not provide authenticated messaging. Double Ratchet does not authenticate
peer identities or perform its own initial key exchange.

```csharp
using HeroCrypt.Protocols.DoubleRatchet;

// Obtain these inputs from your separately authenticated bootstrap mechanism.
using var alice = DoubleRatchetSession.CreateInitiator(
    sharedSecret, bobPublicKey, sessionContext);
using var bob = DoubleRatchetSession.CreateResponder(
    sharedSecret, bobPrivateKey, sessionContext);

var first = alice.Encrypt("First"u8, "expected metadata"u8);
var second = alice.Encrypt("Second"u8, "expected metadata"u8);

// The receiving endpoint may obtain the second message before the first.
var secondBytes = bob.Decrypt(
    DoubleRatchetMessage.FromBytes(second.ToBytes()), "expected metadata"u8);
var firstBytes = bob.Decrypt(first, "expected metadata"u8);

// Receiving the authenticated first chain enables the responder's sending chain.
var replyBytes = alice.Decrypt(bob.Encrypt("Reply"u8));
```

Inputs are copied; clear your original shared secret/private-key buffers once
unneeded. Returned plaintext is owned by the caller and must be cleared as
appropriate. Message properties and serialization return copies. The factories
accept an optional final `SecurityPolicyOptions? policy` argument; otherwise they
capture the current immutable policy. Compliance policies rejecting X25519 or
ChaCha20 reject this profile.

## Delivery, errors and lifetime

The default skipped-key budget is 1000, shared across all receive chains; set
`maxSkippedKeys` to 0–10000 inclusive. Zero requires ordered delivery. Missing old
messages remain decryptable across DH turns while their keys remain cached.
Exceeding the budget rejects the message instead of silently evicting old keys;
deliver missing messages first or establish a fresh authenticated session.

Decryption consumes a message key only after authentication. Replay, wrong metadata,
wrong context, bad tags, low-order DH keys, exhausted receive counters and excessive
gaps throw `CryptographicException` without changing state. Invalid configuration,
wire encoding or excessive payload sizes throw argument exceptions. Sending before
the responder authenticates its first message, or after counter exhaustion, throws
`InvalidOperationException`. Operations after disposal throw `ObjectDisposedException`.

Session methods serialize access internally. They do not provide transport ordering,
acknowledgments or retransmission; retransmit the same serialized message rather than
encrypting the same application message again. Calling `Dispose` clears owned key
buffers and skipped keys. There is no supported state export/import/reset/clone API.
After process restart, establish a new authenticated session. Restoring a stale
state can reuse keys or accept replays and must not be used as an ad hoc persistence
mechanism. Secure persistent sessions require a separate crash-safe design.

## Version 1 cryptographic profile

- Root KDF: HKDF-SHA256, salt = old root, input = X25519 shared secret, ASCII info
  `HeroCrypt.DoubleRatchet.Root.v1`, output = 32-byte root then 32-byte chain key.
- Chain KDF: message key = HMAC-SHA256(chain, `0x01`), next chain =
  HMAC-SHA256(chain, `0x02`). The message key is the ChaCha20-Poly1305 key.
- Header: version byte `1`, canonical 32-byte X25519 public key, previous-chain
  length `PN` and message number `N` as 4-byte unsigned big-endian values, then
  a fresh 12-byte nonce. Total header size: 53 bytes.
- Wire message: header followed by ciphertext with its appended 16-byte tag.
  Plaintext and per-message associated data are each limited to 16 MiB.
- AEAD associated data: ASCII `HeroCrypt.DoubleRatchet.v1`, context length as
  4-byte big-endian, context bytes, metadata length as 4-byte big-endian,
  metadata bytes, then the complete header.

The responder supplies its initial DH private key; the initiator generates a fresh
DH pair and derives its first sending chain against the authenticated responder key.
On a new received ratchet key, the receiver derives its receiving chain, generates
a fresh local pair, and derives its sending chain. Counter `uint.MaxValue` is never
used as an outgoing or accepted message number.

## Evidence and example

`DoubleRatchetProfileTests` checks independent HKDF/HMAC vectors and exact framing.
`DoubleRatchetSessionTests` checks independently composed initial messages and DH
transitions, authenticated rollback, reordering across chains, replay, bounded work,
counter exhaustion, input ownership, concurrent operations and disposal. Bouncy
Castle is used only in tests as an independent primitive oracle.

From the repository root:

```bash
dotnet run --project examples/HeroCrypt.Examples/HeroCrypt.Examples.csproj --framework net10.0 -- --double-ratchet
```

The example uses a trusted in-process bootstrap solely to demonstrate messaging;
it is not a network identity-authentication mechanism.
