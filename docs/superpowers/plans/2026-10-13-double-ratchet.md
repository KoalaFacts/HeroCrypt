# Double Ratchet Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans for inline execution. The user approved the written design and instructed execution with “开干”.

**Goal:** Add authenticated two-party Double Ratchet sessions without runtime cryptographic dependencies.

**Architecture:** Own mutable ratchet state behind a locked session API. Work on a deep candidate copy and commit only after successful AEAD, with immutable versioned messages and bounded skipped keys.

**Tech Stack:** C#, HeroCrypt X25519/HKDF/ChaCha20-Poly1305, .NET HMAC-SHA256, xUnit v3.

**Spec:** `docs/superpowers/specs/2026-10-13-double-ratchet-design.md`

## Global Constraints

- Build netstandard2.0, net8.0, net9.0, net10.0; no new production dependencies.
- Bouncy Castle remains a private test oracle only.
- Exact root/chain KDF, header and AD bytes follow the spec.
- Keys/context are copied; dispose owned sensitive material; no state export/reset/clone API.
- X3DH, Signal wire interoperability and persistent state are outside this change.
- Report existing .NET 10 SLH-DSA failures without suppressing them.

## Review Focus

- Forged far-ahead `N`/`PN`: bounded work and no state change, including across DH transitions.
- Delayed old-chain messages: cached keys survive new DH turns and are consumed only after authentication.
- Counter exhaustion: reject before key use or state mutation; no wraparound.
- Caller mutation/concurrent disposal: copied input data, serialized operations, no cross-thread key reuse.
- Low-order/noncanonical X25519 encodings: reject consistently on initialization and received messages.

### Task 1: Profile KDF and immutable wire messages

**Files:** Create `src/HeroCrypt/Protocols/DoubleRatchet/DoubleRatchetKdf.cs`, `DoubleRatchetMessage.cs`, and `tests/HeroCrypt.Tests/Protocols/DoubleRatchet/DoubleRatchetProfileTests.cs`.

**Interfaces:** `Root(byte[] root, byte[] dh, SecurityPolicyOptions policy) -> (byte[] Root, byte[] Chain)`; `Chain(byte[] chain) -> (byte[] Next, byte[] Message)`; public message `FromBytes(byte[])`, `ToBytes()`, `RatchetPublicKey`, `PreviousChainLength`, `MessageNumber`, `Nonce`, `Ciphertext`.

- [ ] Write tests: independently computed root/chain vectors; exact 53-byte header and counters; malformed lengths/version/coordinates; copy ownership.
- [ ] Run tests and confirm missing functionality fails. Use minimal throwing declarations to make missing APIs compile when needed.
- [ ] Implement exact KDF framing, canonical X25519 validation and immutable message codec.
- [ ] Run focused tests; expected all pass. Commit only task files.

### Task 2: Transactional session state machine

**Files:** Create `DoubleRatchetState.cs`, `DoubleRatchetSession.cs`, and `DoubleRatchetSessionTests.cs` under the corresponding source/test directories.

**Interfaces:** Spec's `CreateInitiator`, `CreateResponder`, `Encrypt`, `Decrypt`, `Dispose`. The factories also accept an optional final `SecurityPolicyOptions? policy = null` to match existing explicit-policy APIs; omitted policy captures the current immutable policy.

- [ ] Write tests for initial delivery/reply, multiple DH turns, same-chain/cross-chain reordering, replay, wrong secret/context/AD, header/ciphertext/tag modifications, malformed/low-order keys, total skipped-key limit, overflow, ownership, disposal and concurrent calls. After every rejected message assert the authentic original still decrypts.
- [ ] Run and inspect the failed tests before implementing their behavior.
- [ ] Implement cloned disposable state, standard initial/DH transitions, bounded key skipping and single-use keys. Header `N=uint.MaxValue` cannot be consumed or emitted; exhausted counters throw before mutation.
- [ ] Compare deterministic KDF/initial transitions with independent fixtures, then run the complete Double Ratchet test namespace; expected all pass. Commit task files.

### Task 3: Public documentation, example and final validation

**Files:** Add `examples/HeroCrypt.Examples/UseCases/DoubleRatchetExample.cs`; modify `Program.cs`, examples README, root README, CHANGELOG, SECURITY and PRODUCTION_READINESS. Add `docs/double-ratchet.md`.

- [ ] Add a two-party in-memory example showing authenticated bootstrap assumptions, reordering and replies. Clearly mark in-memory lifecycle, unaudited profile and absent X3DH.
- [ ] Build all frameworks with locked restore, run new tests and full suites on .NET 8/9/10, plus Python package gates. Confirm no new failures against the known baseline.
- [ ] Run formatting on changed C# files and an isolated package consumer exercising the new public session API; verify package graph has no Bouncy Castle.
- [ ] Request one fresh-context final code review of all protocol code/tests/spec. Resolve important findings with failing regression tests and rerun affected checks.
- [ ] Commit verified task changes; preserve all unrelated changes. Report test outcomes, known repository failures and protocol limitations.

## Execution record

Track task status and evidence in `/workspace/setup/double-ratchet-ledger.md`. Use the existing isolated task checkout; no worktree is needed or requested. Keep long logs and TRX files outside the checkout. Do not publish, push or merge.
