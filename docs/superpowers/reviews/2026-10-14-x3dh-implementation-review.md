# X3DH implementation review — 2026-10-14

A fresh coding-agent reviewer examined `4c0ae01` through `2746de8`, independently
of implementation, using the approved specification and five review focus areas.
No critical or important defect was identified. This is source review and test
execution, not a professional cryptographic audit or timing-resistance certification.

The review checked XEdDSA normalization and canonical encodings, identity pinning,
signed prekey authentication, three/four-DH order, HKDF and transcript/AD framing,
retained signed-prekey selection, authentication before store commitment,
allocation-free replay/OPK commitment, concurrent acceptance/disposal, and owned
buffer cleanup. The reviewer independently ran all 53 then-existing XEdDSA/X3DH
cases on .NET 10 successfully.

Two minor coverage gaps were identified and addressed after review:

- Validator tests did not exercise maximum payload/metadata through the complete
  handshake. `MaximumPayloadAndContextEndpoints_RoundTrip` now serializes, parses,
  authenticates and replies with 16 MiB plaintext, context lengths 1 and 4096,
  and metadata lengths 0 and 16 MiB minus the 70-byte identity/length overhead.
- The identity-disposal test copied private snapshots without constructing stores.
  `StoreConstruction_RacingIdentityDisposal_ReturnsCompleteStoreOrDisposedAsync`
  now starts construction and disposal from the same asynchronous gate. Every
  returned store must retain the pinned identity and a valid signed prekey;
  explicit before/after cases prevent vacuous coverage of the lifetime endpoints.

The supplementary tests do not guarantee every scheduler interleaving. Managed
memory erasure and constant-time execution cannot be certified by these tests.
The documented trust, persistence, no-OPK and protocol-compatibility limitations
remain part of the public API contract.
