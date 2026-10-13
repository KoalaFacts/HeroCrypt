# X3DH design and implementation-plan review

Reviewed on 2026-10-14 at the user's request. Baseline: design `ff7ec49` and
implementation plan `e798a98`. This is a review of proposed code, interfaces and
state transitions; at that reviewed baseline X3DH had not been implemented or qualified.

The primary agent checked two independent reviewers' findings against the
repository and reference sources, then corrected the
[design](../specs/2026-10-14-x3dh-design.md) and
[implementation plan](../plans/2026-10-14-x3dh.md).

## Findings and resolutions

All four material findings are P2 design/plan issues, not demonstrated defects
in an implemented X3DH feature.

| Finding | Evidence and failure | Resolution |
| --- | --- | --- |
| OPK downgrade guarantee is too broad | Only `Encode(SPK_B)` is signed. A directory can remove an optional OPK before initiation while retaining a valid signature. | Distinguish unauthenticated pre-initiation availability from forbidden fallback after an OPK is selected. Document the required caller-side presence check for four-DH and test the supported three-DH path after withholding. |
| Cleanup requirement conflicts with permitted changes | Existing Ed25519 helpers including `M`, `Add`, `Scalarbase`, `Pack` and `Reduce` allocate secret-derived scratch that a new entry-point finally cannot reach. The original plan allowed only making the class partial. | Permit narrowly scoped finally-based cleanup inside those helpers, preserve arithmetic/RFC 8032 results, use span clearing and protect shared constants/caller input. Keep the managed-runtime limitations explicit. |
| Cleanup can fail after acceptance commits | The byte-array `SecureClear` overload's .NET Standard 2.0 branch calls RNG and GC/finalizer waits. Using it after replay/OPK mutation can report failure after consuming state. | Require a fully prepared result and all fallible work before commit. Use nonallocating span cleanup for store commitment and return-path finally blocks; perform no RNG/explicit GC/user callback after commitment. |
| Replay insertion cannot assume failure atomicity | `HashSet<string>.Add` can insert/link a record and then allocate during collision-triggered randomized rehashing. An exception is not proof that the set was unchanged. | Replace the growing hash set with a preallocated `32 * maxReplayEntries` byte digest buffer and occupied-count tracking. Validate a free slot before authentication; commit only copies into that slot, updates the count and consumes/clears the OPK under the lock. |

The replay representation uses at most 320000 bytes per store and a bounded
membership scan of at most 10000 digest slots. It introduces no new public API,
wire format, KDF or runtime dependency.

## Additional coverage clarified

- Initial envelopes must carry ratchet `N = PN = 0`; later messages are rejected
  before DH derivation or key skipping. Parsing and internal creation enforce it.
- Separate signature rejection at initiation, malformed-byte rejection at
  parsing, and authentication/rollback testing at `Accept`, which takes an
  already parsed object and receives no signature in HCXI.
- Fresh-store recovery must reject old envelopes, accept fresh prekeys and
  preserve independently owned existing sessions.
- A signed-prekey retention cap of one intentionally prevents in-place
  rotation; fresh-store recovery remains available.
- Acceptance builds its transcript from the specifically selected retained
  signed/one-time keys, not the current publication bundle.
- Test fixed replay-buffer ownership/no growth and its clearing on disposal.

## Evidence and limits

The selected DH ordering, F-prefix, HKDF salt/info/output, normalized XEdDSA
scalar/nonce equations and identity/transcript framing revealed no additional
construction contradiction in this review. The pinned normalized XEdDSA C
references were inspected rather than copied. BC remains test-only; its
Ed25519 verifier alone does not establish XEdDSA-specific signing correctness.

Source evidence for the cleanup findings is in
`src/HeroCrypt/Primitives/Ed25519/Ed25519Core.cs` and
`src/HeroCrypt/Security/SecureMemoryOperations.cs`. Replay-container evidence was
checked against the public
[.NET 10 HashSet source](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Private.CoreLib/src/System/Collections/Generic/HashSet.cs):
`AddIfNotPresent` updates the entry/bucket/count before its collision-triggered
`Resize(..., forceNewHashCodes: true)` call, which allocates a new entries array.

Document consistency checks confirm unchanged wire sizes (138/174-byte bundles,
78/82-byte initial overhead), unchanged KDF/AD domains and metadata cap, covered
review conditions, removal of the contradictory declaration-only restriction,
and fixed replay-storage bounds. No production files or test suites were
changed by this review. Cryptographic runtime tests still belong to implementation.

Both independent reviewers re-read the final corrections and found no remaining
material design/plan issue. This disposition applies to the documents, not to
unwritten implementation. This is a coding-agent review, not a professional cryptographic
audit, constant-time certification or proof of complete secret erasure.
