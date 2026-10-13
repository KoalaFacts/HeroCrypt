# X3DH qualification — 2026-10-14

Implemented X3DH identity bootstrap for HeroCrypt's Double Ratchet profile. Production code and example have no Bouncy Castle dependency; BC is a private test reference only.

| Runtime | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| net8.0 | 4492 | 0 | 1 |
| net9.0 | 4501 | 0 | 1 |
| net10.0 | 4571 | 0 | 1 |

The only skip on each runtime is `Rfc6070 TestVector4 16777216Iterations`, the existing 16-million-iteration PBKDF2 vector. The 56 new XEdDSA/X3DH cases ran; the combined XEdDSA/X3DH/Double Ratchet focused suite passed 116 cases per runtime. Four library targets (.NET Standard 2.0, .NET 8/9/10) and all example/test targets built with zero warnings/errors. Locked restore and changed-file format verification passed; `git diff --check` is clean. Release-validation Python suite: 36 passed.

Independent evidence includes 16 pinned Python affine-Edwards XEdDSA fixtures and BC signature verification, independent Python/BC three/four-DH HKDF values, and independently composed BC first-message decryption. Five isolated mutations (identity pin, signed-prekey verification, premature OPK consumption, replay commit, canonical signature scalar) were each detected. Adversarial tests cover every initial wire byte, low-order keys, wrong trust/context/metadata, replay, caps, retained/retired SPKs, transactional rollback, concurrency and disposal. Supplementary tests execute 16 MiB plaintext with metadata/context endpoints and store-construction/identity-disposal races.

At verified implementation commit `ade6b94`, actual nupkg/snupkg identity, SourceLink provenance and payload validation passed. Independent public-API consumers of the actual net8 package and its extracted netstandard2.0 assembly passed initial authentication, tamper rollback, replay rejection, and replies after disposing identities/store. Library, example and consumer dependency graphs have no BC, and the production packages contain no BC assembly or test fixtures. Runnable `--x3dh` example passed.

A fresh coding-agent source review found no critical/important issue. Both minor test-coverage findings were addressed; see [implementation review](superpowers/reviews/2026-10-14-x3dh-implementation-review.md). This does not establish timing resistance, complete managed-memory erasure, or professional cryptographic audit assurance. Peer identity trust, in-memory state, restart recovery with fresh prekeys, weaker no-OPK forward secrecy, and absence of Signal wire compatibility/PQXDH remain explicit boundaries in [the public profile](x3dh.md).

Execution followed the approved plan in the existing managed isolated checkout. Two bookkeeping rulings: logs/ledger were kept under `/workspace/setup` because skill helper scripts had no executable filesystem root; BC/policy assertions were grouped in existing fixture/builder tests instead of duplicating classes. Neither changes protocol behavior.
