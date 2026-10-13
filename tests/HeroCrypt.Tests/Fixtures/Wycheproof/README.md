# Wycheproof secp256k1 ECDSA vectors

Unmodified upstream corpus from C2SP/wycheproof, revision `7a325932231bd7a724c791c8b0d65ea4d6d2f435`.
Source: https://github.com/C2SP/wycheproof/blob/7a325932231bd7a724c791c8b0d65ea4d6d2f435/testvectors_v1/ecdsa_secp256k1_sha256_p1363_test.json
SHA-256: `7a339efc7134fb2495cd32afdbd692e0f86427d3c24e9073f6a7d858bb8788d2`.

The 252 cases contain 167 valid and 85 invalid signatures; no acceptable cases.
Tests hash each message with SHA-256 and verify the original P1363 signature
against both compressed and uncompressed SEC 1 public keys. Malformed signature
lengths must raise ArgumentException; correctly sized invalid signatures must
return false. The fixture hash and case counts are checked before enumeration.

Licensed under Apache-2.0; the upstream license is included alongside the corpus.
These vectors exercise signature verification, not constant-time behavior.
