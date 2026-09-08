# Security policy

This document tracks the release-blocking security defects that were
identified in the 2026 production-readiness audit (`catapult_analysis.md`)
and remediated in the Phase 0 series of fixes.

Catapult must not be used in production until the release-blocking items in
`catapult_analysis.md` are completed. Phase 0 has closed the most immediate
memory-safety and authorization-bypass defects; Phases 1–4 close the
standards-conformance, cryptographic, and supply-chain gaps.

## Reporting a vulnerability

Please open a private security advisory through the repository's GitHub
Security tab. Do not open a public issue for vulnerabilities in the
authorization, cryptographic, or parsing paths.

## Supported versions

| Version   | Supported | Notes                                            |
|-----------|-----------|--------------------------------------------------|
| ≥ 2.0.0   | Yes       | Phase 0 baseline + audit-round A-01..A-04 fixes. Breaking ABI change: `UsageStateHook::revoke()` now returns `RevokeResult` (was `void`); `DpopPayload::iat` is now `std::optional<int64_t>` (was `int64_t`). |
| 1.3.0     | Yes       | Phase 0 remediation baseline. See advisories.    |
| < 1.3.0   | No        | Contains CATAPULT-2026-0001..0003.               |

## Advisories

### CATAPULT-2026-0001 — Legacy JWT-shaped token API is non-standard

- **Severity:** High (interoperability + policy divergence).
- **Affected:** all versions before 1.3.0.
- **Description:** The `encodeToken` / `decodeToken` helpers emitted a
  JWT-shaped, dot-separated string with a JSON header and CBOR payload.
  This format does not conform to CTA-5007-B or RFC 8392 (CWT) and is not
  interoperable with any CAT implementation outside this repository.
- **Remediation:** the free-function API has been moved into
  `catapult::legacy::legacyJwtEncodeToken` / `legacyJwtDecodeToken` inside
  `#ifdef CATAPULT_ENABLE_LEGACY_JWT_TOKEN`. Both symbols are
  `[[deprecated]]`. Production callers must migrate to
  `Cwt::createCwtBase64` / `Cwt::validateCwtBase64`.

### CATAPULT-2026-0002 — DPoP proof signature verification could be skipped

- **Severity:** Critical (authorization bypass).
- **Affected:** all versions before 1.3.0 that exposed
  `DpopProofValidator::validate_proof`.
- **Description:** For CWT-encoded DPoP proofs, `validate_proof` would
  succeed on structural checks alone if the caller did not separately verify
  the proof signature. An attacker who could mint a syntactically correct
  DPoP proof (no key ownership required) could pass authorization.
- **Remediation:** `validate_proof` now fails closed if signature
  verification does not succeed. Callers must attach a verifier via
  `DpopProofValidator::set_cwt_verifier(&algorithm)` before validating
  CWT-encoded proofs. JWT-encoded proofs self-resolve their verifier from
  the embedded JWK (unchanged).

### CATAPULT-2026-0003 — Composite claim pool factories caused UB on destruction

- **Severity:** Critical (memory safety).
- **Affected:** all versions before 1.3.0 that used
  `composite_utils::createOrComposite` / `createAndComposite` /
  `createNorComposite` (and the `*FromTokens` variants) with `usePool=true`.
- **Description:** The pool-backed paths released memory owned by a
  thread-local memory pool into a `std::unique_ptr` with the default
  deleter. On destruction the default deleter called `delete` on storage the
  global allocator had never allocated — undefined behavior, and in
  practice a heap corruption vector.
- **Remediation:** the `usePool` argument is now a no-op. All six
  factories unconditionally use standard allocation and emit a warning log
  if `usePool=true` was passed. Full pool support will return once the
  ownership model is rewritten (`catapult_analysis.md` task #24).

## Related remediation

Phase 0 also closed:

- **H-01** — the 60-second time-leeway default on `CatTokenValidator` has
  been removed. Callers who need a non-zero leeway must set it explicitly
  via `withClockSkewTolerance()` and document the operational reason.
- **H-02** — encoded CWT tokens larger than 4096 bytes are rejected before
  any base64/CBOR/crypto work, matching CTA-5007-B §4.3.1.
- **C-05** — the CWT payload decoder no longer silently repairs malformed
  known claims. Type errors on `iss`, `aud`, `exp`, `nbf`, `cti`,
  `catreplay`, `catpor`, `catv`, `catu`, `catgeocoord`, `geohash`, `sub`,
  `iat`, `catifdata`, `cnf`, `catdpop`, and every element inside `moqt`
  now cause the whole token to be rejected. Unregistered claim ids are
  logged and ignored per CTA-5007-B §4.5.

See `catapult_analysis.md` for the outstanding Phase 1–4 items that block
production deployment.
