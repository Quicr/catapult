# Standards baseline

This library targets specific published revisions of the following
specifications. Every conformance claim in the codebase is written against
these pinned revisions. When a specification advances, the pin must be
updated deliberately, with an accompanying audit of the deltas — do not
silently follow the latest version.

## Pinned revisions

| Specification | Revision | Source |
|---|---|---|
| CTA-5007-B | Common Access Token (CAT), December 2024 (revised January 2025) | Consumer Technology Association |
| CAT-4-MOQT | `draft-ietf-moq-c4m-01`, 2026-06-18 | IETF datatracker |
| DPoP proof profile | `draft-nandakumar-moq-generic-dpop-proof-00` | IETF datatracker |
| RFC 8152 | CBOR Object Signing and Encryption (COSE) | IETF |
| RFC 8230 | Using RSA Algorithms with COSE Messages | IETF |
| RFC 8392 | CBOR Web Token (CWT) | IETF |
| RFC 8747 | Proof-of-Possession Key Semantics for CWTs | IETF |
| RFC 9052 | COSE Structures and Process (successor to RFC 8152 §§1–7) | IETF (informative only; RFC 8152 remains normative here) |
| RFC 9053 | COSE Initial Algorithms (successor to RFC 8152 §8) | IETF (informative only; RFC 8152 remains normative here) |
| draft-lemmons-cose-composite-claims-01 | Composite claim structure (OR / AND / NOR) | IETF |

The previous `draft-jennings-moq-cat-04` pin (2026-01-13) has been retired.
That draft was superseded by the IETF working document above. The wire
format changed in ways that affect the `moqt` claim, `moqt-reval`, DPoP
profile, and confirmation binding — see the deviations table below for
the parts that are not yet aligned.

## Non-goals

- Following unreleased or "latest" specification working copies. Draft
  identifiers must reference an immutable revision. In particular,
  CAT-4-MOQT is a moving target — the wire format may change between draft
  revisions, so relays and issuers MUST agree on the same draft number.
- Providing a complete relay implementation. Catapult is an embeddable
  library. Relay lifecycle integration — session management, ongoing
  stream revalidation, admission control, observability, and deployment
  packaging — is the responsibility of the embedding application. The
  library exposes hooks for those integration points (`ReplayStore`,
  key resolver, revalidation callback) but does not itself execute the
  relay side of the protocol.

## Known deviations

The following intentional deviations from the pinned revisions exist. Each
carries a security or interoperability rationale and MUST be reviewed
before the next release.

- **CAT-4-MOQT claim identifier (`moqt`, `moqt-reval`)**: `draft-ietf-moq-c4m-01`
  still marks these as `TBD_MOQT` / `TBD_MOQT_REVAL` in the IANA table.
  This implementation allocates `65000` (moqt) and `65001` (reval) in the
  private-use range to remain deployable against the current draft. These
  MUST be replaced with the IANA-assigned identifiers once the draft is
  finalized. Deployments that peer with other implementations MUST agree
  on the same identifiers out of band.
- **CAT-4-MOQT `CONTAINS` match type**: the CDDL admits only `prefix-match`
  (1) and `suffix-match` (2). Legacy `CONTAINS` (type 3) is rejected at
  decode; the enum entry is retained for source compatibility only and
  will be removed in a following release.
- **`moqt-reval` scope**: the draft requires that `moqt-reval` MUST NOT
  appear inside a composite (OR / AND / NOR) claim; when it does, the
  token is not well-formed. This is enforced at decode; a composite
  claimset carrying `moqt-reval` is rejected with `InvalidClaimValueError`.
- **DPoP `actx.action` encoding**: the CAT-4-MOQT DPoP profile carries the
  action as a string (`"SETUP"`, `"PUB_NS"`, `"SUB_NS"`, `"SUBSCRIBE"`,
  `"REQ_UPDATE"`, `"PUBLISH"`, `"FETCH"`, `"TRK_STATUS"`) while the
  `moqt` claim itself uses integer action values (0–8). The library
  serializes JWT DPoP proofs with the string form; the integer form
  remains the internal representation for scope matching.
- **`cnf.jkt` binding**: the confirmation claim uses a 32-byte SHA-256
  JWK thumbprint (RFC 7638). The library computes the thumbprint from
  the canonical JWK when the proof carries a JWK header, and from a
  canonical COSE_Key subset when the proof carries a `COSE_Key`. Both
  paths hash to a 32-byte output.
- **`catreplay`, `catv`, `catpor`, `catnip`, `catu`, `catm`, `catalpn`,
  `cath`, `catgeocoord`, `geohash`, `catgeoalt`, `cnf`, `catdpop`,
  `catifdata`, `catif`, `catr`**: current in-memory representation covers
  wire encode/decode but does not yet execute full semantic enforcement.
  Tracked in remediation plan phase 2 (`catapult_analysis.md`).

## Release policy

- Any change to a pin here is a semver-major event.
- The advisories in `SECURITY.md` cite the pinned revision, not "latest".
- Test vectors under `tests/test_data/` MUST be regenerated whenever a
  pin advances, and the regeneration MUST be reviewed for interop drift.
