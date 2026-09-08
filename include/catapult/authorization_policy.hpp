/**
 * @file authorization_policy.hpp
 * @brief Pluggable operator-supplied authorization policy hook for CAT
 *        semantic-claim enforcement.
 *
 * `CatTokenValidator` can decide whether a token is *structurally* well
 * formed and whether its temporal / issuer / audience / replay claims hold.
 * It cannot decide the semantic questions that a real deployment must
 * enforce — those depend on request context (client IP, DPoP key,
 * revocation feeds, geo policy) that the library never sees:
 *
 *   - `catpor` (proof-of-possession): does the resource server have a live
 *     block-list check for `identifier`, and should this request be sampled
 *     against it (given `probability`)?
 *   - `catdpop`: has a DPoP proof been presented and validated against the
 *     window declared in the token?
 *   - `catif` / `catr`: does the requesting interface / renewal directive
 *     match what the relay knows about this session?
 *   - `catgeoiso3166` / `geohash` / `catgeoalt`: is the requester in one of
 *     the permitted regions?
 *
 * `AuthorizationPolicyHook` is the seam. When a token carries any of these
 * claims, `CatTokenValidator` MUST NOT admit it unless an operator-supplied
 * policy has explicitly said "yes". Without a policy installed the
 * validator fails closed — silently ignoring an enforcement-carrying claim
 * would let a misconfigured relay believe it was enforcing when it was
 * not, which is exactly the failure mode the claims exist to prevent.
 *
 * @note Callers who genuinely want to admit tokens carrying these claims
 *   without semantic enforcement (test suites, exploratory tooling) can
 *   install `PermissivePolicy` explicitly. That is a deliberate,
 *   auditable choice — not a silent default.
 */

#pragma once

#include <string_view>

#include "claims.hpp"

namespace catapult {

/**
 * @brief Operator-supplied semantic enforcement for CAT claims that the
 *        library cannot enforce from token state alone.
 *
 * Each accept*() method reports whether the corresponding claim's
 * requirement has been satisfied by the current request context. A `false`
 * return causes `CatTokenValidator` to reject the token with the
 * appropriate CatError subclass. Implementations MUST be safe to call
 * concurrently from multiple threads.
 *
 * All accept*() methods are called only when the token actually carries
 * the corresponding claim; a policy authoring a strict-only deployment
 * does not need to worry about "should I return true when the claim is
 * absent?" — that path never reaches the hook.
 */
class AuthorizationPolicyHook {
 public:
  virtual ~AuthorizationPolicyHook() = default;

  /**
   * @brief Decide whether the presented request satisfies the token's
   *        proof-of-possession requirement.
   *
   * A real implementation resolves `por.identifier` against the issuer's
   * block list and, if `por.probability < 1.0`, sample-checks according
   * to that probability. Returning `false` here yields an authorization
   * failure, not a replay/expiry error — the token is intact, its PoP
   * commitment was simply not honoured.
   */
  virtual bool acceptProofOfPossession(const CatProofOfPossession& por) = 0;

  /**
   * @brief Decide whether the requesting client has presented a DPoP
   *        proof consistent with the token's `catdpop` binding.
   *
   * The library validates DPoP proof structure and signatures via
   * `DpopProofValidator`; the semantic tie between "this token expects a
   * DPoP proof with these parameters" and "the current request came with
   * a matching proof" is deployment-specific and lives here.
   */
  virtual bool acceptDpopBinding(const CatDpopSettings& settings) = 0;

  /**
   * @brief Decide whether the request satisfies a request-context
   *        directive (`catif` or `catr`).
   *
   * `claim_name` is `"catif"` or `"catr"` so a single policy can dispatch
   * on which directive is in play. The value is the still-opaque wire
   * bytes; the draft's semantics are not stable enough for the library
   * to attempt structural decoding.
   */
  virtual bool acceptRequestDirective(std::string_view claim_name,
                                      const CatRequestDirective& directive) = 0;

  /**
   * @brief Decide whether the request originates from one of the
   *        permitted ISO 3166 regions.
   */
  virtual bool acceptGeoIso3166(
      const std::vector<std::string>& allowed_codes) = 0;

  /**
   * @brief Decide whether the request's location falls under an allowed
   *        geohash prefix (or array of prefixes).
   */
  virtual bool acceptGeohash(const GeohashClaimValue& allowed) = 0;

  /**
   * @brief Decide whether the request's altitude satisfies the token's
   *        `catgeoalt` restriction.
   */
  virtual bool acceptGeoAltitude(const GeoAltitude& allowed) = 0;
};

/**
 * @brief Default policy that admits every claim it is asked about.
 *
 * Provided as a convenience for tests and for deployments that have
 * consciously decided to disable one or more semantic checks (for
 * example, during a staged rollout where the block-list feed is not yet
 * wired up). Installing this policy is an explicit, auditable choice —
 * it MUST NOT be the default in production.
 */
class PermissivePolicy final : public AuthorizationPolicyHook {
 public:
  bool acceptProofOfPossession(const CatProofOfPossession&) override {
    return true;
  }
  bool acceptDpopBinding(const CatDpopSettings&) override { return true; }
  bool acceptRequestDirective(std::string_view,
                              const CatRequestDirective&) override {
    return true;
  }
  bool acceptGeoIso3166(const std::vector<std::string>&) override {
    return true;
  }
  bool acceptGeohash(const GeohashClaimValue&) override { return true; }
  bool acceptGeoAltitude(const GeoAltitude&) override { return true; }
};

/**
 * @brief Default policy that rejects every claim it is asked about.
 *
 * Provided so a caller who wants a "no semantic claims allowed at all"
 * posture (e.g. an issuance-only environment) can wire that in without
 * writing a bespoke class. `RejectingPolicy` is not what
 * `CatTokenValidator` falls back to when no hook is installed — the
 * validator's fail-closed default throws before it would consult a
 * hook — but it is the right choice when the caller wants to admit a
 * token *only if it does not carry any of these claims*.
 */
class RejectingPolicy final : public AuthorizationPolicyHook {
 public:
  bool acceptProofOfPossession(const CatProofOfPossession&) override {
    return false;
  }
  bool acceptDpopBinding(const CatDpopSettings&) override { return false; }
  bool acceptRequestDirective(std::string_view,
                              const CatRequestDirective&) override {
    return false;
  }
  bool acceptGeoIso3166(const std::vector<std::string>&) override {
    return false;
  }
  bool acceptGeohash(const GeohashClaimValue&) override { return false; }
  bool acceptGeoAltitude(const GeoAltitude&) override { return false; }
};

}  // namespace catapult
