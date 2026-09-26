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

#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>

#include "claims.hpp"

namespace catapult {

// Forward declarations kept lightweight so `authorization_policy.hpp` does
// not pull in `dpop.hpp` transitively — a policy implementation only needs
// the DPoP payload structure if it consumes the presented proof.
struct DpopPayload;

/**
 * @brief Request-side context handed to every `AuthorizationPolicyHook`
 *        callback.
 *
 * `AuthorizationPolicyHook` decides whether a token's semantic claim is
 * satisfied by the *current request*, not by the token alone. The library
 * has no privileged view of that request, so it forwards whatever the
 * caller supplies here. Every field is optional: a caller that does not
 * yet know a value passes `std::nullopt`, and a hook must be prepared for
 * that case (a strict hook should reject when a needed field is missing;
 * a permissive hook may ignore it).
 *
 * All string_view / pointer fields must reference storage that outlives
 * the `validate()` call; the context is never copied and never retained
 * past the callback.
 */
struct PolicyContext {
  /**
   * @brief Human-readable client identifier — subject, session id, or
   *        similar. Not necessarily authenticated on its own; treat as a
   *        hint unless the caller documents otherwise.
   */
  std::optional<std::string_view> client_id;

  /**
   * @brief Client network origin (typically the peer IP address as a
   *        printable string; IPv4 dotted-quad or IPv6 textual form).
   */
  std::optional<std::string_view> client_ip;

  /**
   * @brief Presented DPoP proof payload, already parsed and structurally
   *        validated by `DpopProofValidator`. Non-owning; the hook must
   *        not retain the pointer past its callback.
   */
  const DpopPayload* dpop_proof = nullptr;

  /**
   * @brief MOQT action being authorized on this request (see
   *        `moqt_actions::*`), if the caller is in a MOQT context.
   */
  std::optional<int> moqt_action;

  /**
   * @brief MOQT track namespace being addressed, byte-exact.
   */
  std::optional<std::string_view> moqt_namespace;

  /**
   * @brief MOQT track name being addressed, byte-exact.
   */
  std::optional<std::string_view> moqt_track;

  /**
   * @brief Wall-clock time of the request. Callers that want to align
   *        policy decisions with the same `now` used for `exp` / `nbf`
   *        pass the shared timestamp here; hooks that consult external
   *        state may prefer their own clock.
   */
  std::optional<std::chrono::system_clock::time_point> request_time;

  /**
   * @brief Opaque session-scope handle the relay can use to correlate a
   *        policy decision with a persistent session (session id,
   *        connection id, or a hash of them). Non-owning; the hook must
   *        not retain the pointer past the callback.
   *
   * The library never inspects this field; it is a pass-through for
   * operator-supplied policy code that needs to bind a decision to a
   * session-scoped external record (e.g., a DPoP jkt already pinned at
   * connection establishment).
   */
  std::optional<std::string_view> session_id;
};

/**
 * @brief Declares which `PolicyContext` fields the validator will require
 *        callers to populate before invoking the authorization-policy hook.
 *
 * A relay knows which request-side facts its policies depend on: a policy
 * enforcing IP allowlists needs `client_ip`; a policy binding DPoP proofs
 * needs `dpop_proof`; a MOQT-aware policy needs the action/namespace/track
 * triple. Rather than trust each hook implementation to check its own
 * inputs (and silently succeed on unpopulated fields when it forgets), the
 * validator enforces the required-field contract centrally.
 *
 * `validate(token, ctx)` throws `MissingRequiredClaimError` before any
 * `AuthorizationPolicyHook::accept*` callback fires if a required field
 * is missing. Fields not listed here are informational and may be
 * `std::nullopt`; hooks are still free to inspect them.
 */
struct RequiredPolicyContextFields {
  bool client_id = false;
  bool client_ip = false;
  bool dpop_proof = false;
  bool moqt_action = false;
  bool moqt_namespace = false;
  bool moqt_track = false;
  bool request_time = false;
  bool session_id = false;

  /// Convenience: require every field. Suitable for the strictest MOQT
  /// deployments where any missing input is a bug on the caller side.
  [[nodiscard]] static constexpr RequiredPolicyContextFields all() noexcept {
    RequiredPolicyContextFields r;
    r.client_id = true;
    r.client_ip = true;
    r.dpop_proof = true;
    r.moqt_action = true;
    r.moqt_namespace = true;
    r.moqt_track = true;
    r.request_time = true;
    r.session_id = true;
    return r;
  }
};

/**
 * @brief Operator-supplied semantic enforcement for CAT claims that the
 *        library cannot enforce from token state alone.
 *
 * Each accept*() method reports whether the corresponding claim's
 * requirement has been satisfied by the current request context, passed
 * in as a `PolicyContext`. A `false` return causes `CatTokenValidator`
 * to reject the token with the appropriate CatError subclass.
 *
 * All accept*() methods are called only when the token actually carries
 * the corresponding claim; a policy authoring a strict-only deployment
 * does not need to worry about "should I return true when the claim is
 * absent?" — that path never reaches the hook.
 *
 * ## Lifetime and concurrency contract
 *
 * - **Ownership.** `CatTokenValidator` holds a non-owning raw pointer.
 *   The hook MUST outlive every validator that references it.
 * - **Configuration mutation.** `withAuthorizationPolicy()` is NOT safe
 *   to call concurrently with `validate()` on the same validator. Swap
 *   hooks by preparing a new validator or serialising externally.
 * - **Concurrent invocation.** Every accept*() method is called
 *   concurrently from every worker thread when the validator is shared
 *   on a thread pool. Implementations MUST be safe under concurrent
 *   calls; mutable dependencies (blocklists, feature-flag caches) must
 *   be synchronised or immutable.
 * - **Exception behaviour.** The validator does NOT catch exceptions
 *   from an accept*() call; an escaped exception aborts admission and
 *   unwinds through the caller. Prefer returning `false` for policy
 *   failure; reserve exceptions for programmer bugs.
 * - **PolicyContext view lifetimes.** The `PolicyContext` reference and
 *   every field on it are valid only for the duration of the callback.
 *   Do not retain views past return; copy any bytes the hook needs to
 *   keep.
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
  virtual bool acceptProofOfPossession(const CatProofOfPossession& por,
                                       const PolicyContext& ctx) = 0;

  /**
   * @brief Decide whether the requesting client has presented a DPoP
   *        proof consistent with the token's `catdpop` binding.
   *
   * The library validates DPoP proof structure and signatures via
   * `DpopProofValidator`; the semantic tie between "this token expects a
   * DPoP proof with these parameters" and "the current request came with
   * a matching proof" is deployment-specific and lives here.
   */
  virtual bool acceptDpopBinding(const CatDpopSettings& settings,
                                 const PolicyContext& ctx) = 0;

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
                                      const CatRequestDirective& directive,
                                      const PolicyContext& ctx) = 0;

  /**
   * @brief Decide whether the request originates from one of the
   *        permitted ISO 3166 regions.
   */
  virtual bool acceptGeoIso3166(const std::vector<std::string>& allowed_codes,
                                const PolicyContext& ctx) = 0;

  /**
   * @brief Decide whether the request's location falls under an allowed
   *        geohash prefix (or array of prefixes).
   */
  virtual bool acceptGeohash(const GeohashClaimValue& allowed,
                             const PolicyContext& ctx) = 0;

  /**
   * @brief Decide whether the request's altitude satisfies the token's
   *        `catgeoalt` restriction.
   */
  virtual bool acceptGeoAltitude(const GeoAltitude& allowed,
                                 const PolicyContext& ctx) = 0;
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
  bool acceptProofOfPossession(const CatProofOfPossession&,
                               const PolicyContext&) override {
    return true;
  }
  bool acceptDpopBinding(const CatDpopSettings&,
                         const PolicyContext&) override {
    return true;
  }
  bool acceptRequestDirective(std::string_view, const CatRequestDirective&,
                              const PolicyContext&) override {
    return true;
  }
  bool acceptGeoIso3166(const std::vector<std::string>&,
                        const PolicyContext&) override {
    return true;
  }
  bool acceptGeohash(const GeohashClaimValue&,
                     const PolicyContext&) override {
    return true;
  }
  bool acceptGeoAltitude(const GeoAltitude&, const PolicyContext&) override {
    return true;
  }
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
  bool acceptProofOfPossession(const CatProofOfPossession&,
                               const PolicyContext&) override {
    return false;
  }
  bool acceptDpopBinding(const CatDpopSettings&,
                         const PolicyContext&) override {
    return false;
  }
  bool acceptRequestDirective(std::string_view, const CatRequestDirective&,
                              const PolicyContext&) override {
    return false;
  }
  bool acceptGeoIso3166(const std::vector<std::string>&,
                        const PolicyContext&) override {
    return false;
  }
  bool acceptGeohash(const GeohashClaimValue&,
                     const PolicyContext&) override {
    return false;
  }
  bool acceptGeoAltitude(const GeoAltitude&, const PolicyContext&) override {
    return false;
  }
};

}  // namespace catapult
