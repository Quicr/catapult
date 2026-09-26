#include "catapult/token.hpp"

#include <cctype>
#include <chrono>
#include <cmath>
#include <sstream>

#include "catapult/claims.hpp"
#include "catapult/composite_impl.hpp"
#include "catapult/cwt.hpp"
#include "catapult/internal/parse_limits.hpp"
#include "catapult/internal/safe_arith.hpp"
#include "catapult/logging.hpp"
// This translation unit defines the legacy JWT-shaped API when the build
// option is enabled; opt into the acknowledgement macro so the
// declarations in validator.hpp are visible here.
#define CATAPULT_LEGACY_JWT_ACKNOWLEDGE_INSECURE 1
#include "catapult/validator.hpp"

namespace catapult {

// CTA-5007-B §4.6.3–4.6.4: recipients MUST NOT permit leeway when validating
// `exp` and `nbf`. Default tolerance is zero; callers who need a non-zero
// tolerance must set it explicitly via withClockSkewTolerance() and must
// document the operational reason.
CatTokenValidator::CatTokenValidator() : clockSkewTolerance_(0) {}

CatTokenValidator& CatTokenValidator::withExpectedIssuers(
    const std::vector<std::string>& issuers) {
  expectedIssuers_ =
      std::unordered_set<std::string>(issuers.begin(), issuers.end());
  return *this;
}

CatTokenValidator& CatTokenValidator::withExpectedAudiences(
    const std::vector<std::string>& audiences) {
  expectedAudiences_ =
      std::unordered_set<std::string>(audiences.begin(), audiences.end());
  return *this;
}

CatTokenValidator& CatTokenValidator::withClockSkewTolerance(
    int64_t toleranceSeconds) {
  if (toleranceSeconds < 0) {
    throw InvalidClaimValueError("Clock skew tolerance must be non-negative");
  }
  clockSkewTolerance_ = toleranceSeconds;
  return *this;
}

CatTokenValidator& CatTokenValidator::withRevalidationCallback(
    RevalidationCallback* callback) {
  revalidation_callback_ = callback;
  return *this;
}

CatTokenValidator& CatTokenValidator::withUsageStateHook(
    UsageStateHook* hook) {
  usage_state_ = hook;
  return *this;
}

CatTokenValidator& CatTokenValidator::withAuthorizationPolicy(
    AuthorizationPolicyHook* hook) {
  authz_policy_ = hook;
  return *this;
}

CatTokenValidator& CatTokenValidator::withRequiredContextFields(
    RequiredPolicyContextFields fields) {
  required_context_fields_ = fields;
  return *this;
}

CatTokenValidator& CatTokenValidator::withMoqtScopeContextOptional(
    bool optional) {
  moqt_scope_context_optional_ = optional;
  return *this;
}

/**
 * @brief Template-based claim validation helper
 */
template <typename ClaimType>
consteval void validate_single_claim() {
  static_assert(ClaimType::value > 0 && ClaimType::value <= 65535,
                "Invalid claim identifier");
  static_assert(composite_constants::is_valid_claim_id(ClaimType::value),
                "Claim not validated by composite constants");
}

template <typename... ClaimTypes>
consteval void validate_claims() {
  static_assert(sizeof...(ClaimTypes) > 0, "At least one claim type required");
  (validate_single_claim<ClaimTypes>(), ...);
}

void CatTokenValidator::validate(const CatToken& token) const {
  validate(token, PolicyContext{});
}

void CatTokenValidator::validate(const CatToken& token,
                                 const PolicyContext& context) const {
  CAT_LOG_DEBUG("Starting token validation");

  // Compile-time validation of all claim types used in validation
  using namespace claim_validation;
  validate_claims<IssuerClaim, AudienceClaim, ExpirationClaim, NotBeforeClaim,
                  CwtIdClaim, CatUsageClaim, CatVersionClaim>();

  // Additional registry validation
  static_assert(StandardClaimRegistry::is_valid_id(ExpirationClaim::value),
                "ExpirationClaim not in standard registry");
  static_assert(StandardClaimRegistry::is_valid_id(NotBeforeClaim::value),
                "NotBeforeClaim not in standard registry");

  auto now = std::chrono::duration_cast<std::chrono::seconds>(
                 std::chrono::system_clock::now().time_since_epoch())
                 .count();

  // Cross-claim relationship: nbf must not exceed exp.
  if (token.core.exp && token.core.nbf &&
      *token.core.nbf > *token.core.exp) {
    throw InvalidClaimValueError(
        "Token 'nbf' is after 'exp' — token is uninhabitable");
  }

  // Check expiration. Guard the tolerance addition against signed overflow
  // before comparing against `now`.
  if (token.core.exp) {
    const int64_t exp = *token.core.exp;
    int64_t exp_deadline;
    if (internal::addOverflow(exp, clockSkewTolerance_, exp_deadline)) {
      // Overflow implies an implausibly distant future — treat as invalid
      // rather than accept a token whose deadline cannot be represented.
      throw InvalidClaimValueError(
          "'exp' + clock skew tolerance overflows int64_t");
    }
    if (now > exp_deadline) {
      throw TokenExpiredError();
    }
  }

  // Check not before, guarding subtraction against signed overflow.
  if (token.core.nbf) {
    const int64_t nbf = *token.core.nbf;
    int64_t nbf_floor;
    if (internal::subOverflow(nbf, clockSkewTolerance_, nbf_floor)) {
      throw InvalidClaimValueError(
          "'nbf' - clock skew tolerance overflows int64_t");
    }
    if (now < nbf_floor) {
      throw TokenNotYetValidError();
    }
  }

  // Check issuer
  if (expectedIssuers_) {
    if (token.core.iss) {
      if (expectedIssuers_->find(*token.core.iss) == expectedIssuers_->end()) {
        throw InvalidIssuerError();
      }
    } else {
      throw MissingRequiredClaimError("iss");
    }
  }

  // Check audience
  if (expectedAudiences_) {
    if (token.core.aud) {
      bool found = false;
      for (const auto& aud : *token.core.aud) {
        if (expectedAudiences_->find(aud) != expectedAudiences_->end()) {
          found = true;
          break;
        }
      }
      if (!found) {
        throw InvalidAudienceError();
      }
    } else {
      throw MissingRequiredClaimError("aud");
    }
  }

  validateGeographicRestrictions(token);
  validateCompositeClaims(token);
  validateAuthorizationPolicy(token, context);
  validateMoqtRevalidation(token, now);
  validateMoqtScopes(token, context);

  // Usage admission runs LAST — any earlier check can reject the token
  // for reasons that are request-specific (policy hook, MOQT scope,
  // reval deadline). If admission ran before those checks, a token
  // rejected for a request-side reason would still have consumed its
  // one-time `cti`, so the client could never retry with a corrected
  // request. `UsageStateHook::admit` is the single write in this
  // pipeline; deferring it until every read-only check has passed is
  // equivalent to "commit only when everything else succeeded" without
  // needing a two-phase admission API on the hook.
  validateUsageLimits(token);
}

// CAT-4-MOQT (draft-ietf-moq-c4m-01): if `moqt-reval` is present the
// resource server MUST reject the token when
// `iat + moqt-reval < now (adjusted by clock skew tolerance)`. The client
// is then required to obtain a fresh token from the issuer.
//
// Two constraints follow from the draft:
//  - `moqt-reval` is only meaningful when `moqt` scopes are present. That
//    invariant is enforced by the decoder, so we don't re-check it here.
//  - The reval anchor is `iat`. A token that carries `moqt-reval` but
//    omits `iat` cannot be authoritatively measured against the interval,
//    which is exactly the failure mode the reval mechanism exists to
//    prevent — treat this as a required-claim violation.
void CatTokenValidator::validateMoqtRevalidation(
    const CatToken& token, int64_t now_epoch_seconds) const {
  if (!token.extended.hasMoqtClaims()) {
    return;
  }
  const auto* moqt = token.extended.getMoqtClaimsReadOnly();
  auto interval = moqt->getRevalidationInterval();
  if (!interval.has_value()) {
    return;
  }
  if (!token.informational.iat.has_value()) {
    throw MissingRequiredClaimError("iat (required when moqt-reval is set)");
  }
  const int64_t iat = *token.informational.iat;
  const int64_t reval = interval->count();

  // Guard the deadline arithmetic against signed overflow: an issuer that
  // encodes a huge `moqt-reval` should be rejected rather than silently
  // wrapping to a small deadline (which would masquerade as a valid,
  // near-future revalidation window).
  int64_t deadline;
  if (internal::addOverflow(iat, reval, deadline)) {
    throw InvalidClaimValueError(
        "'iat + moqt-reval' overflows int64_t");
  }
  // Apply the operator-configured clock skew tolerance in the same
  // direction as `exp`: extend the acceptance window forward. Overflow
  // here is again treated as invalid rather than wrapping.
  int64_t deadline_with_skew;
  if (internal::addOverflow(deadline, clockSkewTolerance_,
                            deadline_with_skew)) {
    throw InvalidClaimValueError(
        "'iat + moqt-reval + skew' overflows int64_t");
  }
  const bool expired = now_epoch_seconds > deadline_with_skew;

  // Fire the observability hook before the authorization outcome so a
  // callback that queues an async refresh gets the signal even when we
  // are about to throw. `time_to_reval` is signed: negative when we are
  // already past the deadline, so callbacks can distinguish "just now"
  // from "expired long ago".
  if (revalidation_callback_) {
    const int64_t time_to_reval_seconds =
        deadline_with_skew - now_epoch_seconds;
    // `cti` is a bytestring per CTA-5007-B. Callbacks that want to log it
    // are free to encode however they need; we hand it over as-is so we
    // do not paper over non-UTF-8 bytes with lossy conversion.
    std::string_view token_id;
    if (token.core.cti.has_value() && !token.core.cti->empty()) {
      token_id = std::string_view(
          reinterpret_cast<const char*>(token.core.cti->data()),
          token.core.cti->size());
    }
    revalidation_callback_->onRevalidationCheck(
        expired ? RevalidationStatus::Expired : RevalidationStatus::Fresh,
        token_id, iat, std::chrono::seconds(reval),
        std::chrono::seconds(time_to_reval_seconds));
  }

  if (expired) {
    throw TokenRevalidationRequiredError();
  }
}

void CatTokenValidator::validateGeographicRestrictions(
    const CatToken& token) const {
  if (token.cat.catgeocoord) {
    const auto& coords = *token.cat.catgeocoord;

    // NaN / ±Inf must be rejected explicitly. Range comparisons against
    // NaN always yield false, so a plain `< -90 || > 90` bounds check
    // would silently accept a NaN latitude.
    if (!std::isfinite(coords.lat) || !std::isfinite(coords.lon)) {
      throw GeographicValidationError("Non-finite coordinates");
    }
    if (coords.lat < -90.0 || coords.lat > 90.0 || coords.lon < -180.0 ||
        coords.lon > 180.0) {
      throw GeographicValidationError("Invalid coordinates");
    }
    // Radius is metres. A negative or non-finite radius is nonsense; a
    // radius wider than half the Earth's circumference (≈2e7 m) makes the
    // "restriction" meaningless and typically indicates a producer bug or
    // an attempt to bypass geo enforcement by widening the accepted zone
    // beyond the planet.
    if (coords.radius.has_value()) {
      const double r = *coords.radius;
      if (!std::isfinite(r) || r < 0.0 || r > 2.0e7) {
        throw GeographicValidationError("Invalid coordinate radius");
      }
    }
  }

  if (token.cat.catgeoalt) {
    // Altitude in metres. Bounds reflect physical plausibility: below the
    // Mariana Trench (~-11 km) or above the Kármán line + margin (~100
    // km + some) is not a location a resource server would meaningfully
    // gate on and is more likely to indicate a malformed token.
    const auto& alt = *token.cat.catgeoalt;
    if (alt.altitude < -12000 || alt.altitude > 500000) {
      throw GeographicValidationError("Altitude out of plausible range");
    }
    if (alt.deviation.has_value()) {
      const int32_t d = *alt.deviation;
      if (d < 0 || d > 500000) {
        throw GeographicValidationError("Altitude deviation out of range");
      }
    }
  }

  if (token.cat.geohash) {
    static constexpr std::string_view valid_chars =
        "0123456789bcdefghjkmnpqrstuvwxyz";
    auto validate = [&](const std::string& gh) {
      if (gh.empty() || gh.length() > 12) {
        throw GeographicValidationError("Invalid geohash length");
      }
      for (char c : gh) {
        if (valid_chars.find(static_cast<char>(std::tolower(
                static_cast<unsigned char>(c)))) == std::string_view::npos) {
          throw GeographicValidationError("Invalid geohash character");
        }
      }
    };
    const auto& gh = *token.cat.geohash;
    if (gh.isString()) {
      validate(gh.asString());
    } else {
      // Array form: reject an empty array (issuer emitted the structured
      // form but populated nothing — indistinguishable from "no
      // restriction" but wire-forms as one, so the safe interpretation is
      // to reject rather than silently allow everywhere) and cap the
      // number of alternatives to bound validator work.
      const auto& arr = gh.asArray();
      if (arr.empty()) {
        throw GeographicValidationError("Empty geohash array");
      }
      if (arr.size() > 64) {
        throw GeographicValidationError("Too many geohash alternatives");
      }
      for (const auto& s : arr) {
        validate(s);
      }
    }
  }
}

// CTA-5007-B §4.6.9 `catreplay`: enforce one-time (RejectOnReplay) or
// one-time-plus-sticky-revocation (RevokeOnReplay) semantics through an
// installed `UsageStateHook`. Mode `None` is intentionally a no-op — a
// token that opts out of replay protection cannot be "replayed" in a
// sense that a resource server enforces.
//
// Fail-closed contracts:
//  - `RejectOnReplay` / `RevokeOnReplay` require the token to carry a
//    `cti`. Without one there is no stable key to record; admitting
//    without recording would defeat the claim's whole purpose.
//  - Without a hook installed, both non-None modes throw a missing-
//    required-claim style error. Silently downgrading to `None` would
//    let a misconfigured relay believe it was enforcing replay when it
//    was not, which is exactly the failure the claim exists to prevent.
void CatTokenValidator::validateUsageLimits(const CatToken& token) const {
  if (!token.cat.catreplay.has_value()) {
    return;
  }
  const CatReplayMode mode = *token.cat.catreplay;
  if (mode == CatReplayMode::None) {
    return;
  }

  if (!token.core.cti.has_value() || token.core.cti->empty()) {
    throw MissingRequiredClaimError(
        "cti (required when 'catreplay' opts into replay enforcement)");
  }

  if (usage_state_ == nullptr) {
    // No hook installed. Fail closed rather than accept a token that
    // opted into replay enforcement and silently receive none.
    throw ReplayAttackError();
  }

  const auto& cti_bytes = *token.core.cti;
  std::string_view cti_view(
      reinterpret_cast<const char*>(cti_bytes.data()), cti_bytes.size());

  auto now = std::chrono::system_clock::now();
  std::optional<std::chrono::system_clock::time_point> exp_tp;
  if (token.core.exp.has_value()) {
    exp_tp = std::chrono::system_clock::time_point(
        std::chrono::seconds(*token.core.exp));
  }

  const auto result = usage_state_->admit(cti_view, mode, now, exp_tp);
  switch (result) {
    case UsageAdmitResult::Admitted:
      return;
    case UsageAdmitResult::Replay:
    case UsageAdmitResult::Revoked:
      throw ReplayAttackError();
    case UsageAdmitResult::StoreExhausted:
      // Treat exhaustion as replay (fail closed): admitting a token the
      // store could not record would mean the next presentation would
      // also be admitted, silently disabling replay protection under
      // load. Matches the ReplayStore contract for DPoP jti tracking.
      //
      // Exhaustion is a hard incident, not a routine replay — log at
      // ERROR so operators can distinguish it from ordinary replay
      // rejections and page on it. A ReplayAttackError still propagates
      // because from the caller's point of view the token is rejected;
      // the ERROR log is the observability signal that says "your
      // capacity is inadequate for the workload".
      CAT_LOG_ERROR(
          "UsageStateHook::admit returned StoreExhausted for a well-formed "
          "catreplay token — replay protection is failing closed under load. "
          "This is a hard incident: provision a larger backend, plug in a "
          "distributed store, or reduce token issuance rate.");
      throw ReplayAttackError();
  }
  // Exhaustive switch above; keep the compiler happy on -Werror builds.
  throw ReplayAttackError();
}

// CTA-5007-B / draft-ietf-moq-c4m-01: claims whose semantics require
// request context (block-list feed, DPoP presentation, geo policy) are
// enforced through an operator-supplied `AuthorizationPolicyHook`.
//
// Fail-closed contract mirrors `validateUsageLimits`: any of these claims
// present + no hook installed => reject. Silently admitting would let a
// misconfigured relay believe it was enforcing the claim when it was
// not, defeating the purpose of the claim.
//
// Structural sanity for these claims (probability range, non-empty
// identifier, valid geohash characters, geo range bounds) is already
// enforced upstream at decode time; the hook is asked only whether the
// current request context satisfies a token that has already parsed as
// well-formed.
void CatTokenValidator::validateAuthorizationPolicy(
    const CatToken& token, const PolicyContext& context) const {
  const bool has_por = token.cat.catpor.has_value();
  const bool has_catdpop = token.dpop.catdpop.has_value();
  const bool has_catif = token.request.catif.has_value();
  const bool has_catr = token.request.catr.has_value();
  const bool has_geoiso = token.cat.catgeoiso3166.has_value() &&
                          !token.cat.catgeoiso3166->empty();
  const bool has_geohash = token.cat.geohash.has_value();
  const bool has_geoalt = token.cat.catgeoalt.has_value();

  const bool needs_policy = has_por || has_catdpop || has_catif || has_catr ||
                            has_geoiso || has_geohash || has_geoalt;
  if (!needs_policy) {
    return;
  }

  if (authz_policy_ == nullptr) {
    // No policy installed but the token carries a claim that requires
    // one. Fail closed rather than admit unenforced. Callers who want to
    // admit such tokens without semantic checks MUST install
    // `PermissivePolicy` explicitly.
    throw MissingRequiredClaimError(
        "authorization policy hook (token carries semantic claims requiring "
        "operator-supplied enforcement)");
  }

  // Enforce the required-field contract centrally, so a hook that forgets
  // to check its own inputs cannot silently admit unenforced requests.
  // The check fires only when the token actually carries a hook-relevant
  // claim (guarded above by `needs_policy`), so callers can leave the
  // context empty for token-only paths that never touch the hook.
  const auto& req = required_context_fields_;
  if (req.client_id && !context.client_id.has_value()) {
    throw MissingRequiredClaimError("policy context: client_id");
  }
  if (req.client_ip && !context.client_ip.has_value()) {
    throw MissingRequiredClaimError("policy context: client_ip");
  }
  if (req.dpop_proof && context.dpop_proof == nullptr) {
    throw MissingRequiredClaimError("policy context: dpop_proof");
  }
  if (req.moqt_action && !context.moqt_action.has_value()) {
    throw MissingRequiredClaimError("policy context: moqt_action");
  }
  if (req.moqt_namespace && !context.moqt_namespace.has_value()) {
    throw MissingRequiredClaimError("policy context: moqt_namespace");
  }
  if (req.moqt_track && !context.moqt_track.has_value()) {
    throw MissingRequiredClaimError("policy context: moqt_track");
  }
  if (req.request_time && !context.request_time.has_value()) {
    throw MissingRequiredClaimError("policy context: request_time");
  }
  if (req.session_id && !context.session_id.has_value()) {
    throw MissingRequiredClaimError("policy context: session_id");
  }

  if (has_por &&
      !authz_policy_->acceptProofOfPossession(*token.cat.catpor, context)) {
    throw InvalidClaimValueError("catpor rejected by authorization policy");
  }
  if (has_catdpop &&
      !authz_policy_->acceptDpopBinding(*token.dpop.catdpop, context)) {
    throw InvalidClaimValueError("catdpop rejected by authorization policy");
  }
  if (has_catif && !authz_policy_->acceptRequestDirective(
                       "catif", *token.request.catif, context)) {
    throw InvalidClaimValueError("catif rejected by authorization policy");
  }
  if (has_catr && !authz_policy_->acceptRequestDirective(
                      "catr", *token.request.catr, context)) {
    throw InvalidClaimValueError("catr rejected by authorization policy");
  }
  if (has_geoiso &&
      !authz_policy_->acceptGeoIso3166(*token.cat.catgeoiso3166, context)) {
    throw GeographicValidationError(
        "catgeoiso3166 rejected by authorization policy");
  }
  if (has_geohash &&
      !authz_policy_->acceptGeohash(*token.cat.geohash, context)) {
    throw GeographicValidationError(
        "geohash rejected by authorization policy");
  }
  if (has_geoalt &&
      !authz_policy_->acceptGeoAltitude(*token.cat.catgeoalt, context)) {
    throw GeographicValidationError(
        "catgeoalt rejected by authorization policy");
  }
}

// CAT-4-MOQT (draft-ietf-moq-c4m-01): a token that carries `moqt` scopes
// declares which (action, namespace, track) tuples the bearer is
// authorized for. Enforcement is fail-closed: if the token has scopes,
// the caller MUST supply the complete request tuple on the
// `PolicyContext` so the scopes can be evaluated against a concrete
// request. A missing or partial tuple is `MissingRequiredClaimError` —
// otherwise a `validate(token)` call with empty context would silently
// admit a scoped token without ever comparing the requested flow to its
// scopes (P1 finding in `PRODUCTION_READINESS_AUDIT.md`).
//
// A non-MOQT integration that deliberately accepts scoped tokens without
// tuple enforcement opts out via `withMoqtScopeContextOptional(true)`.
// That is an explicit, auditable choice; production MOQT relays MUST
// leave the default in place.
//
// When the tuple is present, at least one scope must return true from
// `isAuthorized`; otherwise the bearer is out of scope for this request
// and the validator rejects.
void CatTokenValidator::validateMoqtScopes(
    const CatToken& token, const PolicyContext& context) const {
  if (!token.extended.hasMoqtClaims()) {
    return;
  }
  const bool tuple_complete = context.moqt_action.has_value() &&
                              context.moqt_namespace.has_value() &&
                              context.moqt_track.has_value();
  if (!tuple_complete) {
    if (moqt_scope_context_optional_) {
      return;
    }
    if (!context.moqt_action.has_value()) {
      throw MissingRequiredClaimError(
          "policy context: moqt_action (required by MOQT-scoped token)");
    }
    if (!context.moqt_namespace.has_value()) {
      throw MissingRequiredClaimError(
          "policy context: moqt_namespace (required by MOQT-scoped token)");
    }
    throw MissingRequiredClaimError(
        "policy context: moqt_track (required by MOQT-scoped token)");
  }
  const auto* moqt = token.extended.getMoqtClaimsReadOnly();
  if (moqt == nullptr) {
    return;
  }
  const bool authorized = moqt->isAuthorized(*context.moqt_action,
                                             *context.moqt_namespace,
                                             *context.moqt_track);
  if (!authorized) {
    throw InvalidClaimValueError(
        "MOQT scopes do not authorize the requested action/namespace/track");
  }
}

// draft-ietf-moq-c4m-01 §"MOQT Revalidation Claim": `moqt-reval` MUST NOT
// appear inside a composite (OR / AND / NOR) claim; when it does, the
// token is not well-formed. Walk every nested ClaimSet reachable from
// this token and reject if any of them carries `moqt-reval`, so a hostile
// or misconfigured issuer cannot smuggle a reval interval through a
// composite branch that we would otherwise accept purely on its
// authorization outcome.
namespace {
void assertNoMoqtRevalInClaimSet(const ClaimSet& claim_set);

template <CompositeOperator Op>
void assertNoMoqtRevalInComposite(const TypedCompositeClaim<Op>& composite) {
  for (const auto& cs : composite.claims) {
    assertNoMoqtRevalInClaimSet(cs);
  }
}

void assertNoMoqtRevalInClaimSet(const ClaimSet& claim_set) {
  if (claim_set.hasToken()) {
    const auto* moqt = claim_set.token->extended.getMoqtClaimsReadOnly();
    if (moqt && moqt->getRevalidationInterval().has_value()) {
      throw InvalidClaimValueError(
          "'moqt-reval' MUST NOT appear inside a composite claim");
    }
    return;
  }
  if (claim_set.orComposite) {
    assertNoMoqtRevalInComposite(*claim_set.orComposite);
  } else if (claim_set.andComposite) {
    assertNoMoqtRevalInComposite(*claim_set.andComposite);
  } else if (claim_set.norComposite) {
    assertNoMoqtRevalInComposite(*claim_set.norComposite);
  }
}
}  // namespace

void CatTokenValidator::validateCompositeClaims(const CatToken& token) const {
  if (token.composite.hasComposites()) {
    // Check nesting depth limit using the provided utility
    auto checkDepth = [](const auto& claim) {
      if (claim.has_value() && (*claim) &&
          (*claim)->getDepth() > composite_constants::MAX_NESTING_DEPTH) {
        throw InvalidClaimValueError(
            "Composite claim nesting depth exceeds maximum");
      }
    };

    checkDepth(token.composite.orClaim);
    checkDepth(token.composite.norClaim);
    checkDepth(token.composite.andClaim);

    if (token.composite.orClaim && *token.composite.orClaim) {
      assertNoMoqtRevalInComposite(**token.composite.orClaim);
    }
    if (token.composite.norClaim && *token.composite.norClaim) {
      assertNoMoqtRevalInComposite(**token.composite.norClaim);
    }
    if (token.composite.andClaim && *token.composite.andClaim) {
      assertNoMoqtRevalInComposite(**token.composite.andClaim);
    }

    // Validate all composite claims using the TokenValidator concept
    if (!token.composite.validateAll(*this)) {
      throw InvalidClaimValueError("Composite claim validation failed");
    }
  }
}

ValidatedCatToken CatTokenValidator::intoValidated(CatToken token) const {
  // Run every semantic check first. If validate() throws, `token` is
  // destroyed with the exception and no ValidatedCatToken is produced —
  // callers cannot observe partially-validated state.
  validate(token);
  return ValidatedCatToken(std::move(token));
}

CatErrorCode CatTokenValidator::tryValidate(const CatToken& token) const noexcept {
  return tryValidate(token, PolicyContext{});
}

CatErrorCode CatTokenValidator::tryValidate(
    const CatToken& token, const PolicyContext& context) const noexcept {
  try {
    validate(token, context);
    return CatErrorCode::SUCCESS;
  } catch (const CatError& e) {
    return e.errorCode();
  } catch (...) {
    // A non-CatError escape from validate() would be a bug: every
    // internal failure mode is expected to map to a CatError subclass.
    // Fall back to a generic "invalid claim" code so the caller still
    // fails closed rather than propagating an unknown exception.
    return CatErrorCode::INVALID_CLAIM_VALUE;
  }
}

Result<ValidatedCatToken, CatErrorCode>
CatTokenValidator::tryIntoValidated(CatToken token) const noexcept {
  auto code = tryValidate(token);
  if (code != CatErrorCode::SUCCESS) {
    return Result<ValidatedCatToken, CatErrorCode>::error(code);
  }
  return Result<ValidatedCatToken, CatErrorCode>::success(
      ValidatedCatToken(std::move(token)));
}

bool CatTokenValidator::validateTypedOrClaim(const OrClaim& orClaim) const {
  return validateTypedCompositeClaim(orClaim, *this);
}

bool CatTokenValidator::validateTypedAndClaim(const AndClaim& andClaim) const {
  return validateTypedCompositeClaim(andClaim, *this);
}

bool CatTokenValidator::validateTypedNorClaim(const NorClaim& norClaim) const {
  return validateTypedCompositeClaim(norClaim, *this);
}

CatToken createMinimalToken(const std::string& issuer,
                            const std::string& audience) {
  CatToken token;
  token.core.iss = issuer;
  token.core.aud = std::vector<std::string>{audience};
  return token;
}

// Explicit template instantiations for composite claims with CatTokenValidator
template bool CompositeClaims::validateAll<CatTokenValidator>(
    const CatTokenValidator& validator) const;
template bool OrClaim::evaluateClaimSet<CatTokenValidator>(
    const ClaimSet& claimSet, const CatTokenValidator& validator) const;
template bool AndClaim::evaluateClaimSet<CatTokenValidator>(
    const ClaimSet& claimSet, const CatTokenValidator& validator) const;
template bool NorClaim::evaluateClaimSet<CatTokenValidator>(
    const ClaimSet& claimSet, const CatTokenValidator& validator) const;

}  // namespace catapult