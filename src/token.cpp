#include "catapult/token.hpp"

#include <cctype>
#include <chrono>
#include <sstream>

#include "catapult/claims.hpp"
#include "catapult/composite_impl.hpp"
#include "catapult/cwt.hpp"
#include "catapult/internal/parse_limits.hpp"
#include "catapult/logging.hpp"
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
    if (__builtin_add_overflow(exp, clockSkewTolerance_, &exp_deadline)) {
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
    if (__builtin_sub_overflow(nbf, clockSkewTolerance_, &nbf_floor)) {
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
  validateUsageLimits(token);
  validateCompositeClaims(token);
  validateMoqtRevalidation(token, now);
}

// CAT-4-MOQT (draft-jennings-moq-cat-04): if `moqt-reval` is present the
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
  if (__builtin_add_overflow(iat, reval, &deadline)) {
    throw InvalidClaimValueError(
        "'iat + moqt-reval' overflows int64_t");
  }
  // Apply the operator-configured clock skew tolerance in the same
  // direction as `exp`: extend the acceptance window forward. Overflow
  // here is again treated as invalid rather than wrapping.
  int64_t deadline_with_skew;
  if (__builtin_add_overflow(deadline, clockSkewTolerance_,
                             &deadline_with_skew)) {
    throw InvalidClaimValueError(
        "'iat + moqt-reval + skew' overflows int64_t");
  }
  if (now_epoch_seconds > deadline_with_skew) {
    throw TokenRevalidationRequiredError();
  }
}

void CatTokenValidator::validateGeographicRestrictions(
    const CatToken& token) const {
  if (token.cat.catgeocoord) {
    const auto& coords = *token.cat.catgeocoord;

    // Use runtime validation that matches the compile-time checks
    if (coords.lat < -90.0 || coords.lat > 90.0 || coords.lon < -180.0 ||
        coords.lon > 180.0) {
      throw GeographicValidationError("Invalid coordinates");
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
      for (const auto& s : gh.asArray()) {
        validate(s);
      }
    }
  }
}

void CatTokenValidator::validateUsageLimits(const CatToken& token) const {
  // Placeholder for usage limit validation
  // In a real implementation, this would check against a usage tracking system
}

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

#ifdef CATAPULT_ENABLE_LEGACY_JWT_TOKEN
namespace legacy {

std::string legacyJwtEncodeToken(const CatToken& token,
                                 CryptographicAlgorithm& algorithm) {
  CAT_LOG_DEBUG("Encoding legacy JWT-shaped CAT token with algorithm ID: {}",
                algorithm.algorithmId());
  Cwt cwt(algorithm.algorithmId(), token);

  // NOTE: This header is a JSON string, not CBOR, despite historical variable
  // names. The legacy format is intentionally non-standard; do not use for
  // interoperable CAT deployments.
  std::vector<uint8_t> headerBytes;
  std::ostringstream headerStream;
  headerStream << "{\"alg\":" << algorithm.algorithmId() << ",\"typ\":\"CAT\"}";
  std::string headerStr = headerStream.str();
  headerBytes.assign(headerStr.begin(), headerStr.end());

  auto payloadCbor = cwt.encodePayload();
  auto signingInput = createJwtSigningInput(headerBytes, payloadCbor);
  auto signature = algorithm.sign(signingInput);

  auto headerB64 = base64UrlEncode(headerBytes);
  auto payloadB64 = base64UrlEncode(payloadCbor);
  auto signatureB64 = base64UrlEncode(signature);

  return headerB64 + "." + payloadB64 + "." + signatureB64;
}

CatToken legacyJwtDecodeToken(const std::string& tokenStr,
                              CryptographicAlgorithm& algorithm) {
  CAT_LOG_DEBUG("Decoding legacy JWT-shaped CAT token with algorithm ID: {}",
                algorithm.algorithmId());
  // Bound attacker-controlled input before spending any parsing budget.
  // The legacy format is dot-separated base64 so the encoded ceiling is a
  // safe upper bound for the whole string.
  if (tokenStr.size() > internal::kMaxEncodedTokenBytes) {
    CAT_LOG_ERROR("Legacy JWT-shaped token exceeds maximum ({} > {})",
                  tokenStr.size(), internal::kMaxEncodedTokenBytes);
    throw InvalidTokenFormatError();
  }
  std::vector<std::string> parts;
  std::stringstream ss(tokenStr);
  std::string part;

  while (std::getline(ss, part, '.')) {
    parts.push_back(part);
  }

  if (parts.size() != 3) {
    CAT_LOG_ERROR("Invalid legacy token format: expected 3 parts, got {}",
                  parts.size());
    throw InvalidTokenFormatError();
  }

  auto headerBytes = base64UrlDecode(parts[0]);
  auto payloadCbor = base64UrlDecode(parts[1]);
  auto signature = base64UrlDecode(parts[2]);

  auto signingInput = createJwtSigningInput(headerBytes, payloadCbor);
  if (!algorithm.verify(signingInput, signature)) {
    throw SignatureVerificationError();
  }

  return Cwt::decodePayload(payloadCbor);
}

}  // namespace legacy
#endif  // CATAPULT_ENABLE_LEGACY_JWT_TOKEN

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