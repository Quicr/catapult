#include "catapult/token.hpp"
#include "catapult/composite_impl.hpp"
#include "catapult/claims.hpp"
#include "catapult/validator.hpp"
#include "catapult/logging.hpp"

#include <chrono>
#include <sstream>

#include "catapult/cwt.hpp"

namespace catapult {


CatTokenValidator::CatTokenValidator() : clockSkewTolerance_(60) {}

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
  clockSkewTolerance_ = toleranceSeconds;
  return *this;
}

/**
 * @brief Template-based claim validation helper
 */
template<typename ClaimType>
consteval void validate_single_claim() {
  static_assert(ClaimType::value > 0 && ClaimType::value <= 65535, 
                "Invalid claim identifier");
  static_assert(composite_constants::is_valid_claim_id(ClaimType::value),
                "Claim not validated by composite constants");
}

template<typename... ClaimTypes>
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

  // Check expiration
  if (token.core.exp) {
    if (now > *token.core.exp + clockSkewTolerance_) {
      throw TokenExpiredError();
    }
  }

  // Check not before
  if (token.core.nbf) {
    if (now < *token.core.nbf - clockSkewTolerance_) {
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
}

void CatTokenValidator::validateGeographicRestrictions(
    const CatToken& token) const {
  if (token.cat.catgeocoord) {
    const auto& coords = *token.cat.catgeocoord;
    
    // Use runtime validation that matches the compile-time checks
    if (coords.lat < -90.0 || coords.lat > 90.0 || 
        coords.lon < -180.0 || coords.lon > 180.0) {
      throw GeographicValidationError("Invalid coordinates");
    }
  }

  if (token.cat.geohash) {
    const auto& geohash = *token.cat.geohash;
    if (geohash.empty() || geohash.length() > 12) {
      throw GeographicValidationError("Invalid geohash");
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
      if (claim.has_value() && (*claim) && (*claim)->getDepth() > composite_constants::MAX_NESTING_DEPTH) {
        throw InvalidClaimValueError("Composite claim nesting depth exceeds maximum");
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

bool CatTokenValidator::validateTypedOrClaim(const OrClaim& orClaim) const {
  return validateTypedCompositeClaim(orClaim, *this);
}

bool CatTokenValidator::validateTypedAndClaim(const AndClaim& andClaim) const {
  return validateTypedCompositeClaim(andClaim, *this);
}

bool CatTokenValidator::validateTypedNorClaim(const NorClaim& norClaim) const {
  return validateTypedCompositeClaim(norClaim, *this);
}

CatToken createMinimalToken(const std::string& issuer, const std::string& audience) {
  CatToken token;
  token.core.iss = issuer;
  token.core.aud = std::vector<std::string>{audience};
  return token;
}

std::string encodeToken(const CatToken& token,
                        CryptographicAlgorithm& algorithm) {
  CAT_LOG_DEBUG("Encoding CAT token with algorithm ID: {}", algorithm.algorithmId());
  Cwt cwt(algorithm.algorithmId(), token);

  // Create header CBOR
  std::vector<uint8_t> headerCbor;
  // Simplified header creation - in real implementation would use libcbor
  std::ostringstream headerStream;
  headerStream << "{\"alg\":" << algorithm.algorithmId() << ",\"typ\":\"CAT\"}";
  std::string headerStr = headerStream.str();
  headerCbor.assign(headerStr.begin(), headerStr.end());

  // Encode payload
  auto payloadCbor = cwt.encodePayload();

  // Create JWT-style signing input for legacy token format
  auto signingInput = createJwtSigningInput(headerCbor, payloadCbor);

  // Sign
  auto signature = algorithm.sign(signingInput);

  // Base64URL encode components
  auto headerB64 = base64UrlEncode(headerCbor);
  auto payloadB64 = base64UrlEncode(payloadCbor);
  auto signatureB64 = base64UrlEncode(signature);

  return headerB64 + "." + payloadB64 + "." + signatureB64;
}

CatToken decodeToken(const std::string& tokenStr,
                     CryptographicAlgorithm& algorithm) {
  CAT_LOG_DEBUG("Decoding CAT token with algorithm ID: {}", algorithm.algorithmId());
  // Split token
  std::vector<std::string> parts;
  std::stringstream ss(tokenStr);
  std::string part;

  while (std::getline(ss, part, '.')) {
    parts.push_back(part);
  }

  if (parts.size() != 3) {
    CAT_LOG_ERROR("Invalid token format: expected 3 parts, got {}", parts.size());
    throw InvalidTokenFormatError();
  }

  // Decode components
  auto headerCbor = base64UrlDecode(parts[0]);
  auto payloadCbor = base64UrlDecode(parts[1]);
  auto signature = base64UrlDecode(parts[2]);

  // Verify JWT-style signature for legacy token format
  auto signingInput = createJwtSigningInput(headerCbor, payloadCbor);
  if (!algorithm.verify(signingInput, signature)) {
    throw SignatureVerificationError();
  }

  // Decode payload
  return Cwt::decodePayload(payloadCbor);
}

// Explicit template instantiations for composite claims with CatTokenValidator
template bool CompositeClaims::validateAll<CatTokenValidator>(const CatTokenValidator& validator) const;
template bool OrClaim::evaluateClaimSet<CatTokenValidator>(const ClaimSet& claimSet, const CatTokenValidator& validator) const;
template bool AndClaim::evaluateClaimSet<CatTokenValidator>(const ClaimSet& claimSet, const CatTokenValidator& validator) const;
template bool NorClaim::evaluateClaimSet<CatTokenValidator>(const ClaimSet& claimSet, const CatTokenValidator& validator) const;

}  // namespace catapult