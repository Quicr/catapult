/**
 * @file cat_validator.hpp
 * @brief Token validation and encoding/decoding functionality
 */

#pragma once

#include <algorithm>
#include <chrono>
#include <ranges>
#include <unordered_set>

#include "crypto.hpp"
#include "error.hpp"
#include "token.hpp"

namespace catapult {

// Forward declarations
class CatToken;

/**
 * @brief Validator for CAT tokens with configurable validation rules
 */
class CatTokenValidator {
 private:
  std::optional<std::unordered_set<std::string>>
      expectedIssuers_;  ///< Expected token issuers
  std::optional<std::unordered_set<std::string>>
      expectedAudiences_;       ///< Expected token audiences
  int64_t clockSkewTolerance_;  ///< Clock skew tolerance in seconds

 public:
  /**
   * @brief Construct a validator with default settings
   */
  CatTokenValidator();

  /**
   * @brief Set expected token issuers
   * @param issuers List of valid issuers
   * @return Reference to this validator for chaining
   */
  CatTokenValidator& withExpectedIssuers(
      const std::vector<std::string>& issuers);

  /**
   * @brief Set expected token audiences
   * @param audiences List of valid audiences
   * @return Reference to this validator for chaining
   */
  CatTokenValidator& withExpectedAudiences(
      const std::vector<std::string>& audiences);

  /**
   * @brief Set clock skew tolerance
   * @param toleranceSeconds Tolerance in seconds
   * @return Reference to this validator for chaining
   */
  CatTokenValidator& withClockSkewTolerance(int64_t toleranceSeconds);

  /**
   * @brief Validate a CAT token
   * @param token Token to validate
   * @throws Various CatError subclasses on validation failure
   */
  void validate(const CatToken& token) const;

  /**
   * @brief Validate multiple typed composite claims using CompositeClaimType
   * concept
   * @tparam T The composite claim type that satisfies CompositeClaimType
   * @param claims Vector of typed composite claims to validate
   * @return true if all claims are valid
   */
  template <CompositeClaimType T>
  bool validateTypedComposites(const std::vector<T>& claims) const;

  /**
   * @brief Validate a typed OR composite claim
   * @param orClaim The OR composite claim to validate
   * @return true if the claim is valid
   */
  bool validateTypedOrClaim(const OrClaim& orClaim) const;

  /**
   * @brief Validate a typed AND composite claim
   * @param andClaim The AND composite claim to validate
   * @return true if the claim is valid
   */
  bool validateTypedAndClaim(const AndClaim& andClaim) const;

  /**
   * @brief Validate a typed NOR composite claim
   * @param norClaim The NOR composite claim to validate
   * @return true if the claim is valid
   */
  bool validateTypedNorClaim(const NorClaim& norClaim) const;

 private:
  void validateGeographicRestrictions(const CatToken& token) const;
  void validateUsageLimits(const CatToken& token) const;
  void validateCompositeClaims(const CatToken& token) const;
};

/**
 * @brief Encode a CAT token to string format
 * @param token Token to encode
 * @param algorithm Cryptographic algorithm for signing
 * @return Encoded token string
 */
std::string encodeToken(const CatToken& token,
                        CryptographicAlgorithm& algorithm);

/**
 * @brief Decode and verify a CAT token from string format
 * @param tokenStr Encoded token string
 * @param algorithm Cryptographic algorithm for verification
 * @return Decoded and verified token
 * @throws SignatureVerificationError if verification fails
 */
CatToken decodeToken(const std::string& tokenStr,
                     CryptographicAlgorithm& algorithm);

/**
 * @brief Create a minimal valid token using token factory utilities
 * @param issuer The token issuer
 * @param audience The token audience
 * @return A minimal valid CatToken
 */
CatToken createMinimalToken(const std::string& issuer,
                            const std::string& audience);

/**
 * @brief Create typed composite claims using factory utilities
 * @tparam Op The composite operator (OR, AND, NOR)
 * @param tokens Vector of tokens to include in the composite
 * @return A typed composite claim
 */
template <CompositeOperator Op>
  requires(is_valid_operator<Op>())
TypedCompositeClaim<Op> createTypedComposite(
    const std::vector<CatToken>& tokens);

/**
 * @brief Validate a typed composite claim using the CompositeClaimType concept
 * @tparam T The composite claim type that satisfies CompositeClaimType
 * @tparam Validator The validator type that satisfies TokenValidator
 * @param compositeClaim The composite claim to validate
 * @param validator The validator to use for individual token validation
 * @return true if the composite claim is valid and all its tokens pass
 * validation
 */
template <CompositeClaimType T, TokenValidator Validator>
bool validateTypedCompositeClaim(const T& compositeClaim,
                                 const Validator& validator);

// Template implementation
template <CompositeClaimType T, TokenValidator Validator>
bool validateTypedCompositeClaim(const T& compositeClaim,
                                 const Validator& validator) {
  // First validate the depth using the concept
  if (!composite_utils::validateDepth(compositeClaim)) {
    throw InvalidClaimValueError(
        "Typed composite claim exceeds maximum nesting depth");
  }

  // Then validate the composite claim itself
  return compositeClaim.evaluate(validator);
}

// CatTokenValidator template method implementation
template <CompositeClaimType T>
bool CatTokenValidator::validateTypedComposites(
    const std::vector<T>& claims) const {
  return std::ranges::all_of(claims, [this](const T& claim) {
    try {
      return validateTypedCompositeClaim(claim, *this);
    } catch (const CatError&) {
      return false;
    }
  });
}

// Template implementations for factory functions

template <CompositeOperator Op>
  requires(is_valid_operator<Op>())
TypedCompositeClaim<Op> createTypedComposite(
    const std::vector<CatToken>& tokens) {
  TypedCompositeClaim<Op> composite;
  for (const auto& token : tokens) {
    composite.addToken(token);
  }

  // Compile-time validation of depth
  if constexpr (composite_constants::ENABLE_DEPTH_VALIDATION) {
    if (!composite.isDepthValid()) {
      throw InvalidClaimValueError(
          "Composite claim exceeds maximum nesting depth");
    }
  }

  return composite;
}

}  // namespace catapult