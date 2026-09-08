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
#include "revalidation_callback.hpp"
#include "token.hpp"
#include "usage_state.hpp"

namespace catapult {

// Forward declarations
class CatToken;
class CatTokenValidator;

/**
 * @brief Immutable, validated view of a CAT token.
 *
 * A `ValidatedCatToken` can only be produced by `CatTokenValidator::intoValidated`,
 * which enforces every semantic check the validator performs. Once
 * constructed, the underlying claims are read-only: callers cannot mutate
 * fields around the checks that were applied.
 *
 * This addresses catapult_analysis M-01: parsed authorization objects must
 * not expose mutable state that lets callers write invalid values after
 * `build()` has done only structural validation. Relay code should prefer
 * this type over passing a mutable `CatToken` around after validation.
 *
 * The token is stored by value, so `ValidatedCatToken` is move-only. It is
 * safe to `const&`-share across threads.
 */
class ValidatedCatToken {
 public:
  ValidatedCatToken(const ValidatedCatToken&) = delete;
  ValidatedCatToken& operator=(const ValidatedCatToken&) = delete;
  ValidatedCatToken(ValidatedCatToken&&) noexcept = default;
  ValidatedCatToken& operator=(ValidatedCatToken&&) noexcept = default;
  ~ValidatedCatToken() = default;

  const CoreClaims& core() const noexcept { return token_.core; }
  const CatClaims& cat() const noexcept { return token_.cat; }
  const InformationalClaims& informational() const noexcept {
    return token_.informational;
  }
  const DpopClaims& dpop() const noexcept { return token_.dpop; }
  const RequestClaims& request() const noexcept { return token_.request; }
  const CompositeClaims& composite() const noexcept { return token_.composite; }
  const ExtendedCatClaims& extended() const noexcept { return token_.extended; }
  const std::unordered_map<int64_t, std::string>& custom() const noexcept {
    return token_.custom;
  }

  /**
   * @brief Access the underlying `CatToken` as an immutable reference.
   *
   * Retained for interop with APIs that take `const CatToken&`. Callers
   * MUST NOT `const_cast` the reference — doing so re-introduces the M-01
   * mutable-state hazard.
   */
  const CatToken& token() const noexcept { return token_; }

 private:
  friend class CatTokenValidator;
  explicit ValidatedCatToken(CatToken token) noexcept
      : token_(std::move(token)) {}
  CatToken token_;
};

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
  RevalidationCallback* revalidation_callback_ = nullptr;
      ///< Observability hook fired during moqt-reval enforcement.
      ///< Non-owning; the caller is responsible for lifetime. A nullptr
      ///< means "do nothing" — equivalent to installing a
      ///< NoopRevalidationCallback but without the vtable dispatch.
  UsageStateHook* usage_state_ = nullptr;
      ///< Enforcement hook for CTA-5007-B `catreplay` modes. Non-owning;
      ///< the caller is responsible for lifetime. A nullptr means "do
      ///< not enforce" — a token carrying `catreplay=RejectOnReplay`
      ///< or `RevokeOnReplay` is then rejected outright, because
      ///< silently downgrading to `None` would let a misconfigured
      ///< relay believe it was enforcing replay when it was not.

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
   * @brief Install an observability callback for moqt-reval enforcement.
   *
   * The callback fires on every token whose payload carries `moqt-reval`,
   * both when the token is still within its interval (`Fresh`) and when
   * it has crossed the deadline (`Expired`, immediately before the
   * validator throws `TokenRevalidationRequiredError`).
   *
   * Ownership is not transferred — the callback must outlive the
   * validator. Pass `nullptr` to disable (equivalent to the default).
   * See RevalidationCallback docs for the on-hot-path contract.
   */
  CatTokenValidator& withRevalidationCallback(RevalidationCallback* callback);

  /**
   * @brief Install a usage-state hook for `catreplay` enforcement.
   *
   * When the validator sees a token whose `catreplay` claim is
   * `RejectOnReplay` or `RevokeOnReplay`, it consults the installed
   * `UsageStateHook` to decide whether the token's `cti` has already
   * been admitted. Without a hook installed the validator MUST fail
   * closed on those modes — otherwise a claim intended to enforce
   * one-time or revocable use would silently degrade to unenforced.
   *
   * Ownership is not transferred — the hook must outlive the validator.
   * Pass `nullptr` to disable (equivalent to the default; tokens with
   * `catreplay=RejectOnReplay|RevokeOnReplay` will then throw
   * `MissingRequiredClaimError` or `ReplayAttackError` as appropriate).
   *
   * The default `InMemoryUsageState` is suitable for tests and single-
   * process relays. Multi-instance deployments MUST supply an external
   * implementation whose state is shared across relays.
   */
  CatTokenValidator& withUsageStateHook(UsageStateHook* hook);

  /**
   * @brief Validate a CAT token
   * @param token Token to validate
   * @throws Various CatError subclasses on validation failure
   */
  void validate(const CatToken& token) const;

  /**
   * @brief Non-throwing validation for the relay hot path.
   *
   * Runs the same checks as `validate()` but reports failure through a
   * `CatErrorCode` return value rather than an exception. Returns
   * `CatErrorCode::SUCCESS` when the token passes every check.
   *
   * The relay admission path should prefer this entry point: exception
   * unwinding across a per-request boundary is the largest single source
   * of latency variance on this code path, and validation failure is an
   * expected outcome for untrusted input, not an exceptional condition.
   *
   * @note The underlying validation still allocates internally. A future
   *   change is expected to introduce an allocation-lean verifier for
   *   pre-parsed input; this method provides the exception-free surface
   *   that verifier will export.
   */
  [[nodiscard]] CatErrorCode tryValidate(const CatToken& token) const noexcept;

  /**
   * @brief Validate a token and consume it into an immutable
   *        `ValidatedCatToken`.
   *
   * On success the returned wrapper takes ownership of the claims and is the
   * only handle from which they can be read. On failure the same exceptions
   * as `validate()` are thrown; the caller loses the moved-from token, which
   * is the intended contract — an invalid token has no defined content.
   *
   * @throws Various CatError subclasses on validation failure
   */
  [[nodiscard]] ValidatedCatToken intoValidated(CatToken token) const;

  /**
   * @brief Non-throwing companion to `intoValidated`.
   *
   * Returns a `Result` carrying either an immutable `ValidatedCatToken`
   * or the `CatErrorCode` describing why validation failed. On failure
   * the input `token` is dropped (see `intoValidated` for rationale) but
   * no exception is raised.
   */
  [[nodiscard]] Result<ValidatedCatToken, CatErrorCode> tryIntoValidated(
      CatToken token) const noexcept;

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

  // CAT-4-MOQT (draft-ietf-moq-c4m-01) §`moqt-reval`: enforce that
  // `iat + moqt-reval` has not elapsed. `now_epoch_seconds` is passed in
  // from `validate()` so that a single time snapshot is applied
  // consistently across `exp`, `nbf`, and reval checks.
  void validateMoqtRevalidation(const CatToken& token,
                                int64_t now_epoch_seconds) const;
};

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