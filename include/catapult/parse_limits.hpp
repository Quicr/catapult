/**
 * @file parse_limits.hpp
 * @brief Public configuration surface for attacker-facing parse limits.
 *
 * The library ships CTA-5007-B recommended ceilings as internal defaults
 * (see `include/catapult/internal/parse_limits.hpp`). Operators whose
 * deployment envelope differs — a relay whose protocol layer already caps
 * incoming token bytes tighter than 4 KiB, a lab tool that legitimately
 * accepts larger tokens — need a public seam to override without editing
 * headers or forking.
 *
 * `catapult::ParseLimits` is that seam. It is a re-export of the internal
 * struct with a validated construction helper: callers cannot install a
 * configuration whose values exceed the absolute compiled-in ceilings
 * (which double as fuzz-tested safety anchors) nor a zero value that
 * would disable a check entirely.
 *
 * Values may be tightened by the caller; loosening beyond the compiled
 * ceilings is a configuration error the library refuses at construction.
 */

#pragma once

#include <cstddef>
#include <stdexcept>
#include <string>

#include "internal/parse_limits.hpp"

namespace catapult {

/**
 * @brief Public re-export of the internal parse limits struct.
 */
using ParseLimits = ::catapult::internal::ParseLimits;

/**
 * @brief Thrown when a caller-supplied `ParseLimits` violates the
 *        library's safety invariants.
 *
 * Cases: any field is zero (disables the check), or any field exceeds
 * the compiled-in absolute ceiling (loosens beyond what the library
 * has been fuzz-tested against).
 */
class InvalidParseLimitsError : public std::invalid_argument {
 public:
  using std::invalid_argument::invalid_argument;
};

/**
 * @brief Absolute upper bound the caller may not exceed for
 *        `max_encoded_token_bytes`. Matches the compiled-in default so
 *        the shipped defaults are always accepted.
 */
inline constexpr std::size_t kAbsoluteMaxEncodedTokenBytes =
    ::catapult::internal::kMaxEncodedTokenBytes;

/**
 * @brief Absolute upper bound for `max_decoded_cbor_bytes`.
 */
inline constexpr std::size_t kAbsoluteMaxDecodedCborBytes =
    ::catapult::internal::kMaxDecodedCborBytes;

/**
 * @brief Absolute upper bound for CBOR nesting depth.
 */
inline constexpr std::size_t kAbsoluteMaxCborDepth =
    ::catapult::internal::kMaxCborDepth;

/**
 * @brief Absolute upper bound for URI length.
 */
inline constexpr std::size_t kAbsoluteMaxUriLength =
    ::catapult::internal::kMaxUriLength;

/**
 * @brief Absolute upper bound for regex pattern length.
 */
inline constexpr std::size_t kAbsoluteMaxRegexPatternLength =
    ::catapult::internal::kMaxRegexPatternLength;

/**
 * @brief Absolute upper bound for regex pattern count.
 */
inline constexpr std::size_t kAbsoluteMaxRegexPatterns =
    ::catapult::internal::kMaxRegexPatterns;

/**
 * @brief Validate a caller-supplied `ParseLimits` against the library's
 *        safety invariants.
 *
 * Throws `InvalidParseLimitsError` when:
 *   - Any field is zero (a zero limit would disable the check, which is
 *     never a safe operational choice on an attacker-facing parser).
 *   - Any field exceeds the compiled-in absolute ceiling. Callers may
 *     tighten below the defaults but MUST NOT loosen beyond them; the
 *     ceilings are what the fuzz corpus and sanitizer suite exercise.
 *
 * Called from every public entry point that accepts `ParseLimits`.
 */
void validateParseLimits(const ParseLimits& limits);

}  // namespace catapult
