/**
 * @file parse_limits.hpp
 * @brief Shared resource limits for all parse entry points.
 *
 * CTA-5007-B §4.3.1 recommends that CAT processors enforce a maximum
 * encoded token size (RECOMMENDED: 4096 bytes) and a total bound across
 * concurrently processed tokens. The defaults here apply to every public
 * parse boundary; callers may tighten them but should not relax them
 * without documenting the operational reason.
 *
 * The struct is deliberately trivial and header-only so it can be
 * included from crypto/CWT/DPoP/URI code paths without pulling in
 * additional dependencies.
 */

#pragma once

#include <cstddef>

namespace catapult::internal {

/// CTA-5007-B §4.3.1 RECOMMENDED maximum encoded token size, in bytes.
/// Applies to base64url-encoded CWTs, the legacy JWT-shaped compat format,
/// and every DPoP proof accepted from an untrusted source.
inline constexpr std::size_t kMaxEncodedTokenBytes = 4096;

/// Absolute ceiling on raw (post-base64-decode) CBOR bytes we will hand
/// to libcbor. Base64url expansion is ~4/3, so a 4096-byte encoded input
/// decodes to at most 3072 bytes; we keep a small margin for headers.
inline constexpr std::size_t kMaxDecodedCborBytes = 3200;

/// Maximum CBOR container nesting depth. CTA-5007-B tokens do not exceed
/// 8 levels in practice; we keep a small margin.
inline constexpr std::size_t kMaxCborDepth = 16;

/// Maximum accepted URI byte length across every matcher entry point.
inline constexpr std::size_t kMaxUriLength = 8192;

/// Maximum regex pattern length (mirrors CTA-5007-B recommendations
/// for the `catu` regex match type; see also H-03).
inline constexpr std::size_t kMaxRegexPatternLength = 256;

/// Maximum number of regex patterns retained by a single matcher.
inline constexpr std::size_t kMaxRegexPatterns = 50;

/**
 * @brief Aggregated parse limits threaded through every codec entry point.
 *
 * Every attacker-facing parser (CBOR, base64, JWT split, DPoP, URI, JSON)
 * consults these values before allocating buffers or invoking libcbor. The
 * defaults are the CTA-5007-B recommended values; a caller may pass a
 * customised instance to `withDefaults().withMaxEncodedTokenBytes(...)`
 * style construction, but the defaults must remain conservative enough
 * that leaving them alone keeps the library on the standards baseline.
 */
struct ParseLimits {
  std::size_t max_encoded_token_bytes = kMaxEncodedTokenBytes;
  std::size_t max_decoded_cbor_bytes = kMaxDecodedCborBytes;
  std::size_t max_cbor_depth = kMaxCborDepth;
  std::size_t max_uri_length = kMaxUriLength;
  std::size_t max_regex_pattern_length = kMaxRegexPatternLength;
  std::size_t max_regex_patterns = kMaxRegexPatterns;

  /// Return the process-wide defaults. Preferred over default-constructing
  /// so intent is explicit at call sites.
  static constexpr ParseLimits defaults() noexcept { return ParseLimits{}; }
};

}  // namespace catapult::internal
