/**
 * @file parse_limits.hpp
 * @brief Shared resource limits for all parse entry points.
 *
 * CTA-5007-B §4.3.1 recommends that CAT processors enforce a maximum
 * encoded token size (RECOMMENDED: 4096 bytes) and a total bound across
 * concurrently processed tokens. The values here are the defaults applied
 * to every public parse boundary; callers may tighten but should not
 * relax them without documenting the operational reason.
 *
 * NOTE: This is intentionally a small, dependency-free header so it can
 * be included from crypto/CWT/DPoP/URI code paths without pulling in
 * additional headers. Phase 3 will extend this into a full ParseLimits
 * struct passed by reference through every codec (task #19).
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

}  // namespace catapult::internal
