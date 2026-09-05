/**
 * @file safe_arith.hpp
 * @brief Portable overflow-checked integer arithmetic.
 *
 * The token validator does bounded arithmetic on `int64_t` clock values
 * (`exp + skew`, `nbf - skew`, `iat + reval + skew`). The previous
 * implementation used the GCC/Clang `__builtin_*_overflow` intrinsics,
 * which are non-standard and unavailable on MSVC. This header provides
 * a portable equivalent so the same logic compiles cleanly under every
 * supported toolchain.
 *
 * The functions return `true` on overflow (matching the intrinsic's
 * convention). On overflow, the output value is unspecified — callers
 * must inspect the return value first.
 */

#pragma once

#include <cstdint>
#include <limits>

namespace catapult::internal {

inline bool addOverflow(int64_t a, int64_t b, int64_t& out) noexcept {
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_add_overflow(a, b, &out);
#else
  // Two int64_t values overflow iff both are non-negative and their sum
  // exceeds INT64_MAX, or both are non-positive and their sum is below
  // INT64_MIN. This mirrors the semantics of the intrinsic without
  // depending on it.
  constexpr int64_t kMax = std::numeric_limits<int64_t>::max();
  constexpr int64_t kMin = std::numeric_limits<int64_t>::min();
  if (b > 0 && a > kMax - b) return true;
  if (b < 0 && a < kMin - b) return true;
  out = a + b;
  return false;
#endif
}

inline bool subOverflow(int64_t a, int64_t b, int64_t& out) noexcept {
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_sub_overflow(a, b, &out);
#else
  constexpr int64_t kMax = std::numeric_limits<int64_t>::max();
  constexpr int64_t kMin = std::numeric_limits<int64_t>::min();
  if (b < 0 && a > kMax + b) return true;
  if (b > 0 && a < kMin + b) return true;
  out = a - b;
  return false;
#endif
}

}  // namespace catapult::internal
