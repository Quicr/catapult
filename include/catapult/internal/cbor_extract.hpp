/**
 * @file cbor_extract.hpp
 * @brief Primitive extractors for libcbor items used by every claim decoder.
 *
 * The CBOR decoders in `cwt.cpp` and `dpop.cpp` repeatedly extract three
 * shapes from a `cbor_item_t*`: a bounded-length byte string into
 * `std::vector<uint8_t>`, a bounded-length text string into `std::string`,
 * and an unsigned integer into a caller-typed integral. Prior to this
 * header each site open-coded the length check + null check + copy,
 * which produced 10+ near-duplicate blocks that a fuzzer could catch out
 * of sync when one site was patched.
 *
 * Every helper here throws `InvalidClaimValueError` with a caller-supplied
 * field name on the two failure modes: exceeded length cap, or a null
 * data pointer where the length is nonzero. Callers pass the strictest
 * cap that applies at the call site; the shared cap of last resort is
 * `kMaxClaimStringBytes` in `parse_limits.hpp`.
 *
 * All helpers assume the caller has already validated the CBOR item's
 * major type (i.e. `cbor_isa_bytestring` / `cbor_isa_string` /
 * `cbor_isa_uint`). They do not re-check; type-mismatch is a bug in the
 * dispatcher above, not a wire-form failure.
 */

#pragma once

#include <cbor.h>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "catapult/error.hpp"

namespace catapult::internal {

/// Copy the payload of a CBOR byte string into a `std::vector<uint8_t>`,
/// enforcing `max_bytes` and rejecting a null-data-with-nonzero-length.
///
/// @param field_name  Free-form name surfaced in error messages so a
///   caller extracting e.g. `cti` can distinguish it from `cattpk` in a
///   log line. No effect on control flow.
inline std::vector<uint8_t> extractBytestring(cbor_item_t* item,
                                              std::string_view field_name,
                                              std::size_t max_bytes) {
  std::size_t len = cbor_bytestring_length(item);
  if (len > max_bytes) {
    throw InvalidClaimValueError(std::string(field_name) +
                                 " exceeds maximum length");
  }
  const unsigned char* data = cbor_bytestring_handle(item);
  if (!data && len > 0) {
    throw InvalidClaimValueError("Invalid " + std::string(field_name) +
                                 " data pointer");
  }
  return std::vector<uint8_t>(data, data + len);
}

/// Copy the payload of a CBOR text string into a `std::string`, enforcing
/// `max_bytes` and rejecting a null-data-with-nonzero-length.
inline std::string extractTextString(cbor_item_t* item,
                                     std::string_view field_name,
                                     std::size_t max_bytes) {
  std::size_t len = cbor_string_length(item);
  if (len > max_bytes) {
    throw InvalidClaimValueError(std::string(field_name) +
                                 " exceeds maximum length");
  }
  const unsigned char* data = cbor_string_handle(item);
  if (!data && len > 0) {
    throw InvalidClaimValueError("Invalid " + std::string(field_name) +
                                 " data pointer");
  }
  return std::string(reinterpret_cast<const char*>(data), len);
}

/// Read a CBOR unsigned integer into any unsigned target type, rejecting
/// values that would truncate. The caller has already checked
/// `cbor_isa_uint(item)`.
template <typename T>
inline T extractUint(cbor_item_t* item, std::string_view field_name) {
  static_assert(std::is_integral_v<T> && std::is_unsigned_v<T>,
                "extractUint target must be an unsigned integer type");
  std::uint64_t raw = cbor_get_int(item);
  if constexpr (sizeof(T) < sizeof(std::uint64_t)) {
    if (raw > static_cast<std::uint64_t>(std::numeric_limits<T>::max())) {
      throw InvalidClaimValueError(std::string(field_name) +
                                   " exceeds representable range");
    }
  }
  return static_cast<T>(raw);
}

}  // namespace catapult::internal
