#pragma once

#include <cbor.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

#include "catapult/cwt.hpp"

namespace catapult {

// Safe wrappers around libcbor functions that return owning pointers.
// Using these instead of the raw C API makes leak-by-omission impossible:
// bare cbor_array_get / cbor_load / cbor_build_* should not appear in
// catapult source outside this header.

inline CborItemPtr cbor_array_get_owned(cbor_item_t* array, size_t index) {
  return CborItemPtr(cbor_array_get(array, index));
}

inline CborItemPtr cbor_load_owned(const uint8_t* data, size_t len,
                                   struct cbor_load_result& result) {
  return CborItemPtr(cbor_load(data, len, &result));
}

inline CborItemPtr cbor_load_owned(std::span<const uint8_t> data,
                                   struct cbor_load_result& result) {
  return CborItemPtr(cbor_load(data.data(), data.size(), &result));
}

// Bytestring builder that avoids passing nullptr to memcpy when length == 0
// (prevents UBSan nonnull-attribute finding in libcbor).
inline CborItemPtr cbor_build_bytestring_owned(const uint8_t* data,
                                               size_t length) {
  static const uint8_t empty_byte = 0;
  return CborItemPtr(
      cbor_build_bytestring(length == 0 ? &empty_byte : data, length));
}

inline CborItemPtr cbor_build_string_owned(const char* str) {
  return CborItemPtr(cbor_build_string(str));
}

inline CborItemPtr cbor_build_uint8_owned(uint8_t value) {
  return CborItemPtr(cbor_build_uint8(value));
}

// RFC 8949 §4.2.1 "Preferred serialization": encode an unsigned integer
// in the fewest bytes that can represent it. libcbor's cbor_build_uint64
// unconditionally emits an 8-byte body; that would violate the canonical
// encoding rules that loadStrict now enforces. Route every unsigned build
// through the minimal-width helper so encoder output can round-trip
// through the strict decoder.
inline CborItemPtr cbor_build_uint64_owned(uint64_t value) {
  if (value <= 0xFFu) {
    return CborItemPtr(cbor_build_uint8(static_cast<uint8_t>(value)));
  }
  if (value <= 0xFFFFu) {
    return CborItemPtr(cbor_build_uint16(static_cast<uint16_t>(value)));
  }
  if (value <= 0xFFFFFFFFu) {
    return CborItemPtr(cbor_build_uint32(static_cast<uint32_t>(value)));
  }
  return CborItemPtr(cbor_build_uint64(value));
}

// Signed overload for call sites that carry claim IDs or timestamps as
// int64_t but are logically non-negative. Rejects negatives so a caller
// bug cannot silently wrap into a huge positive. Also accepts plain `int`
// literals to disambiguate calls like `cbor_build_uint64_owned(0)`.
template <typename T>
  requires std::is_integral_v<T> && std::is_signed_v<T>
inline CborItemPtr cbor_build_uint64_owned(T value) {
  if (value < 0) {
    throw InvalidCborError("cbor_build_uint64_owned received a negative value");
  }
  return cbor_build_uint64_owned(static_cast<uint64_t>(value));
}

// Same principle for negints: the wire value is `-1 - n` encoded in the
// smallest width that fits.
inline CborItemPtr cbor_build_negint64_owned(uint64_t value) {
  if (value <= 0xFFu) {
    return CborItemPtr(cbor_build_negint8(static_cast<uint8_t>(value)));
  }
  if (value <= 0xFFFFu) {
    return CborItemPtr(cbor_build_negint16(static_cast<uint16_t>(value)));
  }
  if (value <= 0xFFFFFFFFu) {
    return CborItemPtr(cbor_build_negint32(static_cast<uint32_t>(value)));
  }
  return CborItemPtr(cbor_build_negint64(value));
}

inline CborItemPtr cbor_build_bool_owned(bool value) {
  return CborItemPtr(cbor_build_bool(value));
}

inline CborItemPtr cbor_build_float8_owned(double value) {
  return CborItemPtr(cbor_build_float8(value));
}

inline CborItemPtr cbor_new_definite_array_owned(size_t size) {
  return CborItemPtr(cbor_new_definite_array(size));
}

inline CborItemPtr cbor_new_definite_map_owned(size_t size) {
  return CborItemPtr(cbor_new_definite_map(size));
}

inline CborItemPtr cbor_new_null_owned() {
  return CborItemPtr(cbor_new_null());
}

// Serialize a CBOR item, returning the buffer in an RAII wrapper.
// Sets `out_length` to the number of bytes written (0 on failure).
inline CborBufferPtr cbor_serialize_alloc_owned(cbor_item_t* item,
                                                size_t& out_length) {
  unsigned char* buffer = nullptr;
  size_t buffer_size = 0;
  out_length = cbor_serialize_alloc(item, &buffer, &buffer_size);
  return CborBufferPtr(buffer);
}

}  // namespace catapult
