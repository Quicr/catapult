#pragma once

#include <cbor.h>

#include <cstddef>
#include <cstdint>
#include <span>

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

inline CborItemPtr cbor_build_uint64_owned(uint64_t value) {
  return CborItemPtr(cbor_build_uint64(value));
}

inline CborItemPtr cbor_build_negint64_owned(uint64_t value) {
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
