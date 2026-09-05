#include "catapult/internal/strict_cbor.hpp"

#include <cbor.h>

#include <cmath>
#include <cstring>
#include <vector>

#include "catapult/error.hpp"

namespace catapult::internal {

namespace {

// Recursively walk the DOM tree, enforcing:
//   - no indefinite-length containers,
//   - no unrecognized tag items,
//   - no duplicate map keys (byte-level comparison of the canonical
//     serialization of each key),
//   - nesting depth within limit.
//
// Duplicate detection reserialises each key and compares byte strings; this
// is O(n^2 * key_size) worst case but adequate for CAT payloads capped at
// 4 KiB. It intentionally does not depend on hashing to keep the check
// independent of libcbor's internal ordering.
void walk(cbor_item_t* item, const StrictCborOptions& opts,
          std::size_t depth) {
  if (!item) {
    throw InvalidCborError("Null CBOR item during strict validation");
  }
  if (depth > opts.max_depth) {
    throw InvalidCborError("CBOR nesting depth exceeds strict limit");
  }

  switch (cbor_typeof(item)) {
    case CBOR_TYPE_UINT:
    case CBOR_TYPE_NEGINT:
      return;

    case CBOR_TYPE_BYTESTRING:
      if (opts.require_definite_length && cbor_bytestring_is_indefinite(item)) {
        throw InvalidCborError("Indefinite-length bytestring is not canonical");
      }
      return;

    case CBOR_TYPE_STRING:
      if (opts.require_definite_length && cbor_string_is_indefinite(item)) {
        throw InvalidCborError("Indefinite-length string is not canonical");
      }
      return;

    case CBOR_TYPE_ARRAY: {
      if (opts.require_definite_length && cbor_array_is_indefinite(item)) {
        throw InvalidCborError("Indefinite-length array is not canonical");
      }
      std::size_t n = cbor_array_size(item);
      cbor_item_t** items = cbor_array_handle(item);
      for (std::size_t i = 0; i < n; ++i) {
        walk(items[i], opts, depth + 1);
      }
      return;
    }

    case CBOR_TYPE_MAP: {
      if (opts.require_definite_length && cbor_map_is_indefinite(item)) {
        throw InvalidCborError("Indefinite-length map is not canonical");
      }
      std::size_t n = cbor_map_size(item);
      cbor_pair* pairs = cbor_map_handle(item);

      std::vector<std::vector<uint8_t>> keySerializations;
      keySerializations.reserve(n);

      for (std::size_t i = 0; i < n; ++i) {
        walk(pairs[i].key, opts, depth + 1);
        walk(pairs[i].value, opts, depth + 1);

        if (opts.forbid_duplicate_map_keys) {
          unsigned char* buf = nullptr;
          size_t buf_size = 0;
          size_t len = cbor_serialize_alloc(pairs[i].key, &buf, &buf_size);
          if (len == 0) {
            if (buf) free(buf);
            throw InvalidCborError("Failed to serialize map key for dup check");
          }
          std::vector<uint8_t> serialized(buf, buf + len);
          free(buf);
          for (const auto& prev : keySerializations) {
            if (prev == serialized) {
              throw InvalidCborError("Duplicate CBOR map key");
            }
          }
          keySerializations.push_back(std::move(serialized));
        }
      }
      return;
    }

    case CBOR_TYPE_TAG:
      if (opts.forbid_unrecognized_tags) {
        throw InvalidCborError("Unrecognized CBOR tag in strict input");
      }
      walk(cbor_move(cbor_tag_item(item)), opts, depth + 1);
      return;

    case CBOR_TYPE_FLOAT_CTRL:
      // Bool / null / undefined / half/single/double float. Reject NaN
      // and negative zero here so downstream code cannot silently accept
      // them (RFC 8949 §4.2.2).
      if (cbor_float_ctrl_is_ctrl(item)) return;
      {
        double v = cbor_float_get_float(item);
        if (v != v) {  // NaN
          throw InvalidCborError("NaN not permitted in strict CBOR");
        }
        // -0.0 has the same value as 0.0 but a different bit pattern.
        if (v == 0.0 && std::signbit(v)) {
          throw InvalidCborError("Negative zero not permitted in strict CBOR");
        }
      }
      return;
  }
}

}  // namespace

CborItemPtr loadStrict(std::span<const uint8_t> data,
                       const StrictCborOptions& opts) {
  if (data.empty()) {
    throw InvalidCborError("Empty CBOR input");
  }
  if (data.size() > kMaxDecodedCborBytes) {
    throw InvalidCborError("CBOR input exceeds strict size limit");
  }

  struct cbor_load_result result{};
  auto item = cbor_load_owned(data.data(), data.size(), result);
  if (result.error.code != CBOR_ERR_NONE || !item) {
    throw InvalidCborError("Malformed CBOR input");
  }
  if (result.read != data.size()) {
    throw InvalidCborError("Trailing bytes after CBOR root item");
  }

  walk(item.get(), opts, 0);
  return item;
}

}  // namespace catapult::internal
