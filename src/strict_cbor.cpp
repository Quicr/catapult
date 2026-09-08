#include "catapult/internal/strict_cbor.hpp"

#include <cbor.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <vector>

#include "catapult/error.hpp"

namespace catapult::internal {

namespace {

// RFC 8949 §4.2.1 "Preferred serialization": an unsigned integer MUST be
// encoded in the fewest bytes that can represent it. libcbor exposes the
// as-parsed width via cbor_int_get_width(); compare against the minimum
// width that would suffice for the value.
//
// The check applies uniformly to CBOR_TYPE_UINT and CBOR_TYPE_NEGINT since
// negative integers on the wire encode `(-n - 1)` as an unsigned value in
// the same major-type-1 width.
void checkShortestIntegerEncoding(cbor_item_t* item) {
  const uint64_t v = cbor_get_int(item);
  const cbor_int_width w = cbor_int_get_width(item);
  cbor_int_width minimal;
  if (v <= 23) {
    minimal = CBOR_INT_8;  // inline / 1-byte head
  } else if (v <= 0xFF) {
    minimal = CBOR_INT_8;
  } else if (v <= 0xFFFF) {
    minimal = CBOR_INT_16;
  } else if (v <= 0xFFFFFFFFULL) {
    minimal = CBOR_INT_32;
  } else {
    minimal = CBOR_INT_64;
  }
  // Inline (v<=23) is represented by libcbor as CBOR_INT_8 too, so any
  // narrower-than-minimal encoding is impossible; only wider is a bug.
  if (static_cast<int>(w) > static_cast<int>(minimal)) {
    throw InvalidCborError(
        "Integer not encoded in the shortest form (RFC 8949 §4.2.1)");
  }
}

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
      if (opts.require_shortest_integer) {
        checkShortestIntegerEncoding(item);
      }
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

      // We serialise each key once and use it for three checks: recursive
      // walk (already done), duplicate detection, and canonical ordering
      // (RFC 8949 §4.2.3 "Length-first Core Deterministic Encoding":
      // shorter serialised key first; ties broken by bytewise lex order).
      const bool need_serialized =
          opts.forbid_duplicate_map_keys || opts.require_canonical_map_order;
      std::vector<std::vector<uint8_t>> keySerializations;
      if (need_serialized) {
        keySerializations.reserve(n);
      }

      auto lengthFirstLess = [](const std::vector<uint8_t>& a,
                                const std::vector<uint8_t>& b) {
        if (a.size() != b.size()) return a.size() < b.size();
        return std::lexicographical_compare(a.begin(), a.end(), b.begin(),
                                            b.end());
      };

      for (std::size_t i = 0; i < n; ++i) {
        walk(pairs[i].key, opts, depth + 1);
        walk(pairs[i].value, opts, depth + 1);

        if (!need_serialized) continue;

        unsigned char* buf = nullptr;
        size_t buf_size = 0;
        size_t len = cbor_serialize_alloc(pairs[i].key, &buf, &buf_size);
        if (len == 0) {
          if (buf) free(buf);
          throw InvalidCborError("Failed to serialize map key");
        }
        std::vector<uint8_t> serialized(buf, buf + len);
        free(buf);

        if (opts.forbid_duplicate_map_keys) {
          for (const auto& prev : keySerializations) {
            if (prev == serialized) {
              throw InvalidCborError("Duplicate CBOR map key");
            }
          }
        }
        if (opts.require_canonical_map_order && !keySerializations.empty()) {
          if (!lengthFirstLess(keySerializations.back(), serialized)) {
            throw InvalidCborError(
                "Map keys not in canonical length-first order "
                "(RFC 8949 §4.2.3)");
          }
        }
        keySerializations.push_back(std::move(serialized));
      }
      return;
    }

    case CBOR_TYPE_TAG: {
      const uint64_t tag = cbor_tag_value(item);
      if (opts.forbid_unrecognized_tags && !opts.isTagAllowed(tag)) {
        throw InvalidCborError("Unrecognized CBOR tag in strict input");
      }
      // cbor_tag_item returns a new reference; wrap it so the recursive
      // walk cannot leak on throw.
      CborItemPtr inner(cbor_tag_item(item));
      walk(inner.get(), opts, depth + 1);
      return;
    }

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

// Recursively sort each map's pairs in place by their canonical
// serialization (RFC 8949 §4.2.3 length-first order). Called by encoders
// so that maps built from unordered containers still round-trip through
// loadStrict.
void canonicalizeMapOrder(cbor_item_t* item) {
  if (!item) return;
  switch (cbor_typeof(item)) {
    case CBOR_TYPE_ARRAY: {
      const std::size_t n = cbor_array_size(item);
      cbor_item_t** items = cbor_array_handle(item);
      for (std::size_t i = 0; i < n; ++i) {
        canonicalizeMapOrder(items[i]);
      }
      return;
    }
    case CBOR_TYPE_MAP: {
      const std::size_t n = cbor_map_size(item);
      cbor_pair* pairs = cbor_map_handle(item);
      for (std::size_t i = 0; i < n; ++i) {
        canonicalizeMapOrder(pairs[i].key);
        canonicalizeMapOrder(pairs[i].value);
      }
      // Serialize each key once so the sort compares stable byte strings.
      std::vector<std::pair<std::vector<uint8_t>, std::size_t>> keyed;
      keyed.reserve(n);
      for (std::size_t i = 0; i < n; ++i) {
        unsigned char* buf = nullptr;
        size_t buf_size = 0;
        size_t len = cbor_serialize_alloc(pairs[i].key, &buf, &buf_size);
        if (len == 0) {
          if (buf) free(buf);
          throw InvalidCborError(
              "Failed to serialize map key during canonicalization");
        }
        std::vector<uint8_t> serialized(buf, buf + len);
        free(buf);
        keyed.emplace_back(std::move(serialized), i);
      }
      std::stable_sort(keyed.begin(), keyed.end(),
                       [](const auto& a, const auto& b) {
                         const auto& ka = a.first;
                         const auto& kb = b.first;
                         if (ka.size() != kb.size()) {
                           return ka.size() < kb.size();
                         }
                         return std::lexicographical_compare(
                             ka.begin(), ka.end(), kb.begin(), kb.end());
                       });
      std::vector<cbor_pair> reordered(n);
      for (std::size_t i = 0; i < n; ++i) {
        reordered[i] = pairs[keyed[i].second];
      }
      for (std::size_t i = 0; i < n; ++i) {
        pairs[i] = reordered[i];
      }
      return;
    }
    case CBOR_TYPE_TAG: {
      // cbor_tag_item returns a new reference; balance it immediately.
      CborItemPtr inner(cbor_tag_item(item));
      canonicalizeMapOrder(inner.get());
      return;
    }
    default:
      return;
  }
}

StrictCoseEnvelope loadStrictCoseEnvelope(
    std::span<const uint8_t> data,
    std::initializer_list<uint64_t> allowed_tags) {
  StrictCborOptions opts;
  // The outer COSE tag itself is legal only under this specific call, so
  // widen the allowlist to the caller's expected tag(s) — everything else
  // still falls under the strict-by-default policy.
  for (uint64_t t : allowed_tags) {
    opts.allowed_tags.push_back(t);
  }
  CborItemPtr root = loadStrict(data, opts);

  StrictCoseEnvelope env;
  if (cbor_isa_tag(root.get())) {
    env.tag = cbor_tag_value(root.get());
    // cbor_tag_item returns a new (owned) reference; wrap it before
    // dropping the parent so ownership is single-rooted.
    CborItemPtr inner(cbor_tag_item(root.get()));
    env.item = std::move(inner);
  } else {
    env.item = std::move(root);
  }
  return env;
}

CborItemPtr loadStrict(std::span<const uint8_t> data,
                       const StrictCborOptions& opts) {
  if (data.empty()) {
    throw InvalidCborError("Empty CBOR input");
  }
  if (data.size() > opts.max_bytes) {
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
