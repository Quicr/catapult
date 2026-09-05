/**
 * @file strict_cbor.hpp
 * @brief Strict CBOR loader for security-critical parse paths.
 *
 * CTA-5007-B §4.5 and RFC 8949 §4.2 (Core Deterministic Encoding) require
 * relays to reject non-canonical CBOR: non-shortest integer encodings,
 * indefinite-length items, duplicate map keys, trailing bytes after the
 * root item, and improper tags. libcbor's default DOM loader silently
 * tolerates several of these. This wrapper enforces the checks before
 * a decoded value is handed to downstream claim parsers.
 *
 * The wrapper does not (yet) replace libcbor as the underlying parser;
 * it adds a post-parse validation pass and rejects inputs that would
 * otherwise sneak through. Task #19 will thread ParseLimits through
 * every decoder so limits are configurable rather than compiled in.
 */

#pragma once

#include <cbor.h>

#include <cstddef>
#include <cstdint>
#include <span>

#include "catapult/error.hpp"
#include "catapult/internal/cbor_owned.hpp"
#include "catapult/internal/parse_limits.hpp"

namespace catapult::internal {

/// Options controlling strictness. Maximum nesting depth and the total
/// input ceiling are sourced from ParseLimits by default; other checks
/// are always on.
struct StrictCborOptions {
  /// Maximum nested container depth. Defaults to ParseLimits::max_cbor_depth.
  std::size_t max_depth = kMaxCborDepth;
  /// Maximum raw CBOR input in bytes. Defaults to
  /// ParseLimits::max_decoded_cbor_bytes.
  std::size_t max_bytes = kMaxDecodedCborBytes;
  /// If true, forbid indefinite-length arrays/maps/bytestrings/strings.
  /// Required by RFC 8949 §4.2.
  bool require_definite_length = true;
  /// If true, forbid duplicate keys in any map.
  bool forbid_duplicate_map_keys = true;
  /// If true, reject any CBOR tag we do not explicitly allow. Currently
  /// no tags are allowed (CAT/COSE do not use tag numbers in the CWT
  /// payload; the outer COSE tag is handled separately).
  bool forbid_unrecognized_tags = true;
  /// If true, require RFC 8949 §4.2.1 "Preferred serialization" for
  /// integers — the shortest CBOR head that can represent the value.
  bool require_shortest_integer = true;
  /// If true, require RFC 8949 §4.2.3 "Length-first" canonical map key
  /// ordering: shorter serialised key first, ties broken bytewise.
  bool require_canonical_map_order = true;

  /// Derive strict options from an aggregated ParseLimits struct.
  static StrictCborOptions fromLimits(const ParseLimits& limits) noexcept {
    StrictCborOptions o;
    o.max_depth = limits.max_cbor_depth;
    o.max_bytes = limits.max_decoded_cbor_bytes;
    return o;
  }
};

/**
 * @brief Load a CBOR item and validate it against strict rules.
 *
 * @param data   Input bytes (must be fully consumed by a single CBOR item).
 * @param opts   Strictness options.
 * @return Owning CBOR item.
 *
 * @throws InvalidCborError if the input is not well-formed, has trailing
 *   bytes, uses indefinite-length forms, contains duplicate map keys,
 *   nests deeper than allowed, or carries an unrecognized tag.
 */
CborItemPtr loadStrict(std::span<const uint8_t> data,
                       const StrictCborOptions& opts = {});

/**
 * @brief Recursively sort the pairs of every map in a CBOR tree so that the
 *   serialized form satisfies RFC 8949 §4.2.3 "length-first" ordering.
 *
 * Rationale: catapult stores several claim maps in std::unordered_map, whose
 * iteration order is nondeterministic, and libcbor's cbor_map_add preserves
 * insertion order. Without this pass the encoder would emit tokens that the
 * strict loader (loadStrict) itself would reject on round-trip.
 *
 * The reorder is in-place. Duplicate keys are not resolved here; loadStrict
 * catches them separately.
 */
void canonicalizeMapOrder(cbor_item_t* item);

}  // namespace catapult::internal
