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

/// Options controlling strictness. Currently only a maximum nesting depth
/// is exposed; other checks are always on.
struct StrictCborOptions {
  /// Maximum nested container depth. CTA-5007-B tokens do not exceed 8
  /// levels in practice; we keep a small margin.
  std::size_t max_depth = 16;
  /// If true, forbid indefinite-length arrays/maps/bytestrings/strings.
  /// Required by RFC 8949 §4.2.
  bool require_definite_length = true;
  /// If true, forbid duplicate keys in any map.
  bool forbid_duplicate_map_keys = true;
  /// If true, reject any CBOR tag we do not explicitly allow. Currently
  /// no tags are allowed (CAT/COSE do not use tag numbers in the CWT
  /// payload; the outer COSE tag is handled separately).
  bool forbid_unrecognized_tags = true;
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

}  // namespace catapult::internal
