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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>
#include <vector>

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
  /// If true, reject any CBOR tag that is not present in `allowed_tags`.
  /// The default is fail-closed with the empty allowlist — CAT payload
  /// maps and DPoP protected headers carry no tags. Context-sensitive
  /// callers (COSE_Sign1 outer, CATNIP tagged byte-string claims) MUST
  /// explicitly widen the allowlist for the exact tags their schema
  /// admits; a global "allow all tags" toggle is deliberately absent so
  /// a permissive default cannot accidentally leak into a strict path.
  bool forbid_unrecognized_tags = true;
  /// Tag numbers that are legal at any position under this loader
  /// invocation. Empty means "no tags allowed" (default). Callers must
  /// list the exact tag values they intend to accept — never a wildcard.
  std::vector<uint64_t> allowed_tags;
  /// If true, require RFC 8949 §4.2.1 "Preferred serialization" for
  /// integers — the shortest CBOR head that can represent the value.
  bool require_shortest_integer = true;
  /// If true, require RFC 8949 §4.2.3 "Length-first" canonical map key
  /// ordering: shorter serialised key first, ties broken bytewise.
  bool require_canonical_map_order = true;

  /// Return true if `tag` appears in the caller-supplied allowlist.
  [[nodiscard]] bool isTagAllowed(uint64_t tag) const noexcept {
    return std::find(allowed_tags.begin(), allowed_tags.end(), tag) !=
           allowed_tags.end();
  }

  /// Derive strict options from an aggregated ParseLimits struct.
  static StrictCborOptions fromLimits(const ParseLimits& limits) noexcept {
    StrictCborOptions o;
    o.max_depth = limits.max_cbor_depth;
    o.max_bytes = limits.max_decoded_cbor_bytes;
    return o;
  }

  /// Convenience: return a copy with the given tags added to the
  /// allowlist. Used by context-specific parsers (CWT payload with
  /// CATNIP, COSE_Sign1 outer, etc.) so they can compose a policy
  /// without mutating a shared default.
  [[nodiscard]] StrictCborOptions withAllowedTags(
      std::initializer_list<uint64_t> tags) const {
    StrictCborOptions copy = *this;
    for (uint64_t t : tags) {
      copy.allowed_tags.push_back(t);
    }
    return copy;
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
 * @brief Result of loading an outer COSE envelope under strict rules.
 *
 * `tag` carries the outer COSE tag value if the envelope was tagged; the
 * caller uses it to enforce tag/structure agreement (e.g. Sign1 ↔ 18,
 * Mac0 ↔ 17, Sign ↔ 98). `item` owns the inner item that was inside the
 * tag (if any) — always the array that carries the COSE members.
 */
struct StrictCoseEnvelope {
  CborItemPtr item;
  std::optional<uint64_t> tag;
};

/**
 * @brief Load an outer COSE envelope through the strict loader.
 *
 * Applies the same well-formedness, canonical-encoding, and size checks
 * as `loadStrict` to the entire outer COSE byte stream, whitelisting the
 * COSE tags the caller expects (18 for COSE_Sign1, 17 for COSE_Mac0, 16
 * for COSE_Encrypt0, 98 for COSE_Sign). All non-tag strict checks — no
 * indefinite-length forms, no duplicate map keys, no trailing bytes, no
 * unshortest integers — still apply. Also peels the tag so the caller
 * uniformly sees the inner CBOR array.
 *
 * @throws InvalidCborError if the envelope is malformed or its outer tag
 *   is not in `allowed_tags`.
 */
StrictCoseEnvelope loadStrictCoseEnvelope(
    std::span<const uint8_t> data,
    std::initializer_list<uint64_t> allowed_tags);

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
