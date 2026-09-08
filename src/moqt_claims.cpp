/**
 * @file cat_moqt_claims.cpp
 * @brief Implementation of MOQT-specific claims functionality
 */

#include "catapult/moqt_claims.hpp"

#include <algorithm>
#include <ranges>

namespace catapult {

bool MoqtBinaryMatch::matches(std::span<const uint8_t> data) const noexcept {
  // The wildcard (produced by `any()`) is the only shape that accepts
  // every input. An `exact("")` match must fall through to the EXACT
  // arm and authorise only when `data` is itself empty.
  if (is_wildcard()) {
    return true;
  }

  switch (match_type) {
    case BinaryMatchType::EXACT:
      // Equal handles the pattern-empty case correctly: it returns true
      // iff both ranges are empty, which is exactly the semantics of
      // `exact("")`.
      return std::ranges::equal(pattern, data);

    case BinaryMatchType::PREFIX:
      // Factory rejects an empty prefix pattern, so `pattern.size() > 0`
      // holds here. A zero-length data cannot carry a positive-length
      // prefix.
      if (data.size() < pattern.size()) {
        return false;
      }
      return std::ranges::equal(pattern, data.first(pattern.size()));

    case BinaryMatchType::SUFFIX:
      if (data.size() < pattern.size()) {
        return false;
      }
      return std::ranges::equal(pattern, data.last(pattern.size()));

    case BinaryMatchType::CONTAINS: {
      if (data.size() < pattern.size()) {
        return false;
      }
      auto it = std::ranges::search(data, pattern);
      return it.begin() != data.end();
    }

    default:
      return false;
  }
}

}  // namespace catapult