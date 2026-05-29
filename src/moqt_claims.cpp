/**
 * @file cat_moqt_claims.cpp
 * @brief Implementation of MOQT-specific claims functionality
 */

#include "catapult/moqt_claims.hpp"

#include <algorithm>
#include <ranges>

namespace catapult {

bool MoqtBinaryMatch::matches(std::span<const uint8_t> data) const noexcept {
  if (is_empty()) {
    return true;  // Empty match matches everything
  }

  if (pattern.empty()) {
    return data.empty();
  }

  switch (match_type) {
    case BinaryMatchType::EXACT:
      return std::ranges::equal(pattern, data);

    case BinaryMatchType::PREFIX:
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

      // Use std::search to find pattern within data
      auto it = std::ranges::search(data, pattern);
      return it.begin() != data.end();
    }

    default:
      return false;
  }
}

}  // namespace catapult