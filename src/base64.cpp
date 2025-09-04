#include "catapult/base64.hpp"

#include <array>

namespace catapult {

// Base64 URL encoding/decoding constants and functions
static constexpr std::string_view base64_chars_url =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * @brief Compile-time base64 character validation
 */
consteval bool is_valid_base64_char(char c) noexcept {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
         (c >= '0' && c <= '9') || c == '-' || c == '_';
}

std::string base64UrlEncodeImpl(std::span<const uint8_t> data) {
  std::string result;
  // Pre-allocate capacity for performance (base64 expansion factor ~1.33)
  result.reserve((data.size() * 4 + 2) / 3);

  int val = 0, valb = -6;
  for (uint8_t c : data) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      result.push_back(base64_chars_url[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6) {
    result.push_back(base64_chars_url[((val << 8) >> (valb + 8)) & 0x3F]);
  }
  return result;
}

std::vector<uint8_t> base64UrlDecode(std::string_view encoded) {
  // Create decode lookup table for performance (static to avoid repeated
  // initialization)
  static const std::array<int8_t, 256> decode_table = []() {
    std::array<int8_t, 256> table{};
    // Initialize all to -1 (invalid)
    for (size_t i = 0; i < 256; ++i) table[i] = -1;

    // Set valid base64url characters
    for (size_t i = 0; i < base64_chars_url.size(); ++i) {
      table[static_cast<unsigned char>(base64_chars_url[i])] =
          static_cast<int8_t>(i);
    }
    return table;
  }();

  std::vector<uint8_t> result;
  result.reserve((encoded.size() * 3) / 4);  // Reserve estimated size

  int val = 0, valb = -8;
  for (char c : encoded) {
    if (c == '=') break;

    // Use lookup table for O(1) character validation and conversion
    int8_t decoded = decode_table[static_cast<unsigned char>(c)];
    if (decoded == -1) {
      throw InvalidBase64Error("Invalid character in base64 string");
    }

    val = (val << 6) + decoded;
    valb += 6;
    if (valb >= 0) {
      result.push_back((val >> valb) & 0xFF);
      valb -= 8;
    }
  }
  return result;
}

}  // namespace catapult