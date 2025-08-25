/**
 * @file cat_base64.hpp
 * @brief Base64 URL encoding and decoding utilities for CAT tokens
 */

#pragma once

#include <concepts>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "cat_error.hpp"

namespace catapult {

/**
 * @brief Implementation for base64url encoding from span
 * @param data Input byte span
 * @return Base64url string
 */
std::string base64UrlEncodeImpl(std::span<const uint8_t> data);

/**
 * @brief Concept for data types suitable for base64 encoding
 */
template <typename T>
concept Base64Data = requires(T t) {
  std::data(t);
  std::size(t);
  typename T::value_type;
  requires std::same_as<typename T::value_type, uint8_t>;
};

/**
 * @brief Encode data as base64url
 * @param data Input bytes
 * @return Base64url string
 */
template <Base64Data T>
std::string base64UrlEncode(const T& data) {
  return base64UrlEncodeImpl({std::data(data), std::size(data)});
}

/**
 * @brief Decode base64url string
 * @param data Base64url string
 * @return Decoded bytes
 * @throws InvalidBase64Error if invalid characters found
 */
std::vector<uint8_t> base64UrlDecode(std::string_view data);

}  // namespace catapult