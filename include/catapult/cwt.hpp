/**
 * @file cat_cwt.hpp
 * @brief CBOR Web Token (CWT) structure and encoding/decoding
 */

#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "token.hpp"
#include "error.hpp"
#include <span>
#include <concepts>

// Forward declarations for CBOR types
typedef struct cbor_item_t cbor_item_t;

namespace catapult {

/**
 * @brief RAII wrapper for CBOR items
 */
struct CborItemDeleter {
  void operator()(cbor_item_t* item) const noexcept;
};
using CborItemPtr = std::unique_ptr<cbor_item_t, CborItemDeleter>;

/**
 * @brief RAII wrapper for CBOR buffer
 */
struct CborBufferDeleter {
  void operator()(unsigned char* buffer) const noexcept;
};
using CborBufferPtr = std::unique_ptr<unsigned char, CborBufferDeleter>;

/**
 * @brief CBOR encoding
 */
template<typename T>
concept CborEncodable = requires(T t) {
  { t.has_value() } -> std::convertible_to<bool>;
  { t.value() };
};



/**
 * @brief CWT header structure
 */
struct CwtHeader {
  int64_t alg;                        ///< Algorithm identifier
  std::optional<std::string> kid;     ///< Key ID
  std::optional<std::string> typ;     ///< Token type

  /**
   * @brief Construct a CWT header
   * @param algorithm COSE algorithm identifier
   */
  CwtHeader(int64_t algorithm) : alg(algorithm), typ("CAT") {}
};

/**
 * @brief CBOR Web Token representation
 */
class Cwt {
 public:
  CwtHeader header;                ///< CWT header
  CatToken payload;                ///< Token payload
  std::vector<uint8_t> signature;  ///< Digital signature

  /**
   * @brief Construct a CWT with algorithm and token
   * @param alg COSE algorithm identifier
   * @param token CAT token payload
   */
  Cwt(int64_t alg, const CatToken& token);

  /**
   * @brief Set the key ID in the header
   * @param kid Key identifier
   * @return Reference to this CWT for chaining
   */
  Cwt& withKeyId(const std::string& kid);

  /**
   * @brief Encode the payload to CBOR format
   * @return CBOR-encoded payload bytes
   */
  std::vector<uint8_t> encodePayload() const;
  
  /**
   * @brief Decode a payload from CBOR format
   * @param cborData CBOR-encoded data
   * @return Decoded CAT token
   */
  static CatToken decodePayload(const std::vector<uint8_t>& cborData);

};

}  // namespace catapult