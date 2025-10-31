/**
 * @file cat_cwt.hpp
 * @brief CBOR Web Token (CWT) structure and encoding/decoding
 */

#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include <map>
#include <functional>

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
 * @brief CWT creation mode enumeration
 */
enum class CwtMode {
  Signed,      ///< Signed CWT (COSE_Sign1) - single signature
  MultiSigned, ///< Multi-signed CWT (COSE_Sign) - multiple signatures
  MACed,       ///< MACed CWT (COSE_Mac0)
  Encrypted    ///< Encrypted CWT (COSE_Encrypt0)
};

/**
 * @brief COSE signature structure for multi-signature support
 */
struct CoseSignature {
  std::vector<uint8_t> protectedHeader;   ///< Signature-specific protected header
  std::vector<uint8_t> signature;         ///< Digital signature bytes
  int64_t algorithmId;                     ///< Algorithm ID for this signature
  
  CoseSignature(const std::vector<uint8_t>& header, const std::vector<uint8_t>& sig, int64_t algId)
    : protectedHeader(header), signature(sig), algorithmId(algId) {}
};

/**
 * @brief CBOR Web Token representation
 */
class Cwt {
 public:
  CwtHeader header;                           ///< CWT header
  CatToken payload;                           ///< Token payload
  std::vector<uint8_t> signature;             ///< Digital signature (COSE_Sign1)
  std::vector<CoseSignature> signatures;      ///< Multiple signatures (COSE_Sign)

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
   * @brief Add a signature for COSE_Sign (multi-signature) mode.
   * @param algorithm Cryptographic algorithm for this signature
   * @param signatureHeader Optional signature-specific protected header
   * @return Reference to this CWT for chaining
   */
  Cwt& addSignature(const class CryptographicAlgorithm& algorithm, 
                    const std::vector<uint8_t>& signatureHeader = {});

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

  /**
   * @brief Create and sign/MAC/encrypt a complete CWT according to RFC 8392 Section 7
   * @param mode Creation mode (Signed, MACed, or Encrypted)
   * @param algorithm Cryptographic algorithm implementation
   * @return Base64url-encoded CWT string
   */
  std::string createCwt(CwtMode mode, const class CryptographicAlgorithm& algorithm) const;

  /**
   * @brief Validate a base64url-encoded COSE_Sign1 CWT according to RFC 8392 Section 7
   * @param encodedCwt Base64url-encoded CWT string (must be COSE_Sign1 format)
   * @param algorithm Cryptographic algorithm implementation
   * @return Decoded and verified CWT instance
   * @throws CryptoError if validation fails
   * @throws InvalidTokenFormatError if token is COSE_Sign format (use validateMultiSignedCwt)
   */
  static Cwt validateCwt(const std::string& encodedCwt, 
                         const class CryptographicAlgorithm& algorithm);

  /**
   * @brief Validate a multi-signed CWT with per-signature algorithms
   * @param encodedCwt Base64url-encoded CWT string
   * @param algorithms Map of algorithm ID to cryptographic algorithm implementation
   * @return Decoded and verified CWT instance
   * @throws CryptoError if validation fails
   */
  static Cwt validateMultiSignedCwt(const std::string& encodedCwt,
                                   const std::map<int64_t, std::reference_wrapper<const class CryptographicAlgorithm>>& algorithms);

  /**
   * @brief Create COSE header for the CWT
   * @return CBOR-encoded COSE header bytes
   */
  std::vector<uint8_t> createCoseHeader() const;

};

}  // namespace catapult