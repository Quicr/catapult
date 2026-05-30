/**
 * @file cat_cwt.hpp
 * @brief CBOR Web Token (CWT) structure and encoding/decoding
 */

#pragma once

#include <concepts>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "error.hpp"
#include "token.hpp"

// Forward declarations for CBOR types
typedef struct cbor_item_t cbor_item_t;

namespace catapult {

// Forward declarations
struct AuthorizationContext;

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
template <typename T>
concept CborEncodable = requires(T t) {
  { t.has_value() } -> std::convertible_to<bool>;
  { t.value() };
};

/**
 * @brief COSE protected header fields extracted from a CWT.
 *
 * When constructed explicitly (for token creation), alg is required and typ
 * defaults to "CAT". When returned by decodeHeader(), all fields reflect
 * what was present in the wire encoding — alg may be 0 if the header was
 * malformed, and kid/typ are populated only if present in the CBOR map.
 */
struct CwtHeader {
  int64_t alg;                     ///< COSE algorithm identifier (label 1)
  std::optional<std::string> kid;  ///< Key ID (label 4), used for key routing
  std::optional<std::string> typ;  ///< Content type (label 16)

  /**
   * @brief Construct a CWT header for token creation
   * @param algorithm COSE algorithm identifier (e.g. ALG_HMAC256_256,
   * ALG_ES256)
   */
  CwtHeader(int64_t algorithm) : alg(algorithm), typ("CAT") {}
};

/**
 * @brief CWT creation mode enumeration
 */
enum class CwtMode {
  Signed,       ///< Signed CWT (COSE_Sign1) - single signature
  MultiSigned,  ///< Multi-signed CWT (COSE_Sign) - multiple signatures
  MACed,        ///< MACed CWT (COSE_Mac0)
  Encrypted     ///< Encrypted CWT (COSE_Encrypt0)
};

/**
 * @brief COSE signature structure for multi-signature support
 */
struct CoseSignature {
  std::vector<uint8_t>
      protectedHeader;             ///< Signature-specific protected header
  std::vector<uint8_t> signature;  ///< Digital signature bytes
  int64_t algorithmId;             ///< Algorithm ID for this signature

  CoseSignature(const std::vector<uint8_t>& header,
                const std::vector<uint8_t>& sig, int64_t algId)
      : protectedHeader(header), signature(sig), algorithmId(algId) {}
};

/**
 * @brief CBOR Web Token (CWT) per RFC 8392.
 *
 * Encapsulates a CAT token payload with COSE security (signing, MAC, or
 * encryption). Supports COSE_Sign1, COSE_Sign (multi-signature), COSE_Mac0,
 * and COSE_Encrypt0 envelopes.
 *
 * Typical creation flow:
 *   Cwt cwt(ALG_HMAC256_256, token);
 *   cwt.withKeyId("key-1");
 *   auto bytes = cwt.createCwt(CwtMode::MACed, hmacAlgorithm);
 *
 * Typical validation flow:
 *   auto header = Cwt::decodeHeader(bytes);  // extract kid without crypto
 *   auto cwt = Cwt::validateCwt(bytes, algorithm);  // full verification
 */
class Cwt {
 public:
  CwtHeader header;                       ///< CWT header
  CatToken payload;                       ///< Token payload
  std::vector<uint8_t> signature;         ///< Digital signature (COSE_Sign1)
  std::vector<CoseSignature> signatures;  ///< Multiple signatures (COSE_Sign)

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
   * @brief Create and sign/MAC/encrypt a CWT (RFC 8392)
   * @param mode Creation mode (Signed, MACed, or Encrypted)
   * @param algorithm Cryptographic algorithm implementation
   * @return Raw CBOR-encoded CWT bytes
   */
  std::vector<uint8_t> createCwt(
      CwtMode mode, const class CryptographicAlgorithm& algorithm) const;

  /**
   * @brief Decode the COSE protected header from a CWT without MAC/signature
   *        verification.
   *
   * Parses only the outer CBOR array and the protected-header bytestring to
   * extract routing metadata (alg, kid, typ). No cryptographic operations are
   * performed, so the returned header MUST NOT be trusted for authorization
   * decisions — use it solely to select which key to pass to validateCwt().
   *
   * @param cwtBytes Raw CBOR-encoded CWT bytes (COSE_Sign1, COSE_Mac0, or
   *                 COSE_Encrypt0)
   * @return CwtHeader populated with alg, and optionally kid and typ
   * @throws InvalidCborError if the bytes are not valid CBOR
   * @throws InvalidTokenFormatError if the structure is not a valid COSE array
   *         or the protected header cannot be decoded
   */
  static CwtHeader decodeHeader(std::span<const uint8_t> cwtBytes);

  /**
   * @brief Validate a COSE_Sign1 CWT from raw CBOR bytes (RFC 8392)
   * @param cwtBytes Raw CBOR-encoded CWT bytes
   * @param algorithm Cryptographic algorithm implementation
   * @return Decoded and verified CWT instance
   * @throws CryptoError if validation fails
   * @throws InvalidTokenFormatError if token is COSE_Sign format
   */
  static Cwt validateCwt(std::span<const uint8_t> cwtBytes,
                         const class CryptographicAlgorithm& algorithm);

  /**
   * @brief Validate a multi-signed CWT with per-signature algorithms
   * @param cwtBytes Raw CBOR-encoded CWT bytes
   * @param algorithms Map of algorithm ID to cryptographic algorithm
   * @return Decoded and verified CWT instance
   * @throws CryptoError if validation fails
   */
  static Cwt validateMultiSignedCwt(
      std::span<const uint8_t> cwtBytes,
      const std::map<
          int64_t, std::reference_wrapper<const class CryptographicAlgorithm>>&
          algorithms);

  // Base64url convenience helpers

  /**
   * @brief Create CWT and return as base64url-encoded string
   */
  std::string createCwtBase64(
      CwtMode mode, const class CryptographicAlgorithm& algorithm) const;

  /**
   * @brief Validate a base64url-encoded CWT string
   */
  static Cwt validateCwtBase64(const std::string& encodedCwt,
                               const class CryptographicAlgorithm& algorithm);

  /**
   * @brief Validate a base64url-encoded multi-signed CWT
   */
  static Cwt validateMultiSignedCwtBase64(
      const std::string& encodedCwt,
      const std::map<
          int64_t, std::reference_wrapper<const class CryptographicAlgorithm>>&
          algorithms);

  /**
   * @brief Create COSE header for the CWT
   * @return CBOR-encoded COSE header bytes
   */
  std::vector<uint8_t> createCoseHeader() const;

  /**
   * @brief Create DPoP signing input from authorization context
   * @param actx Authorization context containing DPoP claims
   * @param iat Issued at timestamp
   * @param jti Optional JWT ID
   * @param ath Optional access token hash
   * @return CBOR-encoded DPoP signing input bytes
   */
  static std::vector<uint8_t> createDpopSigningInput(
      const struct AuthorizationContext& actx, int64_t iat,
      const std::optional<std::string>& jti = std::nullopt,
      const std::optional<std::string>& ath = std::nullopt);
};

}  // namespace catapult