/**
 * @file jwk.hpp
 * @brief JSON Web Key (JWK) utilities for cryptographic operations
 *
 * This file provides utilities for creating JWK representations of
 * cryptographic keys and calculating JWK thumbprints according to RFC 7517 and
 * RFC 7638.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace catapult {

/**
 * @brief JWK utilities namespace
 */
namespace jwk {

/**
 * @brief Create ES256 JWK from DER-encoded public key
 * @param public_key_der DER-encoded public key bytes
 * @return JWK JSON string
 * @throws CryptoError if key parsing or extraction fails
 */
std::string createES256JWK(const std::vector<uint8_t>& public_key_der);

/**
 * @brief Create PS256 JWK from DER-encoded public key
 * @param public_key_der DER-encoded public key bytes
 * @return JWK JSON string
 * @throws CryptoError if key parsing or extraction fails
 */
std::string createPS256JWK(const std::vector<uint8_t>& public_key_der);

/**
 * @brief Calculate JWK thumbprint using SHA-256
 * @param jwk_json JWK in JSON string format
 * @return Base64url-encoded thumbprint
 * @throws CryptoError if JWK format is invalid or unsupported
 */
std::string calculateJWKThumbprint(const std::string& jwk_json);

/**
 * @brief Create JWK from algorithm-specific public key
 * @param algorithm_id COSE algorithm identifier (ALG_ES256, ALG_PS256, etc.)
 * @param public_key_der DER-encoded public key bytes
 * @return JWK JSON string
 * @throws CryptoError if algorithm is unsupported or key parsing fails
 */
std::string createJWKFromAlgorithm(int64_t algorithm_id,
                                   const std::vector<uint8_t>& public_key_der);

}  // namespace jwk
}  // namespace catapult