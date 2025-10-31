/**
 * @file jwk.cpp
 * @brief Implementation of JSON Web Key (JWK) utilities
 */

#include "catapult/jwk.hpp"
#include "catapult/base64.hpp"
#include "catapult/crypto.hpp"
#include "catapult/error.hpp"

#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

using json = nlohmann::json;

namespace catapult {
namespace jwk {

std::string createES256JWK(const std::vector<uint8_t>& public_key_der) {
  // Parse DER-encoded public key using modern OpenSSL 3.0 API
  const uint8_t* data = public_key_der.data();
  EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &data, public_key_der.size());
  if (!pkey) {
    throw CryptoError("Failed to parse public key DER");
  }

  // Extract EC parameters using OpenSSL 3.0 API
  BIGNUM* x = BN_new();
  BIGNUM* y = BN_new();
  
  size_t x_len = 0, y_len = 0;
  
  // Get the raw EC point coordinates
  if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x) ||
      !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y)) {
    BN_free(x);
    BN_free(y);
    EVP_PKEY_free(pkey);
    throw CryptoError("Failed to extract EC point coordinates");
  }

  // Convert to 32-byte arrays (for P-256)
  std::vector<uint8_t> x_bytes(32);
  std::vector<uint8_t> y_bytes(32);
  
  if (BN_bn2binpad(x, x_bytes.data(), 32) != 32 ||
      BN_bn2binpad(y, y_bytes.data(), 32) != 32) {
    BN_free(x);
    BN_free(y);
    EVP_PKEY_free(pkey);
    throw CryptoError("Failed to convert EC coordinates to bytes");
  }

  BN_free(x);
  BN_free(y);
  EVP_PKEY_free(pkey);

  // Create JWK JSON
  json jwk = {
    {"kty", "EC"},
    {"crv", "P-256"},
    {"x", base64UrlEncode(x_bytes)},
    {"y", base64UrlEncode(y_bytes)}
  };

  return jwk.dump();
}

std::string createPS256JWK(const std::vector<uint8_t>& public_key_der) {
  // Parse DER-encoded public key using modern OpenSSL 3.0 API
  const uint8_t* data = public_key_der.data();
  EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &data, public_key_der.size());
  if (!pkey) {
    throw CryptoError("Failed to parse public key DER");
  }

  // Extract RSA parameters using OpenSSL 3.0 API
  BIGNUM* n = nullptr;
  BIGNUM* e = nullptr;

  if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) ||
      !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e)) {
    if (n) BN_free(n);
    if (e) BN_free(e);
    EVP_PKEY_free(pkey);
    throw CryptoError("Failed to extract RSA parameters");
  }

  // Convert to byte arrays
  int n_len = BN_num_bytes(n);
  int e_len = BN_num_bytes(e);

  std::vector<uint8_t> n_bytes(n_len);
  std::vector<uint8_t> e_bytes(e_len);

  BN_bn2bin(n, n_bytes.data());
  BN_bn2bin(e, e_bytes.data());

  BN_free(n);
  BN_free(e);
  EVP_PKEY_free(pkey);

  // Create JWK JSON
  json jwk = {
    {"kty", "RSA"},
    {"n", base64UrlEncode(n_bytes)},
    {"e", base64UrlEncode(e_bytes)}
  };

  return jwk.dump();
}

std::string calculateJWKThumbprint(const std::string& jwk_json) {
  json jwk = json::parse(jwk_json);

  // Create canonical JWK for thumbprint calculation per RFC 7638
  json canonical;

  if (jwk["kty"] == "EC") {
    canonical = {
      {"crv", jwk["crv"]},
      {"kty", jwk["kty"]},
      {"x", jwk["x"]},
      {"y", jwk["y"]}
    };
  } else if (jwk["kty"] == "RSA") {
    canonical = {
      {"e", jwk["e"]},
      {"kty", jwk["kty"]},
      {"n", jwk["n"]}
    };
  } else {
    throw CryptoError("Unsupported key type for thumbprint: " + jwk["kty"].get<std::string>());
  }

  // Serialize canonical JWK (lexicographic ordering is maintained by nlohmann::json)
  std::string canonical_str = canonical.dump();
  std::vector<uint8_t> canonical_bytes(canonical_str.begin(), canonical_str.end());

  // Calculate SHA-256 hash
  auto hash = hashSha256(canonical_bytes);

  // Return base64url-encoded hash
  return base64UrlEncode(hash);
}

std::string createJWKFromAlgorithm(int64_t algorithm_id, const std::vector<uint8_t>& public_key_der) {
  switch (algorithm_id) {
    case ALG_ES256:
      return createES256JWK(public_key_der);
    case ALG_PS256:
      return createPS256JWK(public_key_der);
    default:
      throw CryptoError("Unsupported algorithm for JWK creation: " + std::to_string(algorithm_id));
  }
}

} // namespace jwk
} // namespace catapult