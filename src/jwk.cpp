/**
 * @file jwk.cpp
 * @brief Implementation of JSON Web Key (JWK) utilities
 */

#include "catapult/jwk.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>

#include <nlohmann/json.hpp>

#include "catapult/base64.hpp"
#include "catapult/crypto.hpp"
#include "catapult/error.hpp"

using json = nlohmann::json;

namespace catapult {
namespace jwk {

std::string createES256JWK(const std::vector<uint8_t>& public_key_der) {
  // Parse DER-encoded public key using modern OpenSSL 3.0 API
  const uint8_t* data = public_key_der.data();
  EVP_PKEY* pkey =
      d2i_PUBKEY(nullptr, &data, static_cast<long>(public_key_der.size()));
  if (!pkey) {
    throw CryptoError("Failed to parse public key DER");
  }

  // Extract EC parameters using OpenSSL 3.0 API
  BIGNUM* x = BN_new();
  BIGNUM* y = BN_new();

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
  json jwk = {{"kty", "EC"},
              {"crv", "P-256"},
              {"x", base64UrlEncode(x_bytes)},
              {"y", base64UrlEncode(y_bytes)}};

  return jwk.dump();
}

std::string createPS256JWK(const std::vector<uint8_t>& public_key_der) {
  const uint8_t* data = public_key_der.data();
  EVP_PKEY* pkey =
      d2i_PUBKEY(nullptr, &data, static_cast<long>(public_key_der.size()));
  if (!pkey) {
    throw CryptoError("Failed to parse RSA public key DER");
  }
  if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
    EVP_PKEY_free(pkey);
    throw CryptoError("createPS256JWK requires an RSA key");
  }

  const int bits = EVP_PKEY_bits(pkey);
  if (bits < static_cast<int>(crypto_constants::PS256_MIN_MODULUS_BITS) ||
      bits > static_cast<int>(crypto_constants::PS256_MAX_MODULUS_BITS)) {
    EVP_PKEY_free(pkey);
    throw CryptoError("RSA modulus out of policy range for PS256 JWK");
  }

  BIGNUM* n = nullptr;
  BIGNUM* e = nullptr;
  if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) ||
      !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e)) {
    if (n) BN_free(n);
    if (e) BN_free(e);
    EVP_PKEY_free(pkey);
    throw CryptoError("Failed to extract RSA n/e");
  }
  EVP_PKEY_free(pkey);

  // RFC 7518 §6.3.1: `n` and `e` are big-endian with leading zero bytes
  // removed. BN_bn2bin produces exactly that (minimum representation).
  // BN_num_bytes returns `int`; verify it is strictly positive before
  // widening to size_t so a malformed BIGNUM (NULL or zero) cannot
  // produce a bogus allocation or an underflow.
  const int n_len = BN_num_bytes(n);
  const int e_len = BN_num_bytes(e);
  if (n_len <= 0 || e_len <= 0) {
    BN_free(n);
    BN_free(e);
    throw CryptoError("Invalid RSA JWK: non-positive n or e length");
  }
  std::vector<uint8_t> n_bytes(static_cast<size_t>(n_len));
  std::vector<uint8_t> e_bytes(static_cast<size_t>(e_len));
  if (BN_bn2bin(n, n_bytes.data()) != n_len ||
      BN_bn2bin(e, e_bytes.data()) != e_len) {
    BN_free(n);
    BN_free(e);
    throw CryptoError("Failed to serialize RSA n/e");
  }
  BN_free(n);
  BN_free(e);

  json j = {{"kty", "RSA"},
            {"alg", "PS256"},
            {"n", base64UrlEncode(n_bytes)},
            {"e", base64UrlEncode(e_bytes)}};
  return j.dump();
}

std::string calculateJWKThumbprint(const std::string& jwk_json) {
  // Prevent DoS from oversized JSON input
  constexpr size_t MAX_JWK_SIZE = 8192;
  if (jwk_json.size() > MAX_JWK_SIZE) {
    throw CryptoError("JWK exceeds maximum allowed size");
  }

  json jwk = json::parse(jwk_json);

  // Validate required fields exist
  if (!jwk.contains("kty")) {
    throw CryptoError("JWK missing required 'kty' field");
  }

  // Create canonical JWK for thumbprint calculation per RFC 7638
  json canonical;

  if (jwk["kty"] == "EC") {
    // Validate EC-specific required fields
    if (!jwk.contains("crv") || !jwk.contains("x") || !jwk.contains("y")) {
      throw CryptoError("EC JWK missing required fields (crv, x, y)");
    }
    canonical = {{"crv", jwk["crv"]},
                 {"kty", jwk["kty"]},
                 {"x", jwk["x"]},
                 {"y", jwk["y"]}};
  } else if (jwk["kty"] == "RSA") {
    // RFC 7638 §3.2 canonical form for RSA keys: only `e`, `kty`, `n` in
    // lexicographic order. Any extra JWK fields (`alg`, `kid`, `use`, ...)
    // MUST be excluded from the thumbprint input.
    if (!jwk.contains("n") || !jwk.contains("e")) {
      throw CryptoError("RSA JWK missing required fields (n, e)");
    }
    canonical = {{"e", jwk["e"]}, {"kty", jwk["kty"]}, {"n", jwk["n"]}};
  } else {
    throw CryptoError("Unsupported key type for thumbprint: " +
                      jwk["kty"].get<std::string>());
  }

  // Serialize canonical JWK (lexicographic ordering is maintained by
  // nlohmann::json)
  std::string canonical_str = canonical.dump();
  std::vector<uint8_t> canonical_bytes(canonical_str.begin(),
                                       canonical_str.end());

  // Calculate SHA-256 hash
  auto hash = hashSha256(canonical_bytes);

  // Return base64url-encoded hash
  return base64UrlEncode(hash);
}

std::string createJWKFromAlgorithm(int64_t algorithm_id,
                                   const std::vector<uint8_t>& public_key_der) {
  switch (algorithm_id) {
    case ALG_ES256:
      return createES256JWK(public_key_der);
    case ALG_PS256:
      return createPS256JWK(public_key_der);
    default:
      throw CryptoError("Unsupported algorithm for JWK creation: " +
                        std::to_string(algorithm_id));
  }
}

}  // namespace jwk
}  // namespace catapult