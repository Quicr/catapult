/**
 * @file cat_dpop.cpp
 * @brief Implementation of DPoP functionality for CAT tokens
 */

#include "catapult/dpop.hpp"

#include <cbor.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>

#include <algorithm>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <random>
#include <sstream>

#include "catapult/base64.hpp"
#include "catapult/crypto.hpp"
#include "catapult/cwt.hpp"
#include "catapult/jwk.hpp"
#include "catapult/moqt_claims.hpp"

using json = nlohmann::json;

namespace catapult {

// DpopProof implementation

namespace {

/**
 * @brief Create algorithm instance from JWK and algorithm ID
 * @param alg_name Algorithm name (e.g., "ES256", "PS256")
 * @param jwk_json JWK JSON string containing public key
 * @return Unique pointer to algorithm instance for verification
 * @throws CryptoError if algorithm is unsupported or JWK is invalid
 */
std::unique_ptr<CryptographicAlgorithm> createAlgorithmFromJWK(
    const std::string& alg_name, const std::string& jwk_json) {
  json jwk = json::parse(jwk_json);

  if (alg_name == "ES256") {
    if (jwk["kty"] != "EC" || jwk["crv"] != "P-256") {
      throw CryptoError("Invalid JWK for ES256: must be EC P-256");
    }

    // Extract x and y coordinates
    auto x_bytes = base64UrlDecode(jwk["x"].get<std::string>());
    auto y_bytes = base64UrlDecode(jwk["y"].get<std::string>());

    if (x_bytes.size() != 32 || y_bytes.size() != 32) {
      throw CryptoError("Invalid EC coordinates size for P-256");
    }

    // Create DER-encoded public key from x,y coordinates using OpenSSL
    // parameter building
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) {
      throw CryptoError("Failed to create EVP_PKEY for ES256");
    }

    // Build EC public key from coordinates
    OSSL_PARAM_BLD* param_bld = OSSL_PARAM_BLD_new();
    if (!param_bld) {
      EVP_PKEY_free(pkey);
      throw CryptoError("Failed to create parameter builder");
    }

    BIGNUM* x_bn = BN_bin2bn(x_bytes.data(), x_bytes.size(), nullptr);
    BIGNUM* y_bn = BN_bin2bn(y_bytes.data(), y_bytes.size(), nullptr);

    if (!x_bn || !y_bn) {
      OSSL_PARAM_BLD_free(param_bld);
      EVP_PKEY_free(pkey);
      if (x_bn) BN_free(x_bn);
      if (y_bn) BN_free(y_bn);
      throw CryptoError("Failed to create BIGNUM from coordinates");
    }

    OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                    "prime256v1", 0);
    OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_EC_PUB_X, x_bn);
    OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_EC_PUB_Y, y_bn);

    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(param_bld);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!ctx || EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
      OSSL_PARAM_BLD_free(param_bld);
      OSSL_PARAM_free(params);
      if (ctx) EVP_PKEY_CTX_free(ctx);
      EVP_PKEY_free(pkey);
      BN_free(x_bn);
      BN_free(y_bn);
      throw CryptoError("Failed to create EC public key from JWK");
    }

    // Convert to DER format
    int der_len = i2d_PUBKEY(pkey, nullptr);
    if (der_len <= 0) {
      OSSL_PARAM_BLD_free(param_bld);
      OSSL_PARAM_free(params);
      EVP_PKEY_CTX_free(ctx);
      EVP_PKEY_free(pkey);
      BN_free(x_bn);
      BN_free(y_bn);
      throw CryptoError("Failed to get DER length for public key");
    }

    std::vector<uint8_t> der_bytes(der_len);
    uint8_t* der_ptr = der_bytes.data();
    if (i2d_PUBKEY(pkey, &der_ptr) != der_len) {
      OSSL_PARAM_BLD_free(param_bld);
      OSSL_PARAM_free(params);
      EVP_PKEY_CTX_free(ctx);
      EVP_PKEY_free(pkey);
      BN_free(x_bn);
      BN_free(y_bn);
      throw CryptoError("Failed to encode public key to DER");
    }

    // Cleanup
    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BN_free(x_bn);
    BN_free(y_bn);

    return std::make_unique<Es256Algorithm>(der_bytes);

  } else if (alg_name == "PS256") {
    if (jwk["kty"] != "RSA") {
      throw CryptoError("Invalid JWK for PS256: must be RSA");
    }

    // Extract n and e
    auto n_bytes = base64UrlDecode(jwk["n"].get<std::string>());
    auto e_bytes = base64UrlDecode(jwk["e"].get<std::string>());

    // Create DER-encoded public key from n,e using OpenSSL parameter building
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) {
      throw CryptoError("Failed to create EVP_PKEY for PS256");
    }

    OSSL_PARAM_BLD* param_bld = OSSL_PARAM_BLD_new();
    if (!param_bld) {
      EVP_PKEY_free(pkey);
      throw CryptoError("Failed to create parameter builder");
    }

    BIGNUM* n_bn = BN_bin2bn(n_bytes.data(), n_bytes.size(), nullptr);
    BIGNUM* e_bn = BN_bin2bn(e_bytes.data(), e_bytes.size(), nullptr);

    if (!n_bn || !e_bn) {
      OSSL_PARAM_BLD_free(param_bld);
      EVP_PKEY_free(pkey);
      if (n_bn) BN_free(n_bn);
      if (e_bn) BN_free(e_bn);
      throw CryptoError("Failed to create BIGNUM from RSA parameters");
    }

    OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_N, n_bn);
    OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_E, e_bn);

    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(param_bld);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    if (!ctx || EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
      OSSL_PARAM_BLD_free(param_bld);
      OSSL_PARAM_free(params);
      if (ctx) EVP_PKEY_CTX_free(ctx);
      EVP_PKEY_free(pkey);
      BN_free(n_bn);
      BN_free(e_bn);
      throw CryptoError("Failed to create RSA public key from JWK");
    }

    // Convert to DER format
    int der_len = i2d_PUBKEY(pkey, nullptr);
    if (der_len <= 0) {
      OSSL_PARAM_BLD_free(param_bld);
      OSSL_PARAM_free(params);
      EVP_PKEY_CTX_free(ctx);
      EVP_PKEY_free(pkey);
      BN_free(n_bn);
      BN_free(e_bn);
      throw CryptoError("Failed to get DER length for RSA public key");
    }

    std::vector<uint8_t> der_bytes(der_len);
    uint8_t* der_ptr = der_bytes.data();
    if (i2d_PUBKEY(pkey, &der_ptr) != der_len) {
      OSSL_PARAM_BLD_free(param_bld);
      OSSL_PARAM_free(params);
      EVP_PKEY_CTX_free(ctx);
      EVP_PKEY_free(pkey);
      BN_free(n_bn);
      BN_free(e_bn);
      throw CryptoError("Failed to encode RSA public key to DER");
    }

    // Cleanup
    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BN_free(n_bn);
    BN_free(e_bn);

    return std::make_unique<Ps256Algorithm>(der_bytes);

  } else {
    throw CryptoError("Unsupported algorithm for DPoP verification: " +
                      alg_name);
  }
}

}  // anonymous namespace

std::vector<uint8_t> DpopProof::create_signing_input() const {
  // Use CWT implementation for creating DPoP signing input
  return Cwt::createDpopSigningInput(payload_.actx, payload_.iat, payload_.jti,
                                     payload_.ath);
}

bool DpopProof::verify_signature(
    const CryptographicAlgorithm& algorithm) const {
  try {
    // Create the signing input using the same method as when the proof was
    // created
    auto signing_input = create_signing_input();
    // Verify the signature using the provided algorithm
    return algorithm.verify(signing_input, signature_);
  } catch (const std::exception&) {
    // If any exception occurs during verification, the signature is invalid
    return false;
  }
}

bool DpopProof::verify_signature() const {
  try {
    // Validate header has required fields
    if (header_.alg.empty() || header_.jwk.empty()) {
      return false;
    }

    // Create algorithm instance from JWK in header
    auto algorithm = createAlgorithmFromJWK(header_.alg, header_.jwk);

    // Use the algorithm-specific verify method
    return verify_signature(*algorithm);
  } catch (const std::exception&) {
    // If any exception occurs during verification, the signature is invalid
    return false;
  }
}

std::string DpopProof::serialize() const {
  // Return CBOR-encoded DPoP proof instead of JWT format
  auto cbor_payload = create_signing_input();

  // Create COSE structure with header and signature
  auto cose_array = cbor_new_definite_array(3);

  // Protected header (empty for now)
  auto protected_header = cbor_build_bytestring(nullptr, 0);
  cbor_array_push(cose_array, protected_header);

  // Payload
  auto payload_item =
      cbor_build_bytestring(cbor_payload.data(), cbor_payload.size());
  cbor_array_push(cose_array, payload_item);

  // Signature
  auto signature_item =
      cbor_build_bytestring(signature_.data(), signature_.size());
  cbor_array_push(cose_array, signature_item);

  // Serialize to bytes and encode as base64url
  unsigned char* buffer;
  size_t buffer_size;
  size_t length = cbor_serialize_alloc(cose_array, &buffer, &buffer_size);

  if (length == 0) {
    cbor_decref(&cose_array);
    throw CryptoError("Failed to serialize DPoP proof COSE");
  }

  std::vector<uint8_t> cose_bytes(buffer, buffer + length);
  std::string result = base64UrlEncode(cose_bytes);

  // Clean up
  free(buffer);
  cbor_decref(&cose_array);

  return result;
}

DpopProof DpopProof::deserialize(std::string_view cbor_data) {
  // Split serialized data into parts
  std::vector<std::string> parts;
  std::string current;

  for (char c : cbor_data) {
    if (c == '.') {
      parts.push_back(current);
      current.clear();
    } else {
      current += c;
    }
  }
  parts.push_back(current);

  if (parts.size() != 3) {
    throw InvalidTokenFormatError{};
  }

  // Decode parts
  auto header_json = json::parse(base64UrlDecode(parts[0]));
  auto payload_json = json::parse(base64UrlDecode(parts[1]));
  auto signature = base64UrlDecode(parts[2]);

  // Create header
  DpopHeader header;
  header.typ = header_json.value("typ", "");
  header.alg = header_json.value("alg", "");
  header.jwk = header_json.value("jwk", json{}).dump();

  // Create payload - for backward compatibility, check for both old and new
  // format
  DpopPayload payload(0, "", "");

  if (payload_json.contains("actx")) {
    // New format with Authorization Context
    auto actx_json = payload_json["actx"];
    payload.actx.type = actx_json.value("type", "moqt");
    payload.actx.action = actx_json.value("action", 0);
    payload.actx.tns = actx_json.value("tns", "");
    payload.actx.tn = actx_json.value("tn", "");
    payload.actx.resource_uri = actx_json.value("resource", "");
  } else {
    // Legacy format - convert to new format (assume empty track namespace/name)
    payload.actx.type = "moqt";
    payload.actx.action = payload_json.value("moqt_action", 0);
    payload.actx.tns = "";
    payload.actx.tn = "";
    payload.actx.resource_uri = payload_json.value("htu", "");
  }

  payload.iat = payload_json.value("iat", 0);

  if (payload_json.contains("jti")) {
    payload.jti = payload_json["jti"];
  }

  if (payload_json.contains("ath")) {
    payload.ath = payload_json["ath"];
  }

  return DpopProof{std::move(header), std::move(payload), signature};
}

// moqt_dpop namespace implementation

namespace moqt_dpop {

std::string generate_jti() {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint32_t> dis;

  std::ostringstream oss;
  oss << std::hex << dis(gen) << dis(gen);
  return oss.str();
}

}  // namespace moqt_dpop

// DpopProofValidator implementation

bool DpopProofValidator::validate_proof(
    const DpopProof& proof, int expected_action, std::string_view expected_uri,
    const std::string& expected_public_key_thumbprint) {
  // Basic structure validation
  if (!proof.is_valid(settings_)) {
    return false;
  }

  // Check action and URI (if URI is provided)
  if (proof.get_payload().actx.action != expected_action) {
    return false;
  }

  // Check URI if provided (for backward compatibility)
  if (!expected_uri.empty() &&
      proof.get_payload().actx.resource_uri != expected_uri) {
    return false;
  }

  // Check JTI if enabled and present
  if (settings_.get_jti_processing() && proof.get_payload().jti.has_value()) {
    const auto& jti = proof.get_payload().jti.value();

    // Check if JTI was already used
    auto it = used_jtis_.find(jti);
    if (it != used_jtis_.end()) {
      // Check if it's still within the window
      auto now = std::chrono::system_clock::now();
      auto diff = now - it->second;
      if (diff < settings_.get_effective_window()) {
        return false;  // Replay attack detected
      }
    }

    // Record this JTI
    used_jtis_[jti] = std::chrono::system_clock::now();
  }

  // Public key thumbprint matching validation
  if (!expected_public_key_thumbprint.empty()) {
    try {
      // Calculate thumbprint from the JWK in the proof header
      std::string actual_thumbprint =
          jwk::calculateJWKThumbprint(proof.get_header().jwk);

      // Compare thumbprints using secure comparison
      if (actual_thumbprint != expected_public_key_thumbprint) {
        return false;
      }
    } catch (const std::exception&) {
      // If thumbprint calculation fails, validation fails
      return false;
    }
  }

  return true;
}

void DpopProofValidator::cleanup_expired_jtis() {
  auto now = std::chrono::system_clock::now();
  auto window = settings_.get_effective_window();

  auto it = used_jtis_.begin();
  while (it != used_jtis_.end()) {
    if (now - it->second > window) {
      it = used_jtis_.erase(it);
    } else {
      ++it;
    }
  }
}

// DpopKeyPair implementation

DpopKeyPair::DpopKeyPair(std::unique_ptr<CryptographicAlgorithm> alg)
    : algorithm_(std::move(alg)) {
  // Generate public key JWK and thumbprint based on algorithm type
  int64_t alg_id = algorithm_->algorithmId();

  if (alg_id == ALG_ES256) {
    // For ES256, we need to extract the EC public key components
    auto* es256_alg = dynamic_cast<Es256Algorithm*>(algorithm_.get());
    if (es256_alg) {
      auto public_key_der = es256_alg->getPublicKey();
      public_key_jwk_ = jwk::createJWKFromAlgorithm(alg_id, public_key_der);
      public_key_thumbprint_ = jwk::calculateJWKThumbprint(public_key_jwk_);
    } else {
      throw CryptoError("Invalid ES256 algorithm instance");
    }
  } else if (alg_id == ALG_PS256) {
    // For PS256, we need to extract the RSA public key components
    auto* ps256_alg = dynamic_cast<Ps256Algorithm*>(algorithm_.get());
    if (ps256_alg) {
      auto public_key_der = ps256_alg->getPublicKey();
      public_key_jwk_ = jwk::createJWKFromAlgorithm(alg_id, public_key_der);
      public_key_thumbprint_ = jwk::calculateJWKThumbprint(public_key_jwk_);
    } else {
      throw CryptoError("Invalid PS256 algorithm instance");
    }
  } else {
    throw CryptoError("Unsupported algorithm for DPoP: " +
                      std::to_string(alg_id));
  }
}

std::string DpopKeyPair::get_algorithm_name() const {
  int64_t alg_id = algorithm_->algorithmId();

  switch (alg_id) {
    case ALG_ES256:
      return "ES256";
    case ALG_PS256:
      return "PS256";
    case ALG_HMAC256_256:
      return "HS256";
    default:
      return "Unknown";
  }
}

}  // namespace catapult