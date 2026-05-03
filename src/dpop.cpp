/**
 * @file cat_dpop.cpp
 * @brief Implementation of DPoP functionality for CAT tokens
 *
 * Supports both CWT (CBOR) and JWT (JSON) encoding formats per
 * draft-nandakumar-moq-generic-dpop-proof-00
 */

#include "catapult/dpop.hpp"

#include <cbor.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>

#include <algorithm>
#include <iomanip>
#include <random>
#include <sstream>

#ifdef CATAPULT_ENABLE_JSON
#include <nlohmann/json.hpp>
#include "catapult/jwk.hpp"
using json = nlohmann::json;
#endif

#include "catapult/base64.hpp"
#include "catapult/crypto.hpp"
#include "catapult/cwt.hpp"
#include "catapult/moqt_claims.hpp"

namespace catapult {

// DpopProof implementation

namespace {

/**
 * @brief Create COSE_Key from DER-encoded public key
 */
std::vector<uint8_t> createCoseKeyFromDer(int64_t alg_id,
                                          const std::vector<uint8_t>& der_key) {
  const uint8_t* data = der_key.data();
  EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &data, static_cast<long>(der_key.size()));
  if (!pkey) {
    throw CryptoError("Failed to parse DER public key for COSE_Key");
  }

  cbor_item_t* cose_key = cbor_new_definite_map(5);
  if (!cose_key) {
    EVP_PKEY_free(pkey);
    throw CryptoError("Failed to create COSE_Key map");
  }

  if (alg_id == ALG_ES256) {
    BIGNUM* x = nullptr;
    BIGNUM* y = nullptr;

    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x) ||
        !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y)) {
      EVP_PKEY_free(pkey);
      cbor_decref(&cose_key);
      throw CryptoError("Failed to extract EC coordinates");
    }

    std::vector<uint8_t> x_bytes(32), y_bytes(32);
    BN_bn2binpad(x, x_bytes.data(), 32);
    BN_bn2binpad(y, y_bytes.data(), 32);
    BN_free(x);
    BN_free(y);

    // kty: EC (2), alg: ES256 (-7), crv: P-256 (1), x, y
    (void)cbor_map_add(cose_key, {cbor_build_uint8(1), cbor_build_uint8(2)});
    (void)cbor_map_add(cose_key, {cbor_build_uint8(3), cbor_build_negint8(6)});
    (void)cbor_map_add(cose_key, {cbor_build_negint8(0), cbor_build_uint8(1)});
    (void)cbor_map_add(cose_key, {cbor_build_negint8(1),
                           cbor_build_bytestring(x_bytes.data(), x_bytes.size())});
    (void)cbor_map_add(cose_key, {cbor_build_negint8(2),
                           cbor_build_bytestring(y_bytes.data(), y_bytes.size())});
  } else if (alg_id == ALG_PS256) {
    BIGNUM* n = nullptr;
    BIGNUM* e = nullptr;

    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) ||
        !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e)) {
      EVP_PKEY_free(pkey);
      cbor_decref(&cose_key);
      throw CryptoError("Failed to extract RSA parameters");
    }

    int n_len = BN_num_bytes(n);
    int e_len = BN_num_bytes(e);
    std::vector<uint8_t> n_bytes(n_len), e_bytes(e_len);
    BN_bn2bin(n, n_bytes.data());
    BN_bn2bin(e, e_bytes.data());
    BN_free(n);
    BN_free(e);

    // kty: RSA (3), alg: PS256 (-37), n, e
    (void)cbor_map_add(cose_key, {cbor_build_uint8(1), cbor_build_uint8(3)});
    (void)cbor_map_add(cose_key, {cbor_build_uint8(3), cbor_build_negint8(36)});
    (void)cbor_map_add(cose_key, {cbor_build_negint8(0),
                           cbor_build_bytestring(n_bytes.data(), n_bytes.size())});
    (void)cbor_map_add(cose_key, {cbor_build_negint8(1),
                           cbor_build_bytestring(e_bytes.data(), e_bytes.size())});
  } else {
    EVP_PKEY_free(pkey);
    cbor_decref(&cose_key);
    throw CryptoError("Unsupported algorithm for COSE_Key: " +
                      std::to_string(alg_id));
  }

  EVP_PKEY_free(pkey);

  unsigned char* buffer = nullptr;
  size_t buffer_size = 0;
  size_t length = cbor_serialize_alloc(cose_key, &buffer, &buffer_size);
  cbor_decref(&cose_key);

  if (length == 0) {
    throw CryptoError("Failed to serialize COSE_Key");
  }

  std::vector<uint8_t> result(buffer, buffer + length);
  free(buffer);
  return result;
}

/**
 * @brief Calculate thumbprint from COSE_Key bytes
 */
std::string calculateCoseKeyThumbprint(const std::vector<uint8_t>& cose_key) {
  auto hash = hashSha256(cose_key);
  return base64UrlEncode(hash);
}

#ifdef CATAPULT_ENABLE_JSON
/**
 * @brief Create algorithm instance from JWK and algorithm ID
 */
std::unique_ptr<CryptographicAlgorithm> createAlgorithmFromJWK(
    const std::string& alg_name, const std::string& jwk_json) {
  json jwk = json::parse(jwk_json);

  if (alg_name == "ES256") {
    if (jwk["kty"] != "EC" || jwk["crv"] != "P-256") {
      throw CryptoError("Invalid JWK for ES256: must be EC P-256");
    }

    auto x_bytes = base64UrlDecode(jwk["x"].get<std::string>());
    auto y_bytes = base64UrlDecode(jwk["y"].get<std::string>());

    if (x_bytes.size() != 32 || y_bytes.size() != 32) {
      throw CryptoError("Invalid EC coordinates size for P-256");
    }

    EVP_PKEY* pkey = nullptr;
    OSSL_PARAM_BLD* param_bld = OSSL_PARAM_BLD_new();
    if (!param_bld) {
      throw CryptoError("Failed to create parameter builder");
    }

    BIGNUM* x_bn = BN_bin2bn(x_bytes.data(), x_bytes.size(), nullptr);
    BIGNUM* y_bn = BN_bin2bn(y_bytes.data(), y_bytes.size(), nullptr);

    if (!x_bn || !y_bn) {
      OSSL_PARAM_BLD_free(param_bld);
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

    bool success = ctx && EVP_PKEY_fromdata_init(ctx) > 0 &&
                   EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) > 0;

    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PARAM_free(params);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    BN_free(x_bn);
    BN_free(y_bn);

    if (!success) {
      if (pkey) EVP_PKEY_free(pkey);
      throw CryptoError("Failed to create EC public key from JWK");
    }

    int der_len = i2d_PUBKEY(pkey, nullptr);
    if (der_len <= 0) {
      EVP_PKEY_free(pkey);
      throw CryptoError("Failed to get DER length for public key");
    }

    std::vector<uint8_t> der_bytes(der_len);
    uint8_t* der_ptr = der_bytes.data();
    i2d_PUBKEY(pkey, &der_ptr);
    EVP_PKEY_free(pkey);

    return std::make_unique<Es256Algorithm>(der_bytes);

  } else if (alg_name == "PS256") {
    if (jwk["kty"] != "RSA") {
      throw CryptoError("Invalid JWK for PS256: must be RSA");
    }

    auto n_bytes = base64UrlDecode(jwk["n"].get<std::string>());
    auto e_bytes = base64UrlDecode(jwk["e"].get<std::string>());

    EVP_PKEY* pkey = nullptr;
    OSSL_PARAM_BLD* param_bld = OSSL_PARAM_BLD_new();
    if (!param_bld) {
      throw CryptoError("Failed to create parameter builder");
    }

    BIGNUM* n_bn = BN_bin2bn(n_bytes.data(), n_bytes.size(), nullptr);
    BIGNUM* e_bn = BN_bin2bn(e_bytes.data(), e_bytes.size(), nullptr);

    if (!n_bn || !e_bn) {
      OSSL_PARAM_BLD_free(param_bld);
      if (n_bn) BN_free(n_bn);
      if (e_bn) BN_free(e_bn);
      throw CryptoError("Failed to create BIGNUM from RSA parameters");
    }

    OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_N, n_bn);
    OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_E, e_bn);

    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(param_bld);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);

    bool success = ctx && EVP_PKEY_fromdata_init(ctx) > 0 &&
                   EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) > 0;

    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PARAM_free(params);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    BN_free(n_bn);
    BN_free(e_bn);

    if (!success) {
      if (pkey) EVP_PKEY_free(pkey);
      throw CryptoError("Failed to create RSA public key from JWK");
    }

    int der_len = i2d_PUBKEY(pkey, nullptr);
    if (der_len <= 0) {
      EVP_PKEY_free(pkey);
      throw CryptoError("Failed to get DER length for RSA public key");
    }

    std::vector<uint8_t> der_bytes(der_len);
    uint8_t* der_ptr = der_bytes.data();
    i2d_PUBKEY(pkey, &der_ptr);
    EVP_PKEY_free(pkey);

    return std::make_unique<Ps256Algorithm>(der_bytes);
  }

  throw CryptoError("Unsupported algorithm for DPoP verification: " + alg_name);
}
#endif

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
    if (!header_.is_valid()) {
      return false;
    }

#ifdef CATAPULT_ENABLE_JSON
    if (encoding_ == DpopEncoding::JWT) {
      auto algorithm = createAlgorithmFromJWK(header_.alg, header_.jwk);
      return verify_signature(*algorithm);
    }
#endif

    // For CWT format, we need the algorithm to be provided externally
    // as COSE_Key doesn't include the private key needed to create algorithm
    return false;
  } catch (const std::exception&) {
    return false;
  }
}

std::string DpopProof::serialize() const {
  if (encoding_ == DpopEncoding::CWT) {
    return serialize_cwt();
  }
#ifdef CATAPULT_ENABLE_JSON
  return serialize_jwt();
#else
  throw CryptoError("JWT serialization requires CATAPULT_ENABLE_JSON");
#endif
}

std::string DpopProof::serialize_cwt() const {
  // Create COSE_Sign1 structure: [protected, unprotected, payload, signature]
  auto cose_array = cbor_new_definite_array(4);
  if (!cose_array) {
    throw CryptoError("Failed to create COSE_Sign1 array");
  }

  // Protected header with alg and typ
  auto protected_map = cbor_new_definite_map(3);
  (void)cbor_map_add(protected_map,
               {cbor_build_uint8(dpop_labels::ALG),
                cbor_build_negint8(static_cast<uint8_t>(-header_.alg_id - 1))});
  (void)cbor_map_add(protected_map,
               {cbor_build_uint8(dpop_labels::TYP),
                cbor_build_string("dpop-proof+cwt")});
  if (!header_.cose_key.empty()) {
    (void)cbor_map_add(protected_map,
                 {cbor_build_uint8(dpop_labels::COSE_KEY),
                  cbor_build_bytestring(header_.cose_key.data(),
                                        header_.cose_key.size())});
  }

  unsigned char* prot_buf = nullptr;
  size_t prot_size = 0;
  cbor_serialize_alloc(protected_map, &prot_buf, &prot_size);
  cbor_decref(&protected_map);

  auto protected_bstr = cbor_build_bytestring(prot_buf, prot_size);
  free(prot_buf);
  (void)cbor_array_push(cose_array, protected_bstr);

  // Unprotected header (empty map)
  (void)cbor_array_push(cose_array, cbor_new_definite_map(0));

  // Payload (CBOR-encoded claims)
  auto cbor_payload = create_signing_input();
  (void)cbor_array_push(cose_array,
                  cbor_build_bytestring(cbor_payload.data(), cbor_payload.size()));

  // Signature
  (void)cbor_array_push(cose_array,
                  cbor_build_bytestring(signature_.data(), signature_.size()));

  unsigned char* buffer = nullptr;
  size_t buffer_size = 0;
  size_t length = cbor_serialize_alloc(cose_array, &buffer, &buffer_size);
  cbor_decref(&cose_array);

  if (length == 0) {
    throw CryptoError("Failed to serialize DPoP CWT");
  }

  std::vector<uint8_t> cose_bytes(buffer, buffer + length);
  free(buffer);

  return base64UrlEncode(cose_bytes);
}

#ifdef CATAPULT_ENABLE_JSON
std::string DpopProof::serialize_jwt() const {
  json header_json = {
      {"typ", "dpop-proof+jwt"}, {"alg", header_.alg}, {"jwk", json::parse(header_.jwk)}};

  json payload_json = {{"iat", payload_.iat},
                       {"actx",
                        {{"type", payload_.actx.type},
                         {"action", payload_.actx.action},
                         {"tns", payload_.actx.tns},
                         {"tn", payload_.actx.tn}}}};

  if (payload_.jti.has_value()) {
    payload_json["jti"] = payload_.jti.value();
  }
  if (payload_.ath.has_value()) {
    payload_json["ath"] = payload_.ath.value();
  }
  if (!payload_.actx.resource_uri.empty()) {
    payload_json["actx"]["resource"] = payload_.actx.resource_uri;
  }

  std::string header_str = header_json.dump();
  std::string payload_str = payload_json.dump();

  std::string header_b64 = base64UrlEncode(
      std::vector<uint8_t>(header_str.begin(), header_str.end()));
  std::string payload_b64 = base64UrlEncode(
      std::vector<uint8_t>(payload_str.begin(), payload_str.end()));
  std::string sig_b64 = base64UrlEncode(signature_);

  return header_b64 + "." + payload_b64 + "." + sig_b64;
}
#endif

DpopProof DpopProof::deserialize(std::string_view data) {
  // Auto-detect format: JWT has dots, CWT is base64-encoded CBOR
  if (data.find('.') != std::string_view::npos) {
#ifdef CATAPULT_ENABLE_JSON
    return deserialize_jwt(data);
#else
    throw CryptoError("JWT deserialization requires CATAPULT_ENABLE_JSON");
#endif
  }
  return deserialize_cwt(data);
}

DpopProof DpopProof::deserialize_cwt(std::string_view cwt_data) {
  auto cose_bytes = base64UrlDecode(std::string(cwt_data));

  cbor_load_result result;
  cbor_item_t* cose_array =
      cbor_load(cose_bytes.data(), cose_bytes.size(), &result);

  if (!cose_array || !cbor_isa_array(cose_array) || cbor_array_size(cose_array) != 4) {
    if (cose_array) cbor_decref(&cose_array);
    throw InvalidTokenFormatError{};
  }

  DpopHeader header;
  header.set_encoding(DpopEncoding::CWT);

  // Parse protected header
  cbor_item_t* protected_bstr = cbor_array_get(cose_array, 0);
  if (protected_bstr && cbor_isa_bytestring(protected_bstr)) {
    size_t prot_len = cbor_bytestring_length(protected_bstr);
    if (prot_len > 0) {
      cbor_load_result prot_result;
      cbor_item_t* prot_map = cbor_load(cbor_bytestring_handle(protected_bstr),
                                         prot_len, &prot_result);
      if (prot_map && cbor_isa_map(prot_map)) {
        size_t map_size = cbor_map_size(prot_map);
        cbor_pair* pairs = cbor_map_handle(prot_map);
        for (size_t i = 0; i < map_size; ++i) {
          if (cbor_isa_uint(pairs[i].key)) {
            uint8_t key = cbor_get_uint8(pairs[i].key);
            if (key == dpop_labels::ALG && cbor_isa_negint(pairs[i].value)) {
              header.alg_id = -1 - static_cast<int64_t>(cbor_get_uint8(pairs[i].value));
            } else if (key == dpop_labels::COSE_KEY &&
                       cbor_isa_bytestring(pairs[i].value)) {
              size_t ck_len = cbor_bytestring_length(pairs[i].value);
              header.cose_key.assign(cbor_bytestring_handle(pairs[i].value),
                                     cbor_bytestring_handle(pairs[i].value) + ck_len);
            }
          }
        }
        cbor_decref(&prot_map);
      }
    }
  }

  // Parse payload
  cbor_item_t* payload_bstr = cbor_array_get(cose_array, 2);
  DpopPayload payload(0, "", "");

  if (payload_bstr && cbor_isa_bytestring(payload_bstr)) {
    size_t pay_len = cbor_bytestring_length(payload_bstr);
    cbor_load_result pay_result;
    cbor_item_t* pay_map =
        cbor_load(cbor_bytestring_handle(payload_bstr), pay_len, &pay_result);
    if (pay_map && cbor_isa_map(pay_map)) {
      size_t map_size = cbor_map_size(pay_map);
      cbor_pair* pairs = cbor_map_handle(pay_map);
      for (size_t i = 0; i < map_size; ++i) {
        if (cbor_isa_uint(pairs[i].key)) {
          int64_t key = cbor_get_uint64(pairs[i].key);
          if (key == dpop_labels::IAT && cbor_isa_uint(pairs[i].value)) {
            payload.iat = static_cast<int64_t>(cbor_get_uint64(pairs[i].value));
          } else if (key == dpop_labels::CTI &&
                     cbor_isa_string(pairs[i].value)) {
            payload.jti = std::string(
                reinterpret_cast<const char*>(cbor_string_handle(pairs[i].value)),
                cbor_string_length(pairs[i].value));
          }
        }
      }
      cbor_decref(&pay_map);
    }
  }

  // Get signature
  cbor_item_t* sig_bstr = cbor_array_get(cose_array, 3);
  std::vector<uint8_t> signature;
  if (sig_bstr && cbor_isa_bytestring(sig_bstr)) {
    size_t sig_len = cbor_bytestring_length(sig_bstr);
    signature.assign(cbor_bytestring_handle(sig_bstr),
                     cbor_bytestring_handle(sig_bstr) + sig_len);
  }

  cbor_decref(&cose_array);
  return DpopProof{std::move(header), std::move(payload), signature,
                   DpopEncoding::CWT};
}

#ifdef CATAPULT_ENABLE_JSON
DpopProof DpopProof::deserialize_jwt(std::string_view jwt_data) {
  std::vector<std::string> parts;
  std::string current;

  for (char c : jwt_data) {
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

  auto header_bytes = base64UrlDecode(parts[0]);
  auto payload_bytes = base64UrlDecode(parts[1]);
  auto signature = base64UrlDecode(parts[2]);

  auto header_json =
      json::parse(std::string(header_bytes.begin(), header_bytes.end()));
  auto payload_json =
      json::parse(std::string(payload_bytes.begin(), payload_bytes.end()));

  DpopHeader header;
  header.set_encoding(DpopEncoding::JWT);
  header.alg = header_json.value("alg", "");
  if (header_json.contains("jwk")) {
    header.jwk = header_json["jwk"].dump();
  }

  DpopPayload payload(0, "", "");

  if (payload_json.contains("actx")) {
    auto actx_json = payload_json["actx"];
    payload.actx.type = actx_json.value("type", "moqt");
    payload.actx.action = actx_json.value("action", 0);
    payload.actx.tns = actx_json.value("tns", "");
    payload.actx.tn = actx_json.value("tn", "");
    payload.actx.resource_uri = actx_json.value("resource", "");
  }

  payload.iat = payload_json.value("iat", static_cast<int64_t>(0));

  if (payload_json.contains("jti")) {
    payload.jti = payload_json["jti"].get<std::string>();
  }
  if (payload_json.contains("ath")) {
    payload.ath = payload_json["ath"].get<std::string>();
  }

  return DpopProof{std::move(header), std::move(payload), signature,
                   DpopEncoding::JWT};
}
#endif

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
      std::string actual_thumbprint;
      if (proof.encoding() == DpopEncoding::CWT) {
        actual_thumbprint =
            calculateCoseKeyThumbprint(proof.get_header().cose_key);
      }
#ifdef CATAPULT_ENABLE_JSON
      else {
        actual_thumbprint =
            jwk::calculateJWKThumbprint(proof.get_header().jwk);
      }
#endif
      if (actual_thumbprint != expected_public_key_thumbprint) {
        return false;
      }
    } catch (const std::exception&) {
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
  int64_t alg_id = algorithm_->algorithmId();

  if (alg_id == ALG_ES256) {
    auto* es256_alg = dynamic_cast<Es256Algorithm*>(algorithm_.get());
    if (!es256_alg) {
      throw CryptoError("Invalid ES256 algorithm instance");
    }
    public_key_der_ = es256_alg->getPublicKey();
  } else if (alg_id == ALG_PS256) {
    auto* ps256_alg = dynamic_cast<Ps256Algorithm*>(algorithm_.get());
    if (!ps256_alg) {
      throw CryptoError("Invalid PS256 algorithm instance");
    }
    public_key_der_ = ps256_alg->getPublicKey();
  } else {
    throw CryptoError("Unsupported algorithm for DPoP: " +
                      std::to_string(alg_id));
  }

  // Generate COSE_Key (always available)
  cose_key_ = createCoseKeyFromDer(alg_id, public_key_der_);
  public_key_thumbprint_ = calculateCoseKeyThumbprint(cose_key_);

#ifdef CATAPULT_ENABLE_JSON
  // Generate JWK (only when JSON is enabled)
  public_key_jwk_ = jwk::createJWKFromAlgorithm(alg_id, public_key_der_);
#endif
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