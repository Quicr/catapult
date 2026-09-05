/**
 * @file cat_dpop.cpp
 * @brief Implementation of DPoP functionality for CAT tokens
 *
 * Supports both CWT (CBOR) and JWT (JSON) encoding formats per
 * draft-nandakumar-moq-generic-dpop-proof-00
 */

#include "catapult/dpop.hpp"
#include "catapult/internal/parse_limits.hpp"
#include "catapult/logging.hpp"

#include <cbor.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <algorithm>
#include <iomanip>
#include <limits>
#include <sstream>

#ifdef CATAPULT_ENABLE_JSON
#include <nlohmann/json.hpp>

#include "catapult/jwk.hpp"
using json = nlohmann::json;
#endif

#include "catapult/base64.hpp"
#include "catapult/crypto.hpp"
#include "catapult/cwt.hpp"
#include "catapult/internal/cbor_owned.hpp"
#include "catapult/internal/strict_cbor.hpp"
#include "catapult/moqt_claims.hpp"

namespace catapult {

// DpopProof implementation

namespace {

// Add a (key, value) pair to a CBOR map, taking ownership of both items.
// Returns true on success, false on any failure — including when either
// item was nullptr, which indicates a prior allocation failure.
bool safeCborMapAdd(cbor_item_t* map, cbor_item_t* raw_key,
                    cbor_item_t* raw_value) {
  auto key = CborItemPtr(raw_key);
  auto value = CborItemPtr(raw_value);
  if (!key || !value) {
    return false;
  }
  struct cbor_pair pair = {key.get(), value.get()};
  if (!cbor_map_add(map, pair)) {
    return false;
  }
  return true;
}

// Encode a COSE algorithm identifier onto the wire.
//
// COSE registers algorithms with both positive and negative integer
// identifiers (RFC 8152 §16.4). The previous encoder always produced a
// negative CBOR integer, which was correct for the ES256 identifier
// catapult exercises today but would silently mangle any positive
// algorithm added later. Route through the two CBOR integer classes so
// the wire form matches the registered identifier's sign.
CborItemPtr buildAlgId(int64_t alg_id) {
  if (alg_id < 0) {
    return cbor_build_negint64_owned(static_cast<uint64_t>(-alg_id - 1));
  }
  return cbor_build_uint64_owned(static_cast<uint64_t>(alg_id));
}

// Build the DPoP protected-header CBOR bytes. Kept in one place so signer
// and verifier produce byte-identical inputs — the protected header is
// covered by the COSE_Sign1 Sig_structure (RFC 8152 §4.4) and any drift
// between the two sides silently invalidates every signature.
std::vector<uint8_t> buildDpopProtectedHeaderBytes(
    int64_t alg_id, const std::vector<uint8_t>& cose_key) {
  const size_t entries = cose_key.empty() ? 2 : 3;
  auto protected_map = CborItemPtr(cbor_new_definite_map(entries));
  if (!protected_map) {
    throw CryptoError("Failed to allocate DPoP protected header map");
  }

  auto pushPair = [&](CborItemPtr key, CborItemPtr value) {
    if (!key || !value) {
      throw CryptoError("Failed to allocate DPoP protected header entry");
    }
    struct cbor_pair pair = {key.get(), value.get()};
    if (!cbor_map_add(protected_map.get(), pair)) {
      throw CryptoError("Failed to add DPoP protected header entry");
    }
  };

  pushPair(CborItemPtr(cbor_build_uint8(dpop_labels::ALG)), buildAlgId(alg_id));
  pushPair(CborItemPtr(cbor_build_uint8(dpop_labels::TYP)),
           CborItemPtr(cbor_build_string("dpop-proof+cwt")));
  if (!cose_key.empty()) {
    pushPair(CborItemPtr(cbor_build_uint8(dpop_labels::COSE_KEY)),
             CborItemPtr(cbor_build_bytestring(cose_key.data(),
                                               cose_key.size())));
  }

  // The protected header integer labels are 1/3/-2 (RFC 8152) which have
  // different serialized widths, so the insertion order isn't canonical.
  // Reorder before serializing so the header round-trips through loadStrict.
  catapult::internal::canonicalizeMapOrder(protected_map.get());

  size_t length = 0;
  auto buffer = cbor_serialize_alloc_owned(protected_map.get(), length);
  if (length == 0 || !buffer) {
    throw CryptoError("Failed to serialize DPoP protected header");
  }
  return std::vector<uint8_t>(buffer.get(), buffer.get() + length);
}

// Decode the COSE algorithm identifier from a parsed protected-header entry.
// Accepts both CBOR uint and negint. Returns std::nullopt if the value is
// not a well-formed integer.
std::optional<int64_t> decodeAlgId(cbor_item_t* value) {
  if (!value) return std::nullopt;
  if (cbor_isa_negint(value)) {
    return -1 - static_cast<int64_t>(cbor_get_int(value));
  }
  if (cbor_isa_uint(value)) {
    uint64_t v = cbor_get_int(value);
    if (v > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
      return std::nullopt;
    }
    return static_cast<int64_t>(v);
  }
  return std::nullopt;
}

/**
 * @brief Create COSE_Key from DER-encoded public key
 */
std::vector<uint8_t> createCoseKeyFromDer(int64_t alg_id,
                                          const std::vector<uint8_t>& der_key) {
  const uint8_t* data = der_key.data();
  EVP_PKEY* pkey =
      d2i_PUBKEY(nullptr, &data, static_cast<long>(der_key.size()));
  if (!pkey) {
    throw CryptoError("Failed to parse DER public key for COSE_Key");
  }

  // Use RAII wrapper for EVP_PKEY
  auto pkey_guard = EvpKeyPtr(pkey);

  cbor_item_t* raw_cose_key = cbor_new_definite_map(5);
  if (!raw_cose_key) {
    throw CryptoError("Failed to create COSE_Key map");
  }
  // Use RAII wrapper for CBOR item
  CborItemPtr cose_key(raw_cose_key);

  if (alg_id == ALG_ES256) {
    BIGNUM* x = nullptr;
    BIGNUM* y = nullptr;

    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x) ||
        !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y)) {
      if (x) BN_free(x);
      if (y) BN_free(y);
      throw CryptoError("Failed to extract EC coordinates");
    }

    std::vector<uint8_t> x_bytes(32), y_bytes(32);
    BN_bn2binpad(x, x_bytes.data(), 32);
    BN_bn2binpad(y, y_bytes.data(), 32);
    BN_free(x);
    BN_free(y);

    // kty: EC (2), alg: ES256 (-7), crv: P-256 (1), x, y
    if (!safeCborMapAdd(cose_key.get(), cbor_build_uint8(1),
                        cbor_build_uint8(2)) ||
        !safeCborMapAdd(cose_key.get(), cbor_build_uint8(3),
                        cbor_build_negint8(6)) ||
        !safeCborMapAdd(cose_key.get(), cbor_build_negint8(0),
                        cbor_build_uint8(1)) ||
        !safeCborMapAdd(
            cose_key.get(), cbor_build_negint8(1),
            cbor_build_bytestring(x_bytes.data(), x_bytes.size())) ||
        !safeCborMapAdd(
            cose_key.get(), cbor_build_negint8(2),
            cbor_build_bytestring(y_bytes.data(), y_bytes.size()))) {
      throw CryptoError("Failed to build EC COSE_Key");
    }
  } else {
    throw CryptoError("Unsupported algorithm for COSE_Key: " +
                      std::to_string(alg_id));
  }

  unsigned char* buffer = nullptr;
  size_t buffer_size = 0;
  size_t length = cbor_serialize_alloc(cose_key.get(), &buffer, &buffer_size);

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
  // Prevent DoS from oversized JSON input
  constexpr size_t MAX_JWK_SIZE = 8192;  // 8KB reasonable limit for JWK
  constexpr size_t MIN_JWK_SIZE = 30;    // Minimum valid JWK is larger
  if (jwk_json.size() > MAX_JWK_SIZE) {
    throw CryptoError("JWK exceeds maximum allowed size");
  }
  if (jwk_json.size() < MIN_JWK_SIZE) {
    throw CryptoError("JWK too small to be valid");
  }
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

    bool success =
        ctx && EVP_PKEY_fromdata_init(ctx) > 0 &&
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
  }

  throw CryptoError("Unsupported algorithm for DPoP verification: " + alg_name);
}
#endif

}  // anonymous namespace

std::vector<uint8_t> DpopProof::create_signing_input() const {
  auto payload_cbor = Cwt::createDpopSigningInput(payload_.actx, payload_.iat,
                                                  payload_.jti, payload_.ath);

  if (encoding_ == DpopEncoding::CWT) {
    // COSE_Sign1 signing input MUST be a Sig_structure (RFC 8152 §4.4):
    //   Sig_structure = ["Signature1", body_protected, external_aad, payload]
    // The prior implementation signed the payload CBOR directly, which left
    // the protected header (alg_id, cose_key) unauthenticated — an attacker
    // could substitute a different alg or key material without invalidating
    // the signature.
    auto protected_bytes =
        buildDpopProtectedHeaderBytes(header_.alg_id, header_.cose_key);
    return createCoseSign1Input(protected_bytes, payload_cbor);
  }

#ifdef CATAPULT_ENABLE_JSON
  // JWT DPoP signs `base64url(header) "." base64url(payload)` where header
  // is the JSON header and payload is the JSON payload — but our payload
  // is CBOR here, matching the wire form emitted by serialize_jwt. Mirror
  // that exactly so signer and verifier see identical bytes.
  json header_json = {{"typ", "dpop-proof+jwt"},
                      {"alg", header_.alg},
                      {"jwk", json::parse(header_.jwk)}};
  json payload_json = {{"iat", payload_.iat},
                       {"actx",
                        {{"type", payload_.actx.type},
                         {"action", payload_.actx.action},
                         {"tns", payload_.actx.tns},
                         {"tn", payload_.actx.tn}}}};
  if (payload_.jti.has_value()) {
    payload_json["jti"] = *payload_.jti;
  }
  if (payload_.ath.has_value()) {
    payload_json["ath"] = *payload_.ath;
  }
  if (!payload_.actx.resource_uri.empty()) {
    payload_json["actx"]["resource"] = payload_.actx.resource_uri;
  }
  std::string header_str = header_json.dump();
  std::string payload_str = payload_json.dump();
  std::vector<uint8_t> header_bytes(header_str.begin(), header_str.end());
  std::vector<uint8_t> payload_bytes(payload_str.begin(), payload_str.end());
  return createJwtSigningInput(header_bytes, payload_bytes);
#else
  throw CryptoError(
      "JWT DPoP signing requires CATAPULT_ENABLE_JSON");
#endif
}

bool DpopProof::verify_signature(
    const CryptographicAlgorithm& algorithm) const {
  try {
    // Prefer the exact wire signing input captured at deserialization
    // time (HN-03): re-serialising the parsed fields is not guaranteed
    // to reproduce the bytes the issuer actually signed — JSON key
    // ordering, whitespace, and escape choices vary between producers,
    // and CBOR canonical-form deviations in an attacker-crafted proof
    // would be smoothed over by our own emitter. Fall back to the
    // reconstructed input only for proofs created in-memory (never
    // deserialised), which have no wire form yet.
    if (!wire_signing_input_.empty()) {
      return algorithm.verify(wire_signing_input_, signature_);
    }
    auto fresh_input = create_signing_input();
    return algorithm.verify(fresh_input, signature_);
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
  // Emit a COSE_Sign1 structure per RFC 8152 §4.2:
  //   COSE_Sign1 = [protected: bstr, unprotected: {}, payload: bstr,
  //                 signature: bstr]
  // The `protected` bytes and the `payload` bytes MUST be identical to what
  // was passed to `createCoseSign1Input` at sign time; otherwise verifiers
  // that recompute the Sig_structure will get a different digest.

  auto cose_array = CborItemPtr(cbor_new_definite_array(4));
  if (!cose_array) {
    throw CryptoError("Failed to create COSE_Sign1 array");
  }

  auto pushArrayItem = [&](CborItemPtr item, const char* what) {
    if (!item) {
      throw CryptoError(std::string("Failed to allocate ") + what);
    }
    if (!cbor_array_push(cose_array.get(), item.get())) {
      throw CryptoError(std::string("Failed to append ") + what);
    }
  };

  auto protected_bytes =
      buildDpopProtectedHeaderBytes(header_.alg_id, header_.cose_key);
  pushArrayItem(CborItemPtr(cbor_build_bytestring(protected_bytes.data(),
                                                  protected_bytes.size())),
                "COSE_Sign1 protected header");

  pushArrayItem(CborItemPtr(cbor_new_definite_map(0)),
                "COSE_Sign1 unprotected header");

  auto payload_cbor = Cwt::createDpopSigningInput(payload_.actx, payload_.iat,
                                                  payload_.jti, payload_.ath);
  pushArrayItem(CborItemPtr(cbor_build_bytestring(payload_cbor.data(),
                                                  payload_cbor.size())),
                "COSE_Sign1 payload");

  pushArrayItem(CborItemPtr(cbor_build_bytestring(signature_.data(),
                                                  signature_.size())),
                "COSE_Sign1 signature");

  size_t length = 0;
  auto buffer = cbor_serialize_alloc_owned(cose_array.get(), length);
  if (length == 0 || !buffer) {
    throw CryptoError("Failed to serialize DPoP CWT");
  }

  std::vector<uint8_t> cose_bytes(buffer.get(), buffer.get() + length);
  return base64UrlEncode(cose_bytes);
}

#ifdef CATAPULT_ENABLE_JSON
std::string DpopProof::serialize_jwt() const {
  json header_json = {{"typ", "dpop-proof+jwt"},
                      {"alg", header_.alg},
                      {"jwk", json::parse(header_.jwk)}};

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
  // CTA-5007-B §4.3.1: cap encoded DPoP proofs before base64/CBOR work.
  if (cwt_data.size() > internal::kMaxEncodedTokenBytes) {
    throw InvalidTokenFormatError{};
  }
  auto cose_bytes = base64UrlDecode(std::string(cwt_data));
  if (cose_bytes.size() > internal::kMaxDecodedCborBytes) {
    throw InvalidTokenFormatError{};
  }

  cbor_load_result result;
  auto cose_root =
      cbor_load_owned(reinterpret_cast<const uint8_t*>(cose_bytes.data()),
                      cose_bytes.size(), result);

  if (result.error.code != CBOR_ERR_NONE ||
      result.read != cose_bytes.size() || !cose_root) {
    throw InvalidTokenFormatError{};
  }

  // A CWT DPoP proof is a COSE_Sign1 (RFC 8152 §4.2). If the producer
  // tagged it, the tag MUST be 18 — accepting any other single-recipient
  // tag would let a Mac0/Encrypt0-labelled body reach signature dispatch
  // and defeat the tag/structure binding we enforce elsewhere (HN-03).
  if (cbor_isa_tag(cose_root.get())) {
    const uint64_t tagValue = cbor_tag_value(cose_root.get());
    if (tagValue != 18) {
      throw InvalidTokenFormatError{};
    }
    CborItemPtr inner(cbor_tag_item(cose_root.get()));
    cose_root = std::move(inner);
  }

  if (!cose_root || !cbor_isa_array(cose_root.get()) ||
      cbor_array_size(cose_root.get()) != 4) {
    throw InvalidTokenFormatError{};
  }

  cbor_item_t* cose_array = cose_root.get();

  DpopHeader header;
  header.set_encoding(DpopEncoding::CWT);

  // Parse protected header. The bytestring's contents are canonical CBOR
  // that encodes a map keyed by short unsigned integers (COSE header
  // labels).
  auto protected_bstr = cbor_array_get_owned(cose_array, 0);
  if (!protected_bstr || !cbor_isa_bytestring(protected_bstr.get())) {
    throw InvalidTokenFormatError{};
  }
  // Capture the wire bytes of the protected header for later Sig_structure
  // reconstruction. Using these bytes verbatim (rather than re-serialising
  // the parsed alg/cose_key) is what makes the CWT DPoP verification bind
  // to the exact bytes the issuer signed (HN-03).
  std::vector<uint8_t> wire_protected_header(
      cbor_bytestring_handle(protected_bstr.get()),
      cbor_bytestring_handle(protected_bstr.get()) +
          cbor_bytestring_length(protected_bstr.get()));
  {
    size_t prot_len = cbor_bytestring_length(protected_bstr.get());
    if (prot_len > 0) {
      // Attacker-controlled protected header: enforce definite-length,
      // duplicate-key, trailing-byte, and nesting-depth bounds.
      CborItemPtr prot_map;
      try {
        prot_map = catapult::internal::loadStrict(std::span<const uint8_t>(
            cbor_bytestring_handle(protected_bstr.get()), prot_len));
      } catch (const InvalidCborError&) {
        throw InvalidTokenFormatError{};
      }
      if (!prot_map || !cbor_isa_map(prot_map.get())) {
        throw InvalidTokenFormatError{};
      }
      size_t map_size = cbor_map_size(prot_map.get());
      cbor_pair* pairs = cbor_map_handle(prot_map.get());
      if (!pairs && map_size > 0) {
        throw InvalidTokenFormatError{};
      }
      for (size_t i = 0; i < map_size; ++i) {
        if (!pairs[i].key || !pairs[i].value || !cbor_isa_uint(pairs[i].key)) {
          continue;
        }
        uint64_t key = cbor_get_int(pairs[i].key);
        if (key == dpop_labels::ALG) {
          auto decoded = decodeAlgId(pairs[i].value);
          if (!decoded.has_value()) {
            throw InvalidTokenFormatError{};
          }
          header.alg_id = *decoded;
        } else if (key == dpop_labels::COSE_KEY &&
                   cbor_isa_bytestring(pairs[i].value)) {
          size_t ck_len = cbor_bytestring_length(pairs[i].value);
          header.cose_key.assign(
              cbor_bytestring_handle(pairs[i].value),
              cbor_bytestring_handle(pairs[i].value) + ck_len);
        }
      }
    }
  }

  // Parse payload
  auto payload_bstr = cbor_array_get_owned(cose_array, 2);
  DpopPayload payload(0, "", "");

  if (!payload_bstr || !cbor_isa_bytestring(payload_bstr.get())) {
    throw InvalidTokenFormatError{};
  }
  // Capture the wire payload bytes for later Sig_structure use.
  std::vector<uint8_t> wire_payload(
      cbor_bytestring_handle(payload_bstr.get()),
      cbor_bytestring_handle(payload_bstr.get()) +
          cbor_bytestring_length(payload_bstr.get()));
  {
    size_t pay_len = cbor_bytestring_length(payload_bstr.get());
    // Attacker-controlled payload map: enforce strict CBOR rules.
    CborItemPtr pay_map;
    try {
      pay_map = catapult::internal::loadStrict(std::span<const uint8_t>(
          cbor_bytestring_handle(payload_bstr.get()), pay_len));
    } catch (const InvalidCborError&) {
      throw InvalidTokenFormatError{};
    }
    if (!pay_map || !cbor_isa_map(pay_map.get())) {
      throw InvalidTokenFormatError{};
    }
    {
      size_t map_size = cbor_map_size(pay_map.get());
      cbor_pair* pairs = cbor_map_handle(pay_map.get());
      if (!pairs) {
        throw InvalidTokenFormatError{};
      }
      for (size_t i = 0; i < map_size; ++i) {
        if (!pairs[i].key || !pairs[i].value) continue;
        std::string key_str;
        if (cbor_isa_string(pairs[i].key)) {
          key_str = std::string(
              reinterpret_cast<const char*>(cbor_string_handle(pairs[i].key)),
              cbor_string_length(pairs[i].key));
        }

        if (key_str == "iat" && cbor_isa_uint(pairs[i].value)) {
          // libcbor returns an unsigned 64-bit integer; casting a value
          // with the top bit set into int64_t is implementation-defined
          // and would wrap to a large negative time. Reject before it can
          // reach freshness checks (HN-03).
          uint64_t raw_iat = cbor_get_int(pairs[i].value);
          if (raw_iat >
              static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
            throw InvalidTokenFormatError{};
          }
          payload.iat = static_cast<int64_t>(raw_iat);
        } else if (key_str == "jti" && cbor_isa_string(pairs[i].value)) {
          payload.jti = std::string(
              reinterpret_cast<const char*>(cbor_string_handle(pairs[i].value)),
              cbor_string_length(pairs[i].value));
        } else if (key_str == "actx" && cbor_isa_map(pairs[i].value)) {
          cbor_item_t* actx_map = pairs[i].value;
          size_t actx_size = cbor_map_size(actx_map);
          cbor_pair* actx_pairs = cbor_map_handle(actx_map);
          if (!actx_pairs) continue;
          for (size_t j = 0; j < actx_size; ++j) {
            if (!actx_pairs[j].key || !actx_pairs[j].value) continue;
            std::string actx_key;
            if (cbor_isa_string(actx_pairs[j].key)) {
              actx_key = std::string(reinterpret_cast<const char*>(
                                         cbor_string_handle(actx_pairs[j].key)),
                                     cbor_string_length(actx_pairs[j].key));
            }
            if (actx_key == "type" && cbor_isa_string(actx_pairs[j].value)) {
              payload.actx.type =
                  std::string(reinterpret_cast<const char*>(
                                  cbor_string_handle(actx_pairs[j].value)),
                              cbor_string_length(actx_pairs[j].value));
            } else if (actx_key == "action" &&
                       cbor_isa_uint(actx_pairs[j].value)) {
              // `action` is stored as `int` on the payload. Reject
              // values that would truncate on narrow casts (HN-03).
              uint64_t raw_action = cbor_get_int(actx_pairs[j].value);
              if (raw_action >
                  static_cast<uint64_t>(std::numeric_limits<int>::max())) {
                throw InvalidTokenFormatError{};
              }
              payload.actx.action = static_cast<int>(raw_action);
            } else if (actx_key == "tns" &&
                       cbor_isa_string(actx_pairs[j].value)) {
              payload.actx.tns =
                  std::string(reinterpret_cast<const char*>(
                                  cbor_string_handle(actx_pairs[j].value)),
                              cbor_string_length(actx_pairs[j].value));
            } else if (actx_key == "tn" &&
                       cbor_isa_string(actx_pairs[j].value)) {
              payload.actx.tn =
                  std::string(reinterpret_cast<const char*>(
                                  cbor_string_handle(actx_pairs[j].value)),
                              cbor_string_length(actx_pairs[j].value));
            } else if (actx_key == "resource" &&
                       cbor_isa_string(actx_pairs[j].value)) {
              payload.actx.resource_uri =
                  std::string(reinterpret_cast<const char*>(
                                  cbor_string_handle(actx_pairs[j].value)),
                              cbor_string_length(actx_pairs[j].value));
            }
          }
        }
      }
    }
  }

  // Get signature
  auto sig_bstr = cbor_array_get_owned(cose_array, 3);
  if (!sig_bstr || !cbor_isa_bytestring(sig_bstr.get())) {
    throw InvalidTokenFormatError{};
  }
  size_t sig_len = cbor_bytestring_length(sig_bstr.get());
  std::vector<uint8_t> signature(
      cbor_bytestring_handle(sig_bstr.get()),
      cbor_bytestring_handle(sig_bstr.get()) + sig_len);

  // Build the exact Sig_structure the issuer signed over, using the wire
  // bytes of the protected header and payload rather than a re-encoding
  // of the parsed fields (HN-03). `createCoseSign1Input` produces the
  // canonical RFC 8152 §4.4 Sig_structure.
  auto wire_signing_input =
      createCoseSign1Input(wire_protected_header, wire_payload);

  DpopProof proof{std::move(header), std::move(payload), signature,
                  DpopEncoding::CWT};
  proof.set_wire_signing_input(std::move(wire_signing_input));
  return proof;
}

#ifdef CATAPULT_ENABLE_JSON
DpopProof DpopProof::deserialize_jwt(std::string_view jwt_data) {
  // CTA-5007-B §4.3.1: JWT-shaped DPoP proofs share the same encoded-size
  // ceiling as CWT proofs. The previous local 16 KiB limit was strictly
  // larger than the standard permits.
  if (jwt_data.size() > internal::kMaxEncodedTokenBytes) {
    throw InvalidTokenFormatError{};
  }

  std::vector<std::string> parts;
  std::string current;
  current.reserve(jwt_data.size() / 3);  // Reasonable estimate

  for (char c : jwt_data) {
    if (c == '.') {
      parts.push_back(std::move(current));
      current.clear();
      current.reserve(jwt_data.size() / 3);
    } else {
      current += c;
    }
  }
  parts.push_back(std::move(current));

  if (parts.size() != 3) {
    throw InvalidTokenFormatError{};
  }

  // Capture the exact signing input as it appeared on the wire —
  // `base64url(header) "." base64url(payload)` — before decoding. Any
  // re-serialization of the parsed struct would risk producing bytes
  // that don't match what the issuer signed (HN-03).
  std::vector<uint8_t> wire_signing_input;
  wire_signing_input.reserve(parts[0].size() + 1 + parts[1].size());
  wire_signing_input.insert(wire_signing_input.end(), parts[0].begin(),
                            parts[0].end());
  wire_signing_input.push_back('.');
  wire_signing_input.insert(wire_signing_input.end(), parts[1].begin(),
                            parts[1].end());

  auto header_bytes = base64UrlDecode(parts[0]);
  auto payload_bytes = base64UrlDecode(parts[1]);
  auto signature = base64UrlDecode(parts[2]);

  json header_json;
  json payload_json;
  try {
    header_json =
        json::parse(std::string(header_bytes.begin(), header_bytes.end()));
    payload_json =
        json::parse(std::string(payload_bytes.begin(), payload_bytes.end()));
  } catch (const json::parse_error&) {
    throw InvalidTokenFormatError{};
  }

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
    // Range-check `action` before narrowing (HN-03). Unsigned JSON
    // numbers can hold values outside `int`; a silent narrow could
    // yield a legitimate-looking small integer that impersonates a
    // different MOQT action.
    if (actx_json.contains("action")) {
      const auto& action_val = actx_json.at("action");
      if (!action_val.is_number_integer()) {
        throw InvalidTokenFormatError{};
      }
      int64_t raw_action = action_val.get<int64_t>();
      if (raw_action < std::numeric_limits<int>::min() ||
          raw_action > std::numeric_limits<int>::max()) {
        throw InvalidTokenFormatError{};
      }
      payload.actx.action = static_cast<int>(raw_action);
    }
    payload.actx.tns = actx_json.value("tns", "");
    payload.actx.tn = actx_json.value("tn", "");
    payload.actx.resource_uri = actx_json.value("resource", "");
  }

  if (payload_json.contains("iat")) {
    const auto& iat_val = payload_json.at("iat");
    if (!iat_val.is_number_integer()) {
      throw InvalidTokenFormatError{};
    }
    // nlohmann::json stores unsigned integers separately: values with
    // MSB set would wrap to negative on a signed read. Route through
    // uint64_t and range-check (HN-03).
    if (iat_val.is_number_unsigned()) {
      uint64_t raw = iat_val.get<uint64_t>();
      if (raw > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        throw InvalidTokenFormatError{};
      }
      payload.iat = static_cast<int64_t>(raw);
    } else {
      payload.iat = iat_val.get<int64_t>();
    }
  }

  if (payload_json.contains("jti")) {
    payload.jti = payload_json["jti"].get<std::string>();
  }
  if (payload_json.contains("ath")) {
    payload.ath = payload_json["ath"].get<std::string>();
  }

  DpopProof proof{std::move(header), std::move(payload), signature,
                  DpopEncoding::JWT};
  proof.set_wire_signing_input(std::move(wire_signing_input));
  return proof;
}
#endif

// moqt_dpop namespace implementation

namespace moqt_dpop {

std::string generate_jti() {
  std::vector<uint8_t> bytes(16);
  if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
    throw CryptoError("Failed to generate random JTI");
  }
  return base64UrlEncode(bytes);
}

}  // namespace moqt_dpop

// DpopProofValidator implementation

bool DpopProofValidator::validate_proof(
    const DpopProof& proof, int expected_action, std::string_view expected_uri,
    const std::string& expected_public_key_thumbprint) {
  // The `cnf`/`catdpop` binding must be checked against a non-empty
  // expected thumbprint: an empty string cannot represent a caller's
  // policy intent and previously caused the check to be silently
  // skipped. Fail closed at the API boundary rather than at the caller.
  if (expected_public_key_thumbprint.empty()) {
    CAT_LOG_ERROR(
        "DPoP validation requires a non-empty expected public-key "
        "thumbprint; rejecting proof");
    return false;
  }

  // Basic structure validation
  if (!proof.is_valid(settings_)) {
    return false;
  }

  // MANDATORY signature verification (CTA-5007-B / CAT-4-MOQT). Fail
  // closed if verification cannot be performed. JWT proofs self-resolve
  // their algorithm from the embedded JWK; CWT proofs require an external
  // verifier to have been configured via `set_cwt_verifier`.
  bool signature_ok = false;
  if (proof.encoding() == DpopEncoding::CWT) {
    if (cwt_verifier_ != nullptr) {
      signature_ok = proof.verify_signature(*cwt_verifier_);
    }
  } else {
    // DpopProof::verify_signature() constructs the verifier from the
    // embedded JWK for JWT proofs; it returns false on any failure.
    signature_ok = proof.verify_signature();
  }
  if (!signature_ok) {
    CAT_LOG_ERROR(
        "DPoP proof signature verification failed or was not possible; "
        "rejecting proof (encoding={})",
        proof.encoding() == DpopEncoding::CWT ? "CWT" : "JWT");
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

  // Public-key thumbprint (`cnf`/`catdpop` binding) must be checked
  // BEFORE replay admission: otherwise a proof bound to a different key
  // — one the attacker can freely resign — can be used to consume the
  // bounded replay store's admission slots for the target `jti`,
  // producing a replay-store poisoning primitive against the legitimate
  // key holder (HN-03). We already rejected the empty-thumbprint case
  // above, so this branch always runs.
  try {
    std::string actual_thumbprint;
    if (proof.encoding() == DpopEncoding::CWT) {
      actual_thumbprint =
          calculateCoseKeyThumbprint(proof.get_header().cose_key);
    }
#ifdef CATAPULT_ENABLE_JSON
    else {
      actual_thumbprint = jwk::calculateJWKThumbprint(proof.get_header().jwk);
    }
#endif
    if (actual_thumbprint != expected_public_key_thumbprint) {
      return false;
    }
  } catch (const std::exception&) {
    return false;
  }

  // Check JTI if enabled and present. All bookkeeping — TOCTOU-safe
  // check-and-record, size cap, expiry, cross-process sharing — is the
  // replay store's responsibility. Exhaustion is treated as a replay
  // (fail closed) so a full store cannot be turned into an admit oracle.
  if (settings_.get_jti_processing() && proof.get_payload().jti.has_value()) {
    const auto& jti = proof.get_payload().jti.value();
    auto now = std::chrono::system_clock::now();
    auto result = replay_store_->admit(jti, now,
                                       settings_.get_effective_window());
    if (result != ReplayAdmitResult::Admitted) {
      if (result == ReplayAdmitResult::StoreExhausted) {
        CAT_LOG_WARN(
            "DPoP replay store exhausted; rejecting proof to fail closed");
      }
      return false;
    }
  }

  return true;
}

void DpopProofValidator::cleanup_expired_jtis() {
  replay_store_->purgeExpired(std::chrono::system_clock::now(),
                              settings_.get_effective_window());
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
    case ALG_HMAC256_256:
      return "HS256";
    default:
      return "Unknown";
  }
}

}  // namespace catapult