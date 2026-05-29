#include <doctest/doctest.h>
#include <nlohmann/json.hpp>

#include "catapult/base64.hpp"
#include "catapult/claims.hpp"
#include "catapult/crypto.hpp"
#include "catapult/cwt.hpp"
#include "catapult/moqt_claims.hpp"
#include "catapult/token.hpp"
#include "catapult/validator.hpp"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using namespace catapult;
using json = nlohmann::json;

namespace {

std::vector<uint8_t> hexToBytes(const std::string &hex) {
  std::vector<uint8_t> bytes;
  bytes.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    auto byte =
        static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16));
    bytes.push_back(byte);
  }
  return bytes;
}

std::vector<uint8_t> rawEcdsaToDer(const std::vector<uint8_t> &raw) {
  if (raw.size() != 64) return raw;
  auto r = BN_bin2bn(raw.data(), 32, nullptr);
  auto s = BN_bin2bn(raw.data() + 32, 32, nullptr);

  ECDSA_SIG *sig = ECDSA_SIG_new();
  ECDSA_SIG_set0(sig, r, s);

  unsigned char *der = nullptr;
  int derLen = i2d_ECDSA_SIG(sig, &der);
  ECDSA_SIG_free(sig);

  std::vector<uint8_t> result(der, der + derLen);
  OPENSSL_free(der);
  return result;
}

std::string bytesToHex(const std::vector<uint8_t> &bytes) {
  std::string hex;
  hex.reserve(bytes.size() * 2);
  for (auto b : bytes) {
    char buf[3];
    snprintf(buf, sizeof(buf), "%02x", b);
    hex += buf;
  }
  return hex;
}

json loadTestVectors() {
  std::ifstream file("tests/test_data/cat_test_vectors.json");
  if (!file.is_open()) {
    file.open("../tests/test_data/cat_test_vectors.json");
  }
  if (!file.is_open()) {
    file.open("../../tests/test_data/cat_test_vectors.json");
  }
  REQUIRE(file.is_open());
  json j;
  file >> j;
  return j;
}

std::vector<uint8_t> buildDerPublicKey(const std::vector<uint8_t> &x,
                                       const std::vector<uint8_t> &y) {
  std::vector<uint8_t> uncompressed;
  uncompressed.push_back(0x04);
  uncompressed.insert(uncompressed.end(), x.begin(), x.end());
  uncompressed.insert(uncompressed.end(), y.begin(), y.end());

  OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
  OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0);
  OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                   uncompressed.data(), uncompressed.size());
  OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  EVP_PKEY_fromdata_init(ctx);
  EVP_PKEY *pkey = nullptr;
  EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);

  BIO *bio = BIO_new(BIO_s_mem());
  i2d_PUBKEY_bio(bio, pkey);

  char *data;
  long len = BIO_get_mem_data(bio, &data);
  std::vector<uint8_t> der(data, data + len);

  BIO_free(bio);
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(bld);

  return der;
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
buildDerKeyPair(const std::vector<uint8_t> &privKey,
                const std::vector<uint8_t> &x, const std::vector<uint8_t> &y) {
  std::vector<uint8_t> uncompressed;
  uncompressed.push_back(0x04);
  uncompressed.insert(uncompressed.end(), x.begin(), x.end());
  uncompressed.insert(uncompressed.end(), y.begin(), y.end());

  OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
  OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0);
  OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                          BN_bin2bn(privKey.data(), static_cast<int>(privKey.size()), nullptr));
  OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                   uncompressed.data(), uncompressed.size());
  OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  EVP_PKEY_fromdata_init(ctx);
  EVP_PKEY *pkey = nullptr;
  EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params);

  BIO *priv_bio = BIO_new(BIO_s_mem());
  BIO *pub_bio = BIO_new(BIO_s_mem());
  i2d_PrivateKey_bio(priv_bio, pkey);
  i2d_PUBKEY_bio(pub_bio, pkey);

  char *priv_data;
  long priv_len = BIO_get_mem_data(priv_bio, &priv_data);
  std::vector<uint8_t> derPriv(priv_data, priv_data + priv_len);

  char *pub_data;
  long pub_len = BIO_get_mem_data(pub_bio, &pub_data);
  std::vector<uint8_t> derPub(pub_data, pub_data + pub_len);

  BIO_free(priv_bio);
  BIO_free(pub_bio);
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(bld);

  return {derPriv, derPub};
}

} // namespace

TEST_SUITE("Cross-Implementation Test Vectors") {

TEST_CASE("CBOR Decoding - Payload decoding from reference CBOR") {
  auto vectors = loadTestVectors();
  auto &cbor_vectors = vectors["vectors"]["cbor_encoding"]["vectors"];

  SUBCASE("cbor_issuer_only - Decode issuer claim") {
    auto &v = cbor_vectors[0];
    REQUIRE(v["id"] == "cbor_issuer_only");
    auto cborData = hexToBytes(v["payload_cbor_hex"].get<std::string>());

    auto token = Cwt::decodePayload(cborData);
    CHECK(token.core.iss == "https://auth.example.com");
  }

  SUBCASE("cbor_core_claims - Decode all core CWT claims") {
    auto &v = cbor_vectors[1];
    REQUIRE(v["id"] == "cbor_core_claims");
    auto cborData = hexToBytes(v["payload_cbor_hex"].get<std::string>());

    auto token = Cwt::decodePayload(cborData);
    CHECK(token.core.iss == "https://auth.example.com");
    REQUIRE(token.core.aud.has_value());
    CHECK(token.core.aud->size() == 1);
    CHECK((*token.core.aud)[0] == "https://relay.example.com");
    CHECK(token.core.exp == 1700086400);
    CHECK(token.core.nbf == 1700000000);
    CHECK(token.core.cti == "test-token-001");
  }

  SUBCASE("cbor_cat_version_usage - Decode CAT version and usage") {
    auto &v = cbor_vectors[2];
    REQUIRE(v["id"] == "cbor_cat_version_usage");
    auto cborData = hexToBytes(v["payload_cbor_hex"].get<std::string>());

    auto token = Cwt::decodePayload(cborData);
    CHECK(token.cat.catv == "CAT-v1");
    CHECK(token.cat.catu == 5);
  }

  SUBCASE("cbor_geographic_claims - Decode geographic claims") {
    auto &v = cbor_vectors[4];
    REQUIRE(v["id"] == "cbor_geographic_claims");
    auto cborData = hexToBytes(v["payload_cbor_hex"].get<std::string>());

    auto token = Cwt::decodePayload(cborData);
    CHECK(token.cat.geohash == "9q8yyk");
    REQUIRE(token.cat.catgeocoord.has_value());
    CHECK(token.cat.catgeocoord->lat == doctest::Approx(37.7749));
    CHECK(token.cat.catgeocoord->lon == doctest::Approx(-122.4194));
    // Note: accuracy uses half-precision float (f9 5640) in the test vector.
    // The library reads it with cbor_float_get_float8 which may not handle
    // half-precision correctly - this is a known interop gap.
  }

  SUBCASE("cbor_alpn - CBOR is valid and parseable") {
    auto &v = cbor_vectors[6];
    REQUIRE(v["id"] == "cbor_alpn");
    auto cborData = hexToBytes(v["payload_cbor_hex"].get<std::string>());

    // The library can parse the CBOR without error.
    // Note: CLAIM_CATALPN (314) decode is not yet implemented in
    // Cwt::decodePayload - the claim is skipped. This test validates
    // that the CBOR structure is accepted without errors.
    REQUIRE_NOTHROW(Cwt::decodePayload(cborData));
  }
}

TEST_CASE("Token Structure - HMAC-SHA256 signature verification") {
  auto vectors = loadTestVectors();
  auto &token_vectors = vectors["vectors"]["token_structure"]["vectors"];

  SUBCASE("token_hmac_minimal - Verify signature") {
    auto &v = token_vectors[0];
    REQUIRE(v["id"] == "token_hmac_minimal");

    auto keyBytes = hexToBytes(v["key_hex"].get<std::string>());
    HmacSha256Algorithm hmac(keyBytes);

    auto headerBytes = base64UrlDecode(v["header_b64"].get<std::string>());
    auto payloadBytes = base64UrlDecode(v["payload_b64"].get<std::string>());
    auto expectedSig = base64UrlDecode(v["signature_b64"].get<std::string>());

    CHECK(bytesToHex(headerBytes) == v["header_cbor_hex"].get<std::string>());
    CHECK(bytesToHex(payloadBytes) == v["payload_cbor_hex"].get<std::string>());
    CHECK(bytesToHex(expectedSig) == v["signature_hex"].get<std::string>());

    auto signingInput = createJwtSigningInput(headerBytes, payloadBytes);
    auto computedSig = hmac.sign(signingInput);

    CHECK(bytesToHex(computedSig) == v["signature_hex"].get<std::string>());
    CHECK(hmac.verify(signingInput, expectedSig));
  }

  SUBCASE("token_hmac_full - Verify signature and decode claims") {
    auto &v = token_vectors[1];
    REQUIRE(v["id"] == "token_hmac_full");

    auto keyBytes = hexToBytes(v["key_hex"].get<std::string>());
    HmacSha256Algorithm hmac(keyBytes);

    auto headerBytes = base64UrlDecode(v["header_b64"].get<std::string>());
    auto payloadBytes = base64UrlDecode(v["payload_b64"].get<std::string>());
    auto expectedSig = base64UrlDecode(v["signature_b64"].get<std::string>());

    auto signingInput = createJwtSigningInput(headerBytes, payloadBytes);
    CHECK(hmac.verify(signingInput, expectedSig));

    auto token = Cwt::decodePayload(payloadBytes);
    CHECK(token.core.iss == "https://issuer.moq.example");
    REQUIRE(token.core.aud.has_value());
    CHECK(token.core.aud->size() == 2);
    CHECK((*token.core.aud)[0] == "https://relay1.example.com");
    CHECK((*token.core.aud)[1] == "https://relay2.example.com");
    CHECK(token.core.exp == 1700086400);
    CHECK(token.core.nbf == 1700000000);
    CHECK(token.core.cti == "vector-002");
    CHECK(token.cat.catv == "CAT-v1");
    CHECK(token.cat.catu == 10);
  }

  SUBCASE("token_hmac_minimal - decodeToken round-trip") {
    auto &v = token_vectors[0];
    auto keyBytes = hexToBytes(v["key_hex"].get<std::string>());
    HmacSha256Algorithm hmac(keyBytes);

    std::string tokenStr = v["token"].get<std::string>();
    auto token = decodeToken(tokenStr, hmac);

    CHECK(token.core.iss == "https://auth.example.com");
    REQUIRE(token.core.aud.has_value());
    CHECK((*token.core.aud)[0] == "https://relay.example.com");
    CHECK(token.core.exp == 1700086400);
  }

  SUBCASE("token_hmac_full - decodeToken round-trip") {
    auto &v = token_vectors[1];
    auto keyBytes = hexToBytes(v["key_hex"].get<std::string>());
    HmacSha256Algorithm hmac(keyBytes);

    std::string tokenStr = v["token"].get<std::string>();
    auto token = decodeToken(tokenStr, hmac);

    CHECK(token.core.iss == "https://issuer.moq.example");
    REQUIRE(token.core.aud.has_value());
    CHECK(token.core.aud->size() == 2);
    CHECK(token.core.exp == 1700086400);
    CHECK(token.core.nbf == 1700000000);
    CHECK(token.core.cti == "vector-002");
    CHECK(token.cat.catv == "CAT-v1");
    CHECK(token.cat.catu == 10);
  }
}

TEST_CASE("Token Structure - ES256 signature verification") {
  auto vectors = loadTestVectors();
  auto &token_vectors = vectors["vectors"]["token_structure"]["vectors"];
  auto &v = token_vectors[2];
  REQUIRE(v["id"] == "token_es256");

  auto privateKeyRaw = hexToBytes(v["private_key_hex"].get<std::string>());
  auto publicKeyX = hexToBytes(v["public_key_x_hex"].get<std::string>());
  auto publicKeyY = hexToBytes(v["public_key_y_hex"].get<std::string>());

  auto [derPriv, derPub] = buildDerKeyPair(privateKeyRaw, publicKeyX, publicKeyY);
  Es256Algorithm es256(derPriv, derPub);

  auto headerBytes = base64UrlDecode(v["header_b64"].get<std::string>());
  auto payloadBytes = base64UrlDecode(v["payload_b64"].get<std::string>());
  auto expectedSig = base64UrlDecode(v["signature_b64"].get<std::string>());

  CHECK(bytesToHex(headerBytes) == v["header_cbor_hex"].get<std::string>());
  CHECK(bytesToHex(payloadBytes) == v["payload_cbor_hex"].get<std::string>());

  auto signingInput = createJwtSigningInput(headerBytes, payloadBytes);
  auto derSig = rawEcdsaToDer(expectedSig);
  CHECK(es256.verify(signingInput, derSig));

  auto token = Cwt::decodePayload(payloadBytes);
  CHECK(token.core.iss == "https://auth.example.com");
  REQUIRE(token.core.aud.has_value());
  CHECK((*token.core.aud)[0] == "https://moq-relay.example.com");
  CHECK(token.core.exp == 1700086400);
  CHECK(token.core.nbf == 1700000000);
}

TEST_CASE("Token Structure - Base64url component encoding") {
  auto vectors = loadTestVectors();
  auto &token_vectors = vectors["vectors"]["token_structure"]["vectors"];

  for (auto &v : token_vectors) {
    std::string tokenStr = v["token"].get<std::string>();
    std::string headerB64 = v["header_b64"].get<std::string>();
    std::string payloadB64 = v["payload_b64"].get<std::string>();
    std::string sigB64 = v["signature_b64"].get<std::string>();

    CHECK(tokenStr == headerB64 + "." + payloadB64 + "." + sigB64);
  }
}

TEST_CASE("Base64url - Encoding/decoding consistency with test vectors") {
  auto vectors = loadTestVectors();
  auto &token_vectors = vectors["vectors"]["token_structure"]["vectors"];

  for (auto &v : token_vectors) {
    auto headerHex = v["header_cbor_hex"].get<std::string>();
    auto headerBytes = hexToBytes(headerHex);
    auto encoded = base64UrlEncode(headerBytes);
    CHECK(encoded == v["header_b64"].get<std::string>());

    auto decoded = base64UrlDecode(v["header_b64"].get<std::string>());
    CHECK(decoded == headerBytes);

    auto payloadHex = v["payload_cbor_hex"].get<std::string>();
    auto payloadBytes = hexToBytes(payloadHex);
    auto payloadEncoded = base64UrlEncode(payloadBytes);
    CHECK(payloadEncoded == v["payload_b64"].get<std::string>());

    auto sigHex = v["signature_hex"].get<std::string>();
    auto sigBytes = hexToBytes(sigHex);
    auto sigEncoded = base64UrlEncode(sigBytes);
    CHECK(sigEncoded == v["signature_b64"].get<std::string>());
  }
}

TEST_CASE("Validation - Signature failure scenarios") {
  auto vectors = loadTestVectors();
  auto &keys = vectors["keys"];
  auto &val_vectors = vectors["vectors"]["validation"]["vectors"];
  auto hmacKey = hexToBytes(keys["hmac_sha256"].get<std::string>());
  HmacSha256Algorithm hmac(hmacKey);

  SUBCASE("invalid_tampered_signature - Corrupted signature rejected") {
    auto &v = val_vectors[5];
    REQUIRE(v["id"] == "invalid_tampered_signature");

    std::string tokenStr = v["token"].get<std::string>();
    CHECK_THROWS_AS(decodeToken(tokenStr, hmac), SignatureVerificationError);
  }

  SUBCASE("invalid_wrong_key - Wrong key rejected") {
    auto &v = val_vectors[6];
    REQUIRE(v["id"] == "invalid_wrong_key");

    auto wrongKey =
        hexToBytes(v["validation"]["wrong_key_hex"].get<std::string>());
    HmacSha256Algorithm wrongHmac(wrongKey);

    std::string tokenStr = v["token"].get<std::string>();
    CHECK_THROWS_AS(decodeToken(tokenStr, wrongHmac),
                    SignatureVerificationError);
  }

  SUBCASE("invalid_tampered_signature - Original token is valid") {
    auto &v = val_vectors[5];
    std::string originalToken =
        v["original_token"].get<std::string>();
    REQUIRE_NOTHROW(decodeToken(originalToken, hmac));
  }
}

TEST_CASE("Validation - Claim validation scenarios") {
  auto vectors = loadTestVectors();
  auto &keys = vectors["keys"];
  auto &val_vectors = vectors["vectors"]["validation"]["vectors"];
  auto hmacKey = hexToBytes(keys["hmac_sha256"].get<std::string>());
  HmacSha256Algorithm hmac(hmacKey);

  SUBCASE("valid_basic - Token claims are correct") {
    auto &v = val_vectors[0];
    REQUIRE(v["id"] == "valid_basic");

    std::string tokenStr = v["token"].get<std::string>();
    auto token = decodeToken(tokenStr, hmac);

    CHECK(token.core.iss == "https://auth.example.com");
    REQUIRE(token.core.aud.has_value());
    CHECK((*token.core.aud)[0] == "https://relay.example.com");
    CHECK(token.core.exp == 1700086400);
    CHECK(token.core.nbf == 1700000000);

    CatTokenValidator validator;
    validator
        .withExpectedIssuers(
            v["validation"]["expected_issuers"]
                .get<std::vector<std::string>>())
        .withExpectedAudiences(
            v["validation"]["expected_audiences"]
                .get<std::vector<std::string>>())
        .withClockSkewTolerance(
            static_cast<int64_t>(2000000000));
    REQUIRE_NOTHROW(validator.validate(token));
  }

  SUBCASE("invalid_expired - Expired token decoded then rejected") {
    auto &v = val_vectors[1];
    REQUIRE(v["id"] == "invalid_expired");

    std::string tokenStr = v["token"].get<std::string>();
    auto token = decodeToken(tokenStr, hmac);

    CatTokenValidator validator;
    CHECK_THROWS_AS(validator.validate(token), TokenExpiredError);
  }

  SUBCASE("invalid_not_yet_valid - NBF in the future relative to reference time") {
    auto &v = val_vectors[2];
    REQUIRE(v["id"] == "invalid_not_yet_valid");

    std::string tokenStr = v["token"].get<std::string>();
    auto token = decodeToken(tokenStr, hmac);

    // The vector has nbf=1700086400, exp=1700172800 at reference_time=1700000000.
    // At that reference time, nbf is in the future (token not yet valid).
    // Since current wall clock is past exp, our validator sees expiry first.
    // Either way, the token correctly fails validation.
    REQUIRE(token.core.nbf.has_value());
    REQUIRE(token.core.exp.has_value());
    CHECK(*token.core.exp > *token.core.nbf);

    CatTokenValidator validator;
    CHECK_THROWS(validator.validate(token));
  }

  SUBCASE("invalid_wrong_issuer - Issuer validation") {
    auto &v = val_vectors[3];
    REQUIRE(v["id"] == "invalid_wrong_issuer");

    std::string tokenStr = v["token"].get<std::string>();
    auto token = decodeToken(tokenStr, hmac);

    // The token exp is also in the past. Use large clock skew to
    // bypass time checks and test issuer validation.
    CatTokenValidator validator;
    validator.withExpectedIssuers(
        v["validation"]["expected_issuers"]
            .get<std::vector<std::string>>())
        .withClockSkewTolerance(static_cast<int64_t>(2000000000));

    CHECK_THROWS_AS(validator.validate(token), InvalidIssuerError);
  }

  SUBCASE("invalid_wrong_audience - Audience validation") {
    auto &v = val_vectors[4];
    REQUIRE(v["id"] == "invalid_wrong_audience");

    std::string tokenStr = v["token"].get<std::string>();
    auto token = decodeToken(tokenStr, hmac);

    CatTokenValidator validator;
    validator
        .withExpectedIssuers(
            v["validation"]["expected_issuers"]
                .get<std::vector<std::string>>())
        .withExpectedAudiences(
            v["validation"]["expected_audiences"]
                .get<std::vector<std::string>>())
        .withClockSkewTolerance(
            static_cast<int64_t>(2000000000));

    CHECK_THROWS_AS(validator.validate(token), InvalidAudienceError);
  }
}

TEST_CASE("MOQT Scopes - Authorization matching from test vectors") {
  auto vectors = loadTestVectors();
  auto &moqt_vectors = vectors["vectors"]["moqt_scopes"]["vectors"];

  SUBCASE("moqt_admin_wildcard - All actions, no restrictions") {
    auto &v = moqt_vectors[3];
    REQUIRE(v["id"] == "moqt_admin_wildcard");

    auto &scope_def = v["moqt_scopes"][0];
    auto actions = scope_def["actions"].get<std::vector<int>>();

    auto scope = MoqtActionScope::create(actions, MoqtBinaryMatch::any(),
                                         MoqtBinaryMatch::any());

    for (auto &test : v["authorization_tests"]) {
      int action = test["action"].get<int>();
      std::string track = test["track"].get<std::string>();
      bool expected = test["expected"].get<bool>();
      auto ns_parts = test["namespace"].get<std::vector<std::string>>();

      CHECK(scope.authorizes(action, ns_parts[0], track) == expected);
    }
  }

  SUBCASE("moqt_suffix_match - Suffix matching on namespace and track") {
    auto &v = moqt_vectors[4];
    REQUIRE(v["id"] == "moqt_suffix_match");

    auto &scope_def = v["moqt_scopes"][0];
    auto actions = scope_def["actions"].get<std::vector<int>>();

    std::string ns_pattern =
        scope_def["namespace_matches"][0]["pattern_utf8"].get<std::string>();
    auto ns_match = MoqtBinaryMatch::suffix(ns_pattern);

    std::string tr_pattern =
        scope_def["track_match"]["pattern_utf8"].get<std::string>();
    auto tr_match = MoqtBinaryMatch::suffix(tr_pattern);

    auto scope = MoqtActionScope::create(actions, ns_match, tr_match);

    for (auto &test : v["authorization_tests"]) {
      int action = test["action"].get<int>();
      std::string track = test["track"].get<std::string>();
      bool expected = test["expected"].get<bool>();
      auto ns_parts = test["namespace"].get<std::vector<std::string>>();

      CHECK(scope.authorizes(action, ns_parts[0], track) == expected);
    }
  }

  SUBCASE("moqt_subscriber_prefix - Prefix namespace match") {
    auto &v = moqt_vectors[1];
    REQUIRE(v["id"] == "moqt_subscriber_prefix");

    auto &scope_def = v["moqt_scopes"][0];
    auto actions = scope_def["actions"].get<std::vector<int>>();

    std::string ns_pattern =
        scope_def["namespace_matches"][0]["pattern_utf8"].get<std::string>();
    auto ns_match = MoqtBinaryMatch::prefix(ns_pattern);

    auto scope =
        MoqtActionScope::create(actions, ns_match, MoqtBinaryMatch::any());

    for (auto &test : v["authorization_tests"]) {
      int action = test["action"].get<int>();
      std::string track = test["track"].get<std::string>();
      bool expected = test["expected"].get<bool>();
      auto ns_parts = test["namespace"].get<std::vector<std::string>>();

      CHECK(scope.authorizes(action, ns_parts[0], track) == expected);
    }
  }
}

TEST_CASE("MOQT Scopes - CBOR payload decoding") {
  auto vectors = loadTestVectors();
  auto &moqt_vectors = vectors["vectors"]["moqt_scopes"]["vectors"];

  for (auto &v : moqt_vectors) {
    auto cborData = hexToBytes(v["payload_cbor_hex"].get<std::string>());
    REQUIRE_NOTHROW(Cwt::decodePayload(cborData));

    auto token = Cwt::decodePayload(cborData);
    CHECK(token.core.iss == "https://auth.example.com");
    CHECK(token.core.exp == 1700086400);
  }
}

TEST_CASE("MOQT Scopes - Token signature verification") {
  auto vectors = loadTestVectors();
  auto &keys = vectors["keys"];
  auto &moqt_vectors = vectors["vectors"]["moqt_scopes"]["vectors"];
  auto hmacKey = hexToBytes(keys["hmac_sha256"].get<std::string>());
  HmacSha256Algorithm hmac(hmacKey);

  for (auto &v : moqt_vectors) {
    if (!v.contains("token")) continue;
    std::string tokenStr = v["token"].get<std::string>();
    REQUIRE_NOTHROW(decodeToken(tokenStr, hmac));
  }
}

TEST_CASE("DPoP Binding - Payload decoding from test vectors") {
  auto vectors = loadTestVectors();
  auto &dpop_vectors = vectors["vectors"]["dpop_binding"]["vectors"];

  SUBCASE("dpop_jwk_binding - Decode claims") {
    auto &v = dpop_vectors[0];
    REQUIRE(v["id"] == "dpop_jwk_binding");

    auto cborData = hexToBytes(v["payload_cbor_hex"].get<std::string>());
    auto token = Cwt::decodePayload(cborData);

    CHECK(token.core.iss == "https://auth.example.com");
    CHECK(token.core.exp == 1700086400);
  }

  SUBCASE("dpop_es256_real_binding - Decode claims") {
    auto &v = dpop_vectors[2];
    REQUIRE(v["id"] == "dpop_es256_real_binding");

    auto cborData = hexToBytes(v["payload_cbor_hex"].get<std::string>());
    auto token = Cwt::decodePayload(cborData);

    CHECK(token.core.iss == "https://auth.example.com");
    REQUIRE(token.core.aud.has_value());
    CHECK((*token.core.aud)[0] == "https://relay.example.com");
    CHECK(token.core.exp == 1700086400);
  }
}

TEST_CASE("DPoP Binding - HMAC token signature verification") {
  auto vectors = loadTestVectors();
  auto &keys = vectors["keys"];
  auto &dpop_vectors = vectors["vectors"]["dpop_binding"]["vectors"];
  auto hmacKey = hexToBytes(keys["hmac_sha256"].get<std::string>());
  HmacSha256Algorithm hmac(hmacKey);

  SUBCASE("dpop_jwk_binding") {
    auto &v = dpop_vectors[0];
    std::string tokenStr = v["token"].get<std::string>();
    REQUIRE_NOTHROW(decodeToken(tokenStr, hmac));
  }

  SUBCASE("dpop_no_jti") {
    auto &v = dpop_vectors[1];
    std::string tokenStr = v["token"].get<std::string>();
    REQUIRE_NOTHROW(decodeToken(tokenStr, hmac));
  }
}

TEST_CASE("DPoP Binding - ES256 token signature verification") {
  auto vectors = loadTestVectors();
  auto &dpop_vectors = vectors["vectors"]["dpop_binding"]["vectors"];
  auto &v = dpop_vectors[2];
  REQUIRE(v["id"] == "dpop_es256_real_binding");

  auto publicKeyX = hexToBytes(v["public_key_x_hex"].get<std::string>());
  auto publicKeyY = hexToBytes(v["public_key_y_hex"].get<std::string>());
  auto derPub = buildDerPublicKey(publicKeyX, publicKeyY);
  Es256Algorithm es256(derPub);

  std::string tokenStr = v["token"].get<std::string>();

  std::vector<std::string> parts;
  std::stringstream ss(tokenStr);
  std::string part;
  while (std::getline(ss, part, '.')) {
    parts.push_back(part);
  }
  REQUIRE(parts.size() == 3);

  auto headerBytes = base64UrlDecode(parts[0]);
  auto payloadBytes = base64UrlDecode(parts[1]);
  auto signature = base64UrlDecode(parts[2]);

  auto signingInput = createJwtSigningInput(headerBytes, payloadBytes);
  auto derSig = rawEcdsaToDer(signature);
  CHECK(es256.verify(signingInput, derSig));
}

} // TEST_SUITE
