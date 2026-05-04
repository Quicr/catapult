/**
 * @file performance.cpp
 * @brief Performance tests for high-scale token validation (100K+ operations)
 */

#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include "catapult/catapult_minimal.hpp"
#include "catapult/moqt_claims.hpp"
#include "catapult/dpop.hpp"
#include <chrono>
#include <vector>
#include <numeric>

using namespace catapult;

namespace {

struct TestFixture {
    SecureVector<uint8_t> hmac_key;
    SecureVector<uint8_t> es256_private;
    std::vector<uint8_t> es256_public;
    std::string hmac_token;
    std::string es256_token;
    CatToken base_token;

    TestFixture() {
        hmac_key = HmacSha256Algorithm::generateSecureKey();
        auto [priv, pub] = Es256Algorithm::generateSecureKeyPair();
        es256_private = std::move(priv);
        es256_public = std::move(pub);

        base_token = CatToken::builder()
            .issuer("perf-test.example.com")
            .audience("relay.example.com")
            .expiresIn(std::chrono::hours{1})
            .build();

        MoqtClaims moqt;
        std::vector<int> actions = {moqt_actions::PUBLISH, moqt_actions::SUBSCRIBE};
        moqt.addScope(actions, MoqtBinaryMatch::any(), MoqtBinaryMatch::any());
        base_token.extended.setMoqtClaims(std::move(moqt));

        HmacSha256Algorithm hmac(hmac_key);
        Cwt hmac_cwt(ALG_HMAC256_256, base_token);
        hmac_token = hmac_cwt.createCwtBase64(CwtMode::MACed, hmac);

        Es256Algorithm es256(es256_private, es256_public);
        Cwt es256_cwt(ALG_ES256, base_token);
        es256_token = es256_cwt.createCwtBase64(CwtMode::Signed, es256);
    }
};

}  // namespace

TEST_CASE("HMAC token validation throughput", "[performance][hmac]") {
    TestFixture fixture;
    HmacSha256Algorithm hmac(fixture.hmac_key);

    constexpr size_t iterations = 100000;
    size_t successful = 0;

    auto start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < iterations; ++i) {
        try {
            auto validated = Cwt::validateCwtBase64(fixture.hmac_token, hmac);
            if (validated.payload.core.iss.has_value()) {
                ++successful;
            }
        } catch (...) {
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    double ops_per_sec = (iterations * 1000.0) / duration_ms;

    INFO("HMAC validations: " << iterations);
    INFO("Duration: " << duration_ms << " ms");
    INFO("Throughput: " << ops_per_sec << " ops/sec");
    INFO("Successful: " << successful);

    REQUIRE(successful == iterations);
    REQUIRE(ops_per_sec > 10000);  // Expect >10K ops/sec for HMAC
}

TEST_CASE("ES256 token validation throughput", "[performance][es256]") {
    TestFixture fixture;
    Es256Algorithm verifier(fixture.es256_public);

    constexpr size_t iterations = 10000;  // Fewer iterations for asymmetric
    size_t successful = 0;

    auto start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < iterations; ++i) {
        try {
            auto validated = Cwt::validateCwtBase64(fixture.es256_token, verifier);
            if (validated.payload.core.iss.has_value()) {
                ++successful;
            }
        } catch (...) {
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    double ops_per_sec = (iterations * 1000.0) / duration_ms;

    INFO("ES256 validations: " << iterations);
    INFO("Duration: " << duration_ms << " ms");
    INFO("Throughput: " << ops_per_sec << " ops/sec");
    INFO("Successful: " << successful);

    REQUIRE(successful == iterations);
    REQUIRE(ops_per_sec > 500);  // Expect >500 ops/sec for ES256
}

TEST_CASE("MOQT authorization check throughput", "[performance][moqt]") {
    MoqtClaims moqt;
    std::vector<int> pub = {moqt_actions::PUBLISH};
    std::vector<int> sub = {moqt_actions::SUBSCRIBE};
    std::vector<int> fetch = {moqt_actions::FETCH};
    moqt.addScope(pub, MoqtBinaryMatch::exact("live"), MoqtBinaryMatch::any());
    moqt.addScope(sub, MoqtBinaryMatch::any(), MoqtBinaryMatch::prefix("public-"));
    moqt.addScope(fetch, MoqtBinaryMatch::prefix("vod-"), MoqtBinaryMatch::any());

    constexpr size_t iterations = 1000000;
    size_t authorized = 0;

    auto start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < iterations; ++i) {
        if (moqt.isAuthorized(moqt_actions::PUBLISH, "live", "track-" + std::to_string(i % 100))) {
            ++authorized;
        }
        if (moqt.isAuthorized(moqt_actions::SUBSCRIBE, "any-ns", "public-track")) {
            ++authorized;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    double ops_per_sec = (iterations * 2 * 1000.0) / duration_ms;

    INFO("MOQT auth checks: " << iterations * 2);
    INFO("Duration: " << duration_ms << " ms");
    INFO("Throughput: " << ops_per_sec << " ops/sec");

    REQUIRE(authorized == iterations * 2);
    REQUIRE(ops_per_sec > 1000000);  // Expect >1M ops/sec for in-memory checks
}

TEST_CASE("DPoP proof generation throughput", "[performance][dpop]") {
    auto algo = std::make_unique<Es256Algorithm>();
    DpopKeyPair keys(std::move(algo));

    constexpr size_t iterations = 10000;
    size_t generated = 0;

    auto start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < iterations; ++i) {
        auto jti = moqt_dpop::generate_jti();
        auto proof = keys.generate_proof(moqt_actions::PUBLISH, "ns", "track", "relay:4433", jti);
        if (!proof.serialize().empty()) {
            ++generated;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    double ops_per_sec = (iterations * 1000.0) / duration_ms;

    INFO("DPoP proofs generated: " << iterations);
    INFO("Duration: " << duration_ms << " ms");
    INFO("Throughput: " << ops_per_sec << " ops/sec");

    REQUIRE(generated == iterations);
    REQUIRE(ops_per_sec > 500);  // Expect >500 ops/sec
}

TEST_CASE("DPoP proof validation throughput", "[performance][dpop]") {
    auto algo = std::make_unique<Es256Algorithm>();
    DpopKeyPair keys(std::move(algo));
    std::string thumbprint = keys.get_public_key_thumbprint();

    CatDpopSettings settings;
    settings.set_window(std::chrono::seconds{300});
    settings.set_jti_processing(false);  // Disable JTI replay check for throughput test
    DpopProofValidator validator(settings);

    auto jti = moqt_dpop::generate_jti();
    auto proof = keys.generate_proof(moqt_actions::PUBLISH, "ns", "track", "relay:4433", jti);
    std::string proof_str = proof.serialize();
    std::string expected_uri = moqt_dpop::construct_moqt_uri("relay:4433", "ns", "track");

    constexpr size_t iterations = 10000;
    size_t valid = 0;

    auto start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < iterations; ++i) {
        auto deserialized = DpopProof::deserialize(proof_str);
        if (validator.validate_proof(deserialized, moqt_actions::PUBLISH, expected_uri, thumbprint)) {
            ++valid;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    double ops_per_sec = (iterations * 1000.0) / duration_ms;

    INFO("DPoP validations: " << iterations);
    INFO("Duration: " << duration_ms << " ms");
    INFO("Throughput: " << ops_per_sec << " ops/sec");

    REQUIRE(valid == iterations);
    REQUIRE(ops_per_sec > 500);  // Expect >500 ops/sec
}

TEST_CASE("Token creation throughput", "[performance][creation]") {
    auto [priv, pub] = Es256Algorithm::generateSecureKeyPair();
    Es256Algorithm signer(priv, pub);

    constexpr size_t iterations = 10000;
    size_t created = 0;

    auto start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < iterations; ++i) {
        auto token = CatToken::builder()
            .issuer("test.example.com")
            .audience("client.example.com")
            .expiresIn(std::chrono::hours{1})
            .build();

        Cwt cwt(ALG_ES256, token);
        auto encoded = cwt.createCwtBase64(CwtMode::Signed, signer);
        if (!encoded.empty()) {
            ++created;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    double ops_per_sec = (iterations * 1000.0) / duration_ms;

    INFO("Tokens created: " << iterations);
    INFO("Duration: " << duration_ms << " ms");
    INFO("Throughput: " << ops_per_sec << " ops/sec");

    REQUIRE(created == iterations);
    REQUIRE(ops_per_sec > 500);  // Expect >500 ops/sec
}

TEST_CASE("End-to-end relay validation throughput", "[performance][e2e]") {
    // Setup: auth server keys
    auto [auth_priv, auth_pub] = Es256Algorithm::generateSecureKeyPair();
    Es256Algorithm auth_signer(auth_priv, auth_pub);
    Es256Algorithm auth_verifier(auth_pub);

    // Setup: client DPoP keys
    auto client_algo = std::make_unique<Es256Algorithm>();
    DpopKeyPair client_keys(std::move(client_algo));

    // Create token
    auto token = CatToken::builder()
        .issuer("auth.example.com")
        .audience("relay.example.com")
        .expiresIn(std::chrono::hours{1})
        .dpopThumbprint(client_keys.get_public_key_thumbprint())
        .build();

    MoqtClaims moqt;
    std::vector<int> pub = {moqt_actions::PUBLISH};
    moqt.addScope(pub, MoqtBinaryMatch::any(), MoqtBinaryMatch::any());
    token.extended.setMoqtClaims(std::move(moqt));

    Cwt cwt(ALG_ES256, token);
    std::string token_str = cwt.createCwtBase64(CwtMode::Signed, auth_signer);

    CatDpopSettings dpop_settings;
    dpop_settings.set_window(std::chrono::seconds{300});
    DpopProofValidator dpop_validator(dpop_settings);

    // Pre-generate proofs (client does this, not relay)
    constexpr size_t iterations = 100000;
    std::vector<DpopProof> proofs;
    proofs.reserve(iterations);
    for (size_t i = 0; i < iterations; ++i) {
        auto jti = moqt_dpop::generate_jti();
        proofs.push_back(client_keys.generate_proof(moqt_actions::PUBLISH, "ns", "track", "relay:4433", jti));
    }

    size_t authorized = 0;
    std::string expected_uri = moqt_dpop::construct_moqt_uri("relay:4433", "ns", "track");

    auto start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < iterations; ++i) {
        // Relay validation only (no proof generation)
        auto validated = Cwt::validateCwtBase64(token_str, auth_verifier);

        if (validated.payload.extended.hasMoqtClaims()) {
            const auto* moqt_claims = validated.payload.extended.getMoqtClaimsReadOnly();
            if (moqt_claims->isAuthorized(moqt_actions::PUBLISH, "ns", "track")) {
                if (dpop_validator.validate_proof(proofs[i], moqt_actions::PUBLISH, expected_uri,
                        *validated.payload.dpop.cnf)) {
                    ++authorized;
                }
            }
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    double ops_per_sec = (iterations * 1000.0) / duration_ms;

    INFO("E2E validations: " << iterations);
    INFO("Duration: " << duration_ms << " ms");
    INFO("Throughput: " << ops_per_sec << " ops/sec");

    REQUIRE(authorized == iterations);
    REQUIRE(ops_per_sec > 1000);  // Expect >1000 relay validations/sec
}

TEST_CASE("End-to-end relay validation with token cache", "[performance][e2e][cache]") {
    // Setup: auth server keys
    auto [auth_priv, auth_pub] = Es256Algorithm::generateSecureKeyPair();
    Es256Algorithm auth_signer(auth_priv, auth_pub);
    Es256Algorithm auth_verifier(auth_pub);

    // Setup: client DPoP keys
    auto client_algo = std::make_unique<Es256Algorithm>();
    DpopKeyPair client_keys(std::move(client_algo));

    // Create token
    auto token = CatToken::builder()
        .issuer("auth.example.com")
        .audience("relay.example.com")
        .expiresIn(std::chrono::hours{1})
        .dpopThumbprint(client_keys.get_public_key_thumbprint())
        .build();

    MoqtClaims moqt;
    std::vector<int> pub = {moqt_actions::PUBLISH};
    moqt.addScope(pub, MoqtBinaryMatch::any(), MoqtBinaryMatch::any());
    token.extended.setMoqtClaims(std::move(moqt));

    Cwt cwt(ALG_ES256, token);
    std::string token_str = cwt.createCwtBase64(CwtMode::Signed, auth_signer);

    CatDpopSettings dpop_settings;
    dpop_settings.set_window(std::chrono::seconds{300});
    DpopProofValidator dpop_validator(dpop_settings);

    // Pre-generate proofs
    constexpr size_t iterations = 100000;
    std::vector<DpopProof> proofs;
    proofs.reserve(iterations);
    for (size_t i = 0; i < iterations; ++i) {
        auto jti = moqt_dpop::generate_jti();
        proofs.push_back(client_keys.generate_proof(moqt_actions::PUBLISH, "ns", "track", "relay:4433", jti));
    }

    // Simulate token cache: validate once, reuse the result
    auto cached_token = Cwt::validateCwtBase64(token_str, auth_verifier);
    const auto* cached_moqt = cached_token.payload.extended.getMoqtClaimsReadOnly();
    const std::string& cached_thumbprint = *cached_token.payload.dpop.cnf;

    size_t authorized = 0;
    std::string expected_uri = moqt_dpop::construct_moqt_uri("relay:4433", "ns", "track");

    auto start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < iterations; ++i) {
        // Cached validation: skip CWT signature verification
        if (cached_moqt->isAuthorized(moqt_actions::PUBLISH, "ns", "track")) {
            if (dpop_validator.validate_proof(proofs[i], moqt_actions::PUBLISH, expected_uri,
                    cached_thumbprint)) {
                ++authorized;
            }
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    double ops_per_sec = (iterations * 1000.0) / duration_ms;

    INFO("Cached E2E validations: " << iterations);
    INFO("Duration: " << duration_ms << " ms");
    INFO("Throughput: " << ops_per_sec << " ops/sec");

    REQUIRE(authorized == iterations);
    REQUIRE(ops_per_sec > 50000);  // Expect >50k with caching
}
