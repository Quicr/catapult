/**
 * @file relay_token_validation.cpp
 * @brief Relay-side: Validating CAT tokens and DPoP proofs for MOQT authorization
 */

#include "catapult/catapult_minimal.hpp"
#include "catapult/moqt_claims.hpp"
#include "catapult/dpop.hpp"
#include <iostream>
#include <chrono>
#include <vector>

using namespace catapult;

struct AuthorizationResult {
    bool authorized = false;
    std::string reason;
};

AuthorizationResult validate_request(
    const CatToken& token,
    const std::string& dpop_proof_str,
    int requested_action,
    const std::string& requested_namespace,
    const std::string& requested_track,
    const std::string& relay_endpoint
) {
    AuthorizationResult result;

    // Step 1: Check token expiration
    if (token.core.exp.has_value()) {
        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        if (now > token.core.exp.value()) {
            result.reason = "Token expired";
            return result;
        }
    }

    // Step 2: Verify audience matches this relay
    if (token.core.aud.has_value()) {
        bool aud_match = false;
        for (const auto& aud : *token.core.aud) {
            if (aud.find("relay") != std::string::npos) {
                aud_match = true;
                break;
            }
        }
        if (!aud_match) {
            result.reason = "Token not intended for this relay";
            return result;
        }
    }

    // Step 3: Check MOQT authorization
    if (!token.extended.hasMoqtClaims()) {
        result.reason = "No MOQT claims in token";
        return result;
    }

    const auto* moqt = token.extended.getMoqtClaimsReadOnly();
    if (!moqt->isAuthorized(requested_action, requested_namespace, requested_track)) {
        result.reason = "MOQT action not authorized";
        return result;
    }

    // Step 4: Validate DPoP proof
    if (!token.dpop.cnf.has_value()) {
        result.reason = "Token missing DPoP confirmation";
        return result;
    }

    DpopProof proof = DpopProof::deserialize(dpop_proof_str);

    CatDpopSettings dpop_settings;
    dpop_settings.set_window(std::chrono::seconds{300});
    DpopProofValidator validator(dpop_settings);

    auto expected_uri = moqt_dpop::construct_moqt_uri(
        relay_endpoint, requested_namespace, requested_track);

    if (!validator.validate_proof(proof, requested_action, expected_uri, *token.dpop.cnf)) {
        result.reason = "DPoP proof validation failed";
        return result;
    }

    result.authorized = true;
    result.reason = "All validations passed";
    return result;
}

int main() {
    std::cout << "=== MOQT Relay: Token Validation ===\n\n";

    // Relay configuration
    const std::string relay_endpoint = "relay.moqt-cdn.example.com:4433";

    // Issuer's public key (loaded from configuration/JWKS)
    auto [issuer_private, issuer_public] = Es256Algorithm::generateSecureKeyPair();
    Es256Algorithm issuer_signer(issuer_private, issuer_public);
    Es256Algorithm issuer_verifier(issuer_public);

    // Create a test token and proof (simulating client request)
    auto client_algo = std::make_unique<Es256Algorithm>();
    DpopKeyPair client_keys(std::move(client_algo));

    auto token = CatToken::builder()
        .issuer("auth.moqt-cdn.example.com")
        .audience("relay.moqt-cdn.example.com")
        .expiresIn(std::chrono::hours{1})
        .dpopThumbprint(client_keys.get_public_key_thumbprint())
        .build();

    MoqtClaims moqt;
    std::vector<int> publish_actions = {moqt_actions::PUBLISH};
    moqt.addScope(publish_actions, MoqtBinaryMatch::exact("live"), MoqtBinaryMatch::any());
    token.extended.setMoqtClaims(std::move(moqt));

    auto jti = moqt_dpop::generate_jti();
    auto proof = client_keys.generate_proof(moqt_actions::PUBLISH, "live", "video", relay_endpoint, jti);
    std::string proof_str = proof.serialize();

    // Test 1: Valid request
    std::cout << "Test 1: Valid PUBLISH to live/video\n";
    auto result1 = validate_request(token, proof_str,
        moqt_actions::PUBLISH, "live", "video", relay_endpoint);
    std::cout << "  Result: " << (result1.authorized ? "AUTHORIZED" : "DENIED")
              << " - " << result1.reason << "\n\n";

    // Test 2: Unauthorized action
    std::cout << "Test 2: SUBSCRIBE (not permitted)\n";
    auto proof2 = client_keys.generate_proof(moqt_actions::SUBSCRIBE, "live", "video", relay_endpoint, moqt_dpop::generate_jti());
    auto result2 = validate_request(token, proof2.serialize(),
        moqt_actions::SUBSCRIBE, "live", "video", relay_endpoint);
    std::cout << "  Result: " << (result2.authorized ? "AUTHORIZED" : "DENIED")
              << " - " << result2.reason << "\n\n";

    // Test 3: Wrong namespace
    std::cout << "Test 3: PUBLISH to wrong namespace\n";
    auto proof3 = client_keys.generate_proof(moqt_actions::PUBLISH, "other", "video", relay_endpoint, moqt_dpop::generate_jti());
    auto result3 = validate_request(token, proof3.serialize(),
        moqt_actions::PUBLISH, "other", "video", relay_endpoint);
    std::cout << "  Result: " << (result3.authorized ? "AUTHORIZED" : "DENIED")
              << " - " << result3.reason << "\n";

    return 0;
}
