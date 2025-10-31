/**
 * @file moqt_dpop_example.cpp
 * @brief End-to-end example demonstrating MOQT with DPoP proof-of-possession
 * 
 * This example shows how to:
 * 1. Create CAT tokens with MOQT claims and DPoP binding
 * 2. Generate DPoP proofs for MOQT actions
 * 3. Validate the entire flow
 */

#include "catapult/token.hpp"
#include "catapult/claims.hpp"
#include "catapult/moqt_claims.hpp"
#include "catapult/dpop.hpp"
#include "catapult/crypto.hpp"
#include "catapult/json_serialization.hpp"
#include "catapult/cwt.hpp"
#include <iostream>
#include <chrono>

using namespace catapult;

int main() {
    std::cout << "MOQT + DPoP End-to-End Example\n";

    try {
        // Step 1: Create a DPoP key pair for the client
        std::cout << "1. Creating DPoP key pair...\n";
        auto crypto_alg = std::make_unique<Es256Algorithm>();
        DpopKeyPair client_keypair(std::move(crypto_alg));
        std::cout << "   Public key thumbprint: " << client_keypair.get_public_key_thumbprint() << "\n\n";

        // Step 2: Create CAT token with MOQT claims and DPoP binding
        std::cout << "2. Creating CAT token with MOQT claims and DPoP binding...\n";

        CoreClaims core_claims;
        core_claims.iss = "moqt-authority.example.com";
        core_claims.aud = std::vector<std::string>{"moqt-relay.example.com"};
        core_claims.exp = std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now() + std::chrono::hours{1}
        );

        InformationalClaims info_claims;
        info_claims.sub = "client-123";
        info_claims.iat = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

        MoqtClaims moqt_claims = MoqtClaims::create(2);
        
        // Scope 1: Allow PUBLISH action for any track in "live-stream" namespace
        std::vector<int> publish_actions = {moqt_actions::PUBLISH};
        moqt_claims.addScope(
            publish_actions,
            MoqtBinaryMatch::exact("live-stream"),
            MoqtBinaryMatch::any() // Empty match = any track
        );
        
        // Scope 2: Allow SUBSCRIBE and FETCH for tracks starting with "public-" in any namespace
        std::vector<int> read_actions = {moqt_actions::SUBSCRIBE, moqt_actions::FETCH};
        moqt_claims.addScope(
            read_actions,
            MoqtBinaryMatch::exact("live-stream"),
            MoqtBinaryMatch::prefix("public-")
        );
        
        // Set revalidation interval
        moqt_claims.setRevalidationInterval(std::chrono::seconds{1800}); // 30 minutes

        // Create DPoP settings
        CatDpopSettings dpop_settings;
        dpop_settings.set_window(std::chrono::seconds{300}); // 5 minute window
        dpop_settings.set_jti_processing(true); // Enable JTI validation

        // Create enhanced DPoP claims
        EnhancedDpopClaims dpop_claims;
        dpop_claims.set_confirmation(client_keypair.get_public_key_thumbprint());
        dpop_claims.set_dpop_settings(dpop_settings);

        // Create CAT token
        CatToken token;
        token.core = std::move(core_claims);
        token.informational = std::move(info_claims);
        token.extended.setMoqtClaims(std::move(moqt_claims));
        
        // Set DPoP claims
        token.dpop.cnf = client_keypair.get_public_key_thumbprint();
        // Note: catdpop would contain serialized settings in real implementation
        std::cout << "   CAT token created successfully\n\n";

        // Step 2.5: Encode token to CWT format
        Cwt cwt_token(-7, token); // ES256 algorithm identifier
        cwt_token.withKeyId("sixteen-char-keyid"); // Example key ID

        auto cwt_payload = cwt_token.encodePayload();
        std::cout << "   CWT payload encoded (" << cwt_payload.size() << " bytes)\n";

        // Step 2.6: Base64 encode the CWT
        auto base64_encoded = base64UrlEncode(cwt_payload);
        std::cout << "   Base64 encoded CWT (" << base64_encoded.length() << " chars):\n";
        std::cout << "   " << base64_encoded << "\n\n";

        // Step 2.7: Base64 decode the CWT
        auto decoded_cwt_bytes = base64UrlDecode(base64_encoded);
        std::cout << "   Base64 decoded (" << decoded_cwt_bytes.size() << " bytes)\n";

        // Verify the decoded bytes match the original
        bool decode_match = (decoded_cwt_bytes == cwt_payload);
        std::cout << "   Decode verification: " << (decode_match ? "PASS" : "FAIL") << "\n";

        // Step 2.8: CWT decode back to token
        auto decoded_token = Cwt::decodePayload(decoded_cwt_bytes);
        std::cout << "   CWT payload decoded successfully\n";


        // Step 3: Client wants to publish to a track
        std::cout << "3. Client publishing to MOQT track...\n";
        const std::string endpoint = "relay.example.com:4433";
        const std::string namespace_name = "live-stream";
        const std::string track_name = "video-feed-1";
        const int moqt_action = moqt_actions::PUBLISH;
        
        std::cout << "   Action: " << moqt_actions::action_name(moqt_action) << "\n";
        std::cout << "   Namespace: " << namespace_name << "\n";
        std::cout << "   Track: " << track_name << "\n";
        std::cout << "   Endpoint: " << endpoint << "\n\n";

        // Step 4: Generate DPoP proof for the action
        auto jti = moqt_dpop::generate_jti();
        auto dpop_proof = client_keypair.generate_proof(
            moqt_action, namespace_name, track_name, endpoint, jti
        );
        
        auto dpop_serialized = dpop_proof.serialize();
        std::cout << "   DPoP proof (serialized): " << dpop_serialized.substr(0, 50) << "...\n";
        std::cout << "   JTI: " << jti << "\n\n";

        // Step 5: Server-side validation
        std::cout << "5. Server validating request...\n";
        
        const auto& parsed_claims = decoded_token;
        
        // Check MOQT authorization
        bool moqt_authorized = false;
        if (parsed_claims.extended.hasMoqtClaims()) {
            const auto* moqt_claims_ptr = parsed_claims.extended.getMoqtClaimsReadOnly();
            moqt_authorized = moqt_claims_ptr->isAuthorized(moqt_action, namespace_name, track_name);
        }
        
        std::cout << "   MOQT authorization: " << (moqt_authorized ? "GRANTED" : "DENIED") << "\n";
        std::cout << "     Expected: GRANTED (PUBLISH allowed for 'live-stream' namespace)\n";
        std::cout << "     Obtained: " << (moqt_authorized ? "GRANTED" : "DENIED") << "\n";
        
        // Validate DPoP proof
        DpopProofValidator dpop_validator(dpop_settings);
        auto expected_uri = moqt_dpop::construct_moqt_uri(endpoint, namespace_name, track_name);
        
        bool dpop_valid = dpop_validator.validate_proof(
            dpop_proof,
            moqt_action,
            expected_uri,
            client_keypair.get_public_key_thumbprint()
        );
        
        std::cout << "   DPoP proof validation: " << (dpop_valid ? "VALID" : "INVALID") << "\n";
        std::cout << "     Expected: VALID (correct action, URI, and key thumbprint)\n";
        std::cout << "     Obtained: " << (dpop_valid ? "VALID" : "INVALID") << "\n";
        std::cout << "     MOQT Action: " << moqt_action << " (" << moqt_actions::action_name(moqt_action) << ")\n";
        std::cout << "     URI: " << expected_uri << "\n";
        std::cout << "     Context Type: " << dpop_proof.get_payload().actx.type << "\n";
        std::cout << "     Track Namespace (tns): " << dpop_proof.get_payload().actx.tns << "\n";
        std::cout << "     Track Name (tn): " << dpop_proof.get_payload().actx.tn << "\n";
        
        // Check DPoP binding in token
        bool dpop_binding_valid = false;
        if (parsed_claims.dpop.cnf.has_value()) {
            dpop_binding_valid = (parsed_claims.dpop.cnf.value() == 
                                client_keypair.get_public_key_thumbprint());
        }
        
        std::cout << "   DPoP binding validation: " << (dpop_binding_valid ? "VALID" : "INVALID") << "\n";
        std::cout << "     Expected: VALID (token cnf matches proof key thumbprint)\n";
        std::cout << "     Obtained: " << (dpop_binding_valid ? "VALID" : "INVALID") << "\n";
        std::cout << "     Token cnf: " << (parsed_claims.dpop.cnf.has_value() ? parsed_claims.dpop.cnf.value() : "none") << "\n";
        std::cout << "     Proof key: " << client_keypair.get_public_key_thumbprint() << "\n";
        
        // Final authorization decision
        bool final_authorized = moqt_authorized && dpop_valid && dpop_binding_valid;
        std::cout << "\n   FINAL AUTHORIZATION: " << (final_authorized ? "GRANTED" : "DENIED") << "\n";
        std::cout << "     Expected: GRANTED (all validations pass)\n";
        std::cout << "     Obtained: " << (final_authorized ? "GRANTED" : "DENIED") << "\n\n";

        // Step 6: Demonstrate different scenarios
        std::cout << "6. Testing different authorization scenarios...\n";
        
        // Test unauthorized action
        std::cout << "   Testing ANNOUNCE action (should be denied):\n";
        bool announce_auth = false;
        if (parsed_claims.extended.hasMoqtClaims()) {
            const auto* moqt_claims_ptr = parsed_claims.extended.getMoqtClaimsReadOnly();
            announce_auth = moqt_claims_ptr->isAuthorized(
                moqt_actions::ANNOUNCE, namespace_name, track_name
            );
        }
        std::cout << "     Expected: DENIED (ANNOUNCE not in allowed actions)\n";
        std::cout << "     Obtained: " << (announce_auth ? "GRANTED" : "DENIED") << "\n";
        std::cout << "     Action: " << moqt_actions::action_name(moqt_actions::ANNOUNCE) << "\n";
        std::cout << "     Namespace: " << namespace_name << "\n";
        std::cout << "     Track: " << track_name << "\n";
        
        // Test authorized read action
        std::cout << "\n   Testing SUBSCRIBE to public track (should be granted):\n";
        bool subscribe_auth = false;
        const std::string test_namespace = "live-stream";
        const std::string test_public_track = "public-data";
        if (parsed_claims.extended.hasMoqtClaims()) {
            const auto* moqt_claims_ptr = parsed_claims.extended.getMoqtClaimsReadOnly();
            subscribe_auth = moqt_claims_ptr->isAuthorized(
                moqt_actions::SUBSCRIBE, test_namespace, test_public_track
            );
        }
        std::cout << "     Expected: GRANTED (SUBSCRIBE allowed for tracks with 'public-' prefix)\n";
        std::cout << "     Obtained: " << (subscribe_auth ? "GRANTED" : "DENIED") << "\n";
        std::cout << "     Action: " << moqt_actions::action_name(moqt_actions::SUBSCRIBE) << "\n";
        std::cout << "     Namespace: " << test_namespace << "\n";
        std::cout << "     Track: " << test_public_track << " (matches prefix 'public-')\n";
        
        // Test unauthorized read action (private track)
        std::cout << "\n   Testing SUBSCRIBE to private track (should be denied):\n";
        bool private_auth = false;
        const std::string test_private_namespace = "live-stream";
        const std::string test_private_track = "private-data";
        if (parsed_claims.extended.hasMoqtClaims()) {
            const auto* moqt_claims_ptr = parsed_claims.extended.getMoqtClaimsReadOnly();
            private_auth = moqt_claims_ptr->isAuthorized(
                moqt_actions::SUBSCRIBE, test_private_namespace, test_private_track
            );
        }
        std::cout << "     Expected: DENIED (track doesn't match 'public-' prefix requirement)\n";
        std::cout << "     Obtained: " << (private_auth ? "GRANTED" : "DENIED") << "\n";
        std::cout << "     Action: " << moqt_actions::action_name(moqt_actions::SUBSCRIBE) << "\n";
        std::cout << "     Namespace: " << test_private_namespace << "\n";
        std::cout << "     Track: " << test_private_track << " (does NOT match prefix 'public-')\n\n";

        // Step 7: Demonstrate revalidation
        std::cout << "7. Token revalidation example...\n";
        if (parsed_claims.extended.hasMoqtClaims()) {
            const auto* moqt_claims_ptr = parsed_claims.extended.getMoqtClaimsReadOnly();
            auto revalidation_interval = moqt_claims_ptr->getRevalidationInterval();
            if (revalidation_interval.has_value()) {
                std::cout << "   Expected revalidation interval: 1800 seconds (30 minutes)\n";
                std::cout << "   Obtained revalidation interval: " 
                          << revalidation_interval->count() << " seconds\n";
                if (parsed_claims.core.exp.has_value()) {
                    auto refresh_time = parsed_claims.core.exp.value() + revalidation_interval->count();
                    std::cout << "   Token expiry: " << parsed_claims.core.exp.value() << "\n";
                    std::cout << "   Client should refresh token before: " << refresh_time << "\n";
                }
            }
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}