/**
 * @file relay_token_validation.cpp
 * @brief Relay-side: Validating CAT tokens and DPoP proofs for MOQT
 * authorization
 *
 * This example demonstrates the typical relay flow:
 * 1. Token bytes are received from the network (as CWT)
 * 2. Bytes are validated and deserialized into a CatToken
 * 3. MOQT authorization checks are performed
 * 4. DPoP proof is validated
 */

#include <chrono>
#include <iostream>
#include <span>
#include <vector>

#include "catapult/catapult.hpp"

using namespace catapult;

struct AuthorizationResult {
  bool authorized = false;
  std::string reason;
  std::optional<CatToken> token;
};

/**
 * @brief Validate CWT bytes received from the network
 *
 * In a typical MOQT flow, the relay receives the CAT token as CWT bytes
 * over the network. This function validates the cryptographic signature
 * and deserializes the token.
 *
 * @param cwt_bytes Raw CWT bytes from the network
 * @param verifier Algorithm with issuer's public key for signature verification
 * @return AuthorizationResult with deserialized token on success
 */
AuthorizationResult validate_cwt_from_network(
    std::span<const uint8_t> cwt_bytes,
    const CryptographicAlgorithm& verifier) {
  AuthorizationResult result;

  try {
    // Validate signature and deserialize directly from raw CBOR bytes
    Cwt cwt = Cwt::validateCwt(cwt_bytes, verifier);
    result.token = std::move(cwt.payload);
    result.authorized = true;
    result.reason = "CWT signature valid";
  } catch (const SignatureVerificationError& e) {
    result.reason = std::string("CWT signature invalid: ") + e.what();
  } catch (const InvalidTokenFormatError& e) {
    result.reason = std::string("Invalid CWT format: ") + e.what();
  } catch (const CryptoError& e) {
    result.reason = std::string("CWT validation failed: ") + e.what();
  } catch (const std::exception& e) {
    result.reason = std::string("Unexpected error: ") + e.what();
  }

  return result;
}

/**
 * @brief Validate MOQT authorization after CWT validation
 */
AuthorizationResult validate_moqt_authorization(
    const CatToken& token, const std::vector<uint8_t>& dpop_proof_bytes,
    int requested_action, const std::string& requested_namespace,
    const std::string& requested_track, const std::string& relay_endpoint) {
  AuthorizationResult result;

  // Step 1: Check token expiration
  if (token.core.exp.has_value()) {
    auto now =
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
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
  if (!moqt->isAuthorized(requested_action, requested_namespace,
                          requested_track)) {
    result.reason = "MOQT action not authorized";
    return result;
  }

  // Step 4: Validate DPoP proof (also received as bytes from network).
  // CTA-5007-B §4.6.9 binds the token to the client key via `cnf`; the hex
  // thumbprint is carried in the `kid` field.
  if (!token.dpop.cnf.has_value() || !token.dpop.cnf->kid.has_value()) {
    result.reason = "Token missing DPoP confirmation";
    return result;
  }

  // Convert DPoP proof bytes to string for deserialization
  std::string dpop_proof_str(dpop_proof_bytes.begin(), dpop_proof_bytes.end());
  DpopProof proof = DpopProof::deserialize(dpop_proof_str);

  DpopValidationSettings dpop_settings;
  dpop_settings.set_window(std::chrono::seconds{300});
  DpopProofValidator validator(dpop_settings);

  auto expected_uri = moqt_dpop::construct_moqt_uri(
      relay_endpoint, requested_namespace, requested_track);

  if (!validator.validate_proof(proof, requested_action, expected_uri,
                                token.dpop.cnf->kid.value())) {
    result.reason = "DPoP proof validation failed";
    return result;
  }

  result.authorized = true;
  result.reason = "All validations passed";
  return result;
}

int main() {
  std::cout << "=== MOQT Relay: Token Validation from Network Bytes ===\n\n";

  // Relay configuration
  const std::string relay_endpoint = "relay.moqt-cdn.example.com:4433";

  // ========================================
  // SETUP: Simulate what the auth server does
  // ========================================

  // Issuer's key pair (auth server has private key, relay has public key)
  auto [issuer_private, issuer_public] =
      Es256Algorithm::generateSecureKeyPair();
  Es256Algorithm issuer_signer(issuer_private, issuer_public);
  Es256Algorithm issuer_verifier(issuer_public);  // Relay only has public key

  // Client's DPoP key pair
  auto client_algo = std::make_unique<Es256Algorithm>();
  DpopKeyPair client_keys(std::move(client_algo));

  // Auth server creates the token. Bind the client's thumbprint (hex string)
  // via `cnf.kid` per CTA-5007-B §4.6.9 / RFC 8747 §3.4.
  auto token = CatToken::builder()
                   .issuer("auth.moqt-cdn.example.com")
                   .audience("relay.moqt-cdn.example.com")
                   .expiresIn(std::chrono::hours{1})
                   .build();
  {
    CatConfirmation cnf;
    cnf.kid = client_keys.get_public_key_thumbprint();
    token.dpop.cnf = std::move(cnf);
  }

  MoqtClaims moqt;
  std::vector<int> publish_actions = {moqt_actions::PUBLISH};
  moqt.addScope(publish_actions, MoqtBinaryMatch::exact("live"),
                MoqtBinaryMatch::any());
  token.extended.setMoqtClaims(std::move(moqt));

  // ========================================
  // SERIALIZE: Auth server creates CWT bytes
  // ========================================

  std::cout << "Step 1: Auth server serializes token to CWT\n";
  Cwt cwt(ALG_ES256, token);
  std::vector<uint8_t> cwt_bytes =
      cwt.createCwt(CwtMode::Signed, issuer_signer);
  std::cout << "  CWT size: " << cwt_bytes.size() << " bytes\n\n";

  // ========================================
  // RELAY: Receives bytes from network
  // ========================================

  std::cout << "Step 2: Relay receives CWT bytes from network\n";
  std::cout << "  (simulating network receive of " << cwt_bytes.size()
            << " bytes)\n\n";

  // Validate CWT signature and deserialize
  std::cout << "Step 3: Validate CWT signature\n";
  auto cwt_result = validate_cwt_from_network(cwt_bytes, issuer_verifier);
  if (!cwt_result.authorized || !cwt_result.token.has_value()) {
    std::cout << "  FAILED: " << cwt_result.reason << "\n";
    return 1;
  }
  std::cout << "  " << cwt_result.reason << "\n";
  std::cout << "  Token issuer: "
            << cwt_result.token->core.iss.value_or("unknown") << "\n\n";

  // ========================================
  // TEST SCENARIOS
  // ========================================

  // Client generates DPoP proof for PUBLISH request
  auto jti = moqt_dpop::generate_jti();
  auto proof = client_keys.generate_proof(moqt_actions::PUBLISH, "live",
                                          "video", relay_endpoint, jti);
  std::string proof_str = proof.serialize();
  std::vector<uint8_t> proof_bytes(proof_str.begin(), proof_str.end());

  // Test 1: Valid request
  std::cout << "Test 1: Valid PUBLISH to live/video\n";
  auto result1 = validate_moqt_authorization(*cwt_result.token, proof_bytes,
                                             moqt_actions::PUBLISH, "live",
                                             "video", relay_endpoint);
  std::cout << "  Result: " << (result1.authorized ? "AUTHORIZED" : "DENIED")
            << " - " << result1.reason << "\n\n";

  // Test 2: Unauthorized action
  std::cout << "Test 2: SUBSCRIBE (not permitted)\n";
  auto proof2 =
      client_keys.generate_proof(moqt_actions::SUBSCRIBE, "live", "video",
                                 relay_endpoint, moqt_dpop::generate_jti());
  std::string proof2_str = proof2.serialize();
  std::vector<uint8_t> proof2_bytes(proof2_str.begin(), proof2_str.end());
  auto result2 = validate_moqt_authorization(*cwt_result.token, proof2_bytes,
                                             moqt_actions::SUBSCRIBE, "live",
                                             "video", relay_endpoint);
  std::cout << "  Result: " << (result2.authorized ? "AUTHORIZED" : "DENIED")
            << " - " << result2.reason << "\n\n";

  // Test 3: Wrong namespace
  std::cout << "Test 3: PUBLISH to wrong namespace\n";
  auto proof3 =
      client_keys.generate_proof(moqt_actions::PUBLISH, "other", "video",
                                 relay_endpoint, moqt_dpop::generate_jti());
  std::string proof3_str = proof3.serialize();
  std::vector<uint8_t> proof3_bytes(proof3_str.begin(), proof3_str.end());
  auto result3 = validate_moqt_authorization(*cwt_result.token, proof3_bytes,
                                             moqt_actions::PUBLISH, "other",
                                             "video", relay_endpoint);
  std::cout << "  Result: " << (result3.authorized ? "AUTHORIZED" : "DENIED")
            << " - " << result3.reason << "\n\n";

  // Test 4: Invalid CWT signature
  std::cout << "Test 4: Invalid CWT signature (tampered bytes)\n";
  std::vector<uint8_t> tampered_bytes = cwt_bytes;
  if (!tampered_bytes.empty()) {
    tampered_bytes.back() ^= 0xFF;  // Flip bits in last byte
  }
  auto result4 = validate_cwt_from_network(tampered_bytes, issuer_verifier);
  std::cout << "  Result: " << (result4.authorized ? "AUTHORIZED" : "DENIED")
            << " - " << result4.reason << "\n";

  return 0;
}
