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

// Once the CWT signature check passes AND CatTokenValidator has run every
// semantic check, the relay should carry the token as an immutable
// ValidatedCatToken rather than a mutable CatToken. This stops downstream
// authorization code from silently mutating a field the validator already
// examined.
struct AuthorizationResult {
  bool authorized = false;
  std::string reason;
  std::optional<ValidatedCatToken> token;
};

/**
 * @brief Validate CWT bytes received from the network
 *
 * In a typical MOQT flow, the relay receives the CAT token as CWT bytes
 * over the network. This function validates the cryptographic signature,
 * deserializes the token, and runs the semantic validator, returning an
 * immutable ValidatedCatToken on success.
 *
 * @param cwt_bytes Raw CWT bytes from the network
 * @param verifier Algorithm with issuer's public key for signature verification
 * @param validator Configured CatTokenValidator (expected issuers, audiences,
 *                  clock-skew tolerance)
 * @return AuthorizationResult with an immutable ValidatedCatToken on success
 */
AuthorizationResult validate_cwt_from_network(
    std::span<const uint8_t> cwt_bytes,
    const CryptographicAlgorithm& verifier,
    const CatTokenValidator& validator) {
  AuthorizationResult result;

  try {
    // Validate signature and deserialize directly from raw CBOR bytes
    Cwt cwt = Cwt::validateCwt(cwt_bytes, verifier);
    // Consume the parsed CatToken into a ValidatedCatToken; on failure
    // intoValidated throws and no ValidatedCatToken is produced.
    result.token.emplace(validator.intoValidated(std::move(cwt.payload)));
    result.authorized = true;
    result.reason = "CWT signature valid";
  } catch (const SignatureVerificationError& e) {
    result.reason = std::string("CWT signature invalid: ") + e.what();
  } catch (const InvalidTokenFormatError& e) {
    result.reason = std::string("Invalid CWT format: ") + e.what();
  } catch (const CryptoError& e) {
    result.reason = std::string("CWT validation failed: ") + e.what();
  } catch (const CatError& e) {
    result.reason = std::string("Token validation failed: ") + e.what();
  } catch (const std::exception& e) {
    result.reason = std::string("Unexpected error: ") + e.what();
  }

  return result;
}

/**
 * @brief Validate MOQT authorization after CWT validation
 */
bool authorize_moqt(const ValidatedCatToken& token,
                    const std::vector<uint8_t>& dpop_proof_bytes,
                    int requested_action,
                    const std::string& requested_namespace,
                    const std::string& requested_track,
                    const std::string& relay_endpoint,
                    const CryptographicAlgorithm& client_public_verifier,
                    std::string& reason) {
  // Step 1: exp/nbf/moqt-reval have already been checked by
  // CatTokenValidator::intoValidated. Audience match is issuer/relay-policy
  // specific, so re-check it here against the relay's own identifier.
  if (token.core().aud.has_value()) {
    bool aud_match = false;
    for (const auto& aud : *token.core().aud) {
      if (aud.find("relay") != std::string::npos) {
        aud_match = true;
        break;
      }
    }
    if (!aud_match) {
      reason = "Token not intended for this relay";
      return false;
    }
  }

  // Step 2: Check MOQT authorization
  if (!token.extended().hasMoqtClaims()) {
    reason = "No MOQT claims in token";
    return false;
  }

  const auto* moqt = token.extended().getMoqtClaimsReadOnly();
  if (!moqt->isAuthorized(requested_action, requested_namespace,
                          requested_track)) {
    reason = "MOQT action not authorized";
    return false;
  }

  // Step 3: Validate DPoP proof (also received as bytes from network).
  //
  // CAT-4-MOQT DPoP binds the token to the client key via `cnf.jkt`
  // — the SHA-256 thumbprint of the client's public key. On the wire
  // this is a raw byte string (RFC 8747 §3.1); DpopProofValidator
  // compares against the base64url-encoded form, so re-encode here.
  //
  // Some issuer profiles also emit `cnf.kid` — the previous form of
  // this example fell back to `cnf.kid` without a `jkt` present, which
  // conflates key identity with a key-material-derived binding.
  // Prefer `cnf.jkt` explicitly.
  if (!token.dpop().cnf.has_value() ||
      !token.dpop().cnf->jkt.has_value()) {
    reason = "Token missing DPoP `cnf.jkt` binding";
    return false;
  }
  std::string expected_thumbprint =
      base64UrlEncode(token.dpop().cnf->jkt.value());

  // Convert DPoP proof bytes to string for deserialization.
  std::string dpop_proof_str(dpop_proof_bytes.begin(), dpop_proof_bytes.end());
  DpopProof proof = DpopProof::deserialize(dpop_proof_str);

  DpopValidationSettings dpop_settings;
  dpop_settings.set_window(std::chrono::seconds{300});
  DpopProofValidator validator(dpop_settings);

  // CWT-encoded proofs carry a COSE_Key but no signing algorithm
  // instance; the relay must supply a verifier built from the client
  // public key that CWT_Sign1 will verify against. Without this,
  // `DpopProofValidator::validate_proof` correctly fails closed — that
  // is the audit's L-03 objection: the previous example never
  // configured `set_cwt_verifier`, so a CWT proof would always be
  // rejected regardless of validity. JWT proofs self-resolve their
  // algorithm from the embedded JWK, so they do not need this hook.
  if (proof.encoding() == DpopEncoding::CWT) {
    validator.set_cwt_verifier(&client_public_verifier);
  }

  auto expected_uri = moqt_dpop::construct_moqt_uri(
      relay_endpoint, requested_namespace, requested_track);

  if (!validator.validate_proof(proof, requested_action, expected_uri,
                                expected_thumbprint)) {
    reason = "DPoP proof validation failed";
    return false;
  }

  reason = "All validations passed";
  return true;
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

  // Auth server creates the token. Bind the client's public key via
  // `cnf.jkt` — the SHA-256 thumbprint of the key — per CTA-5007-B
  // §4.6.9, RFC 8747 §3.1, and CAT-4-MOQT DPoP §3. `cnf.kid` names a
  // key by identity but does not commit to its material; `cnf.jkt` is
  // the proof-of-possession binding the relay actually needs.
  //
  // On the wire `cnf.jkt` is a raw byte string (32 bytes for SHA-256);
  // catapult's DpopKeyPair exposes the same value pre-encoded as
  // base64url in `get_public_key_thumbprint()`. The relay-side check
  // below re-decodes the token's `jkt` bytes to reconstruct that
  // string before comparing.
  auto token = CatToken::builder()
                   .issuer("auth.moqt-cdn.example.com")
                   .audience("relay.moqt-cdn.example.com")
                   .expiresIn(std::chrono::hours{1})
                   .build();
  {
    CatConfirmation cnf;
    // Decode base64url form back to raw bytes to populate the wire field.
    cnf.jkt = base64UrlDecode(client_keys.get_public_key_thumbprint());
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

  // Configure the semantic validator. The example uses the issuer and
  // audience the auth server just embedded.
  CatTokenValidator cat_validator;
  cat_validator
      .withExpectedIssuers({"auth.moqt-cdn.example.com"})
      .withExpectedAudiences({"relay.moqt-cdn.example.com"});

  // Validate CWT signature and deserialize
  std::cout << "Step 3: Validate CWT signature and semantics\n";
  auto cwt_result =
      validate_cwt_from_network(cwt_bytes, issuer_verifier, cat_validator);
  if (!cwt_result.authorized || !cwt_result.token.has_value()) {
    std::cout << "  FAILED: " << cwt_result.reason << "\n";
    return 1;
  }
  std::cout << "  " << cwt_result.reason << "\n";
  std::cout << "  Token issuer: "
            << cwt_result.token->core().iss.value_or("unknown") << "\n\n";

  // ========================================
  // TEST SCENARIOS
  // ========================================

  // Client generates a DPoP proof for the PUBLISH request. The
  // encoding follows the pinned CAT-4-MOQT DPoP profile — CWT here.
  // The relay must therefore supply a verifier built from the client
  // public key, because CWT proofs do not embed the algorithm the way
  // JWTs (via JWK) do.
  const auto& client_public_verifier = client_keys.get_algorithm();
  auto jti = moqt_dpop::generate_jti();
  auto proof = client_keys.generate_proof(moqt_actions::PUBLISH, "live",
                                          "video", relay_endpoint, jti);
  std::string proof_str = proof.serialize();
  std::vector<uint8_t> proof_bytes(proof_str.begin(), proof_str.end());

  const ValidatedCatToken& validated = *cwt_result.token;

  // Test 1: Valid request
  std::cout << "Test 1: Valid PUBLISH to live/video\n";
  std::string reason1;
  bool ok1 = authorize_moqt(validated, proof_bytes, moqt_actions::PUBLISH,
                            "live", "video", relay_endpoint,
                            client_public_verifier, reason1);
  std::cout << "  Result: " << (ok1 ? "AUTHORIZED" : "DENIED") << " - "
            << reason1 << "\n\n";

  // Test 2: Unauthorized action
  std::cout << "Test 2: SUBSCRIBE (not permitted)\n";
  auto proof2 =
      client_keys.generate_proof(moqt_actions::SUBSCRIBE, "live", "video",
                                 relay_endpoint, moqt_dpop::generate_jti());
  std::string proof2_str = proof2.serialize();
  std::vector<uint8_t> proof2_bytes(proof2_str.begin(), proof2_str.end());
  std::string reason2;
  bool ok2 = authorize_moqt(validated, proof2_bytes, moqt_actions::SUBSCRIBE,
                            "live", "video", relay_endpoint,
                            client_public_verifier, reason2);
  std::cout << "  Result: " << (ok2 ? "AUTHORIZED" : "DENIED") << " - "
            << reason2 << "\n\n";

  // Test 3: Wrong namespace
  std::cout << "Test 3: PUBLISH to wrong namespace\n";
  auto proof3 =
      client_keys.generate_proof(moqt_actions::PUBLISH, "other", "video",
                                 relay_endpoint, moqt_dpop::generate_jti());
  std::string proof3_str = proof3.serialize();
  std::vector<uint8_t> proof3_bytes(proof3_str.begin(), proof3_str.end());
  std::string reason3;
  bool ok3 = authorize_moqt(validated, proof3_bytes, moqt_actions::PUBLISH,
                            "other", "video", relay_endpoint,
                            client_public_verifier, reason3);
  std::cout << "  Result: " << (ok3 ? "AUTHORIZED" : "DENIED") << " - "
            << reason3 << "\n\n";

  // Test 4: Invalid CWT signature
  std::cout << "Test 4: Invalid CWT signature (tampered bytes)\n";
  std::vector<uint8_t> tampered_bytes = cwt_bytes;
  if (!tampered_bytes.empty()) {
    tampered_bytes.back() ^= 0xFF;  // Flip bits in last byte
  }
  auto result4 =
      validate_cwt_from_network(tampered_bytes, issuer_verifier, cat_validator);
  std::cout << "  Result: " << (result4.authorized ? "AUTHORIZED" : "DENIED")
            << " - " << result4.reason << "\n";

  return 0;
}
