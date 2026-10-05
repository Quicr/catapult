/**
 * @file moqt_dpop_ps256_example.cpp
 * @brief End-to-end PS256 DPoP JWT example for MOQT.
 *
 * This mirrors examples/moqt_dpop_example.cpp but exercises the PS256
 * (RSASSA-PSS SHA-256) algorithm end-to-end: the client builds a JWT
 * DPoP proof using an RSA key pair, the relay verifies the signature
 * via the embedded JWK, and the full DpopProofValidator pipeline
 * (algorithm allowlist, signature, action/URI, JWK thumbprint, replay)
 * runs against the proof. Both the happy path and a tampered-signature
 * negative case are demonstrated so the exit status reflects the
 * expected outcome of each stage.
 *
 * PS256 is not in the default DPoP algorithm allowlist (which is
 * `{ALG_ES256}` for conservative deployments). This example widens the
 * allowlist explicitly to `{ALG_ES256, ALG_PS256}` to show how an
 * operator opts in.
 */

#include <chrono>
#include <cstdlib>
#include <iostream>

#include "catapult/base64.hpp"
#include "catapult/crypto.hpp"
#include "catapult/dpop.hpp"
#include "catapult/jwk.hpp"
#include "catapult/moqt_claims.hpp"

using namespace catapult;

int main() {
  std::cout << "=== MOQT + DPoP JWT with PS256 end-to-end example ===\n\n";

  bool all_ok = true;
  try {
    // 1) Client side: generate a PS256 DPoP key pair.
    std::cout << "[1] Client: generating PS256 DPoP key pair...\n";
    auto client_alg = std::make_unique<Ps256Algorithm>();
    DpopKeyPair client(std::move(client_alg));
    std::cout << "    alg = " << client.get_algorithm_name()
              << ", alg_id = " << client.get_algorithm_id() << "\n";
    std::cout << "    JWK = " << client.get_public_key_jwk().substr(0, 72)
              << "...\n\n";

    // 2) Client generates a JWT DPoP proof for a MOQT PUBLISH action.
    const std::string endpoint = "relay.example.com:4433";
    const std::string ns = "live-stream";
    const std::string track = "video-feed-1";
    const int action = moqt_actions::PUBLISH;
    const std::string jti = moqt_dpop::generate_jti();

    std::cout << "[2] Client: generating JWT DPoP proof for " << ns << "/"
              << track << " (" << moqt_actions::action_name(action) << ")\n";
    auto proof = client.generate_proof(action, ns, track, endpoint, jti,
                                       DpopEncoding::JWT);
    const std::string wire = proof.serialize();
    std::cout << "    DPoP wire proof: " << wire.substr(0, 60) << "...\n";
    std::cout << "    jti = " << jti << "\n\n";

    // 3) Relay side: configure validator with PS256 added to the allowlist.
    DpopValidationSettings settings;
    settings.set_window(std::chrono::seconds{300});
    settings.set_jti_processing(true);
    settings.set_allowed_dpop_algorithms({ALG_ES256, ALG_PS256});
    DpopProofValidator validator(settings);

    const auto expected_uri =
        moqt_dpop::construct_moqt_uri(endpoint, ns, track);
    // JWT DPoP proofs bind to the RFC 7638 JWK thumbprint. DpopKeyPair
    // exposes the COSE_Key thumbprint via get_public_key_thumbprint();
    // compute the JWK thumbprint explicitly for the JWT case.
    const std::string jwk_thumb =
        jwk::calculateJWKThumbprint(client.get_public_key_jwk());

    // 4) Happy path.
    auto parsed = DpopProof::deserialize(wire);
    const bool happy =
        validator.validate_proof(parsed, action, expected_uri, jwk_thumb);
    std::cout << "[3] Relay (correct proof): "
              << (happy ? "PASS (admitted)" : "FAIL (unexpectedly rejected)")
              << "\n";
    all_ok = all_ok && happy;

    // 5) Negative path: flip a byte in the signature segment of the JWT.
    std::string tampered = wire;
    auto last_dot = tampered.rfind('.');
    if (last_dot != std::string::npos && last_dot + 1 < tampered.size()) {
      tampered[last_dot + 1] = (tampered[last_dot + 1] == 'A') ? 'B' : 'A';
    }
    bool tampered_rejected = false;
    try {
      auto parsed_tampered = DpopProof::deserialize(tampered);
      tampered_rejected = !validator.validate_proof(
          parsed_tampered, action, expected_uri, jwk_thumb);
    } catch (const std::exception&) {
      tampered_rejected = true;  // parse-time refusal is also correct
    }
    std::cout << "[4] Relay (tampered signature): "
              << (tampered_rejected
                      ? "PASS (rejected)"
                      : "FAIL (unexpectedly admitted)")
              << "\n";
    all_ok = all_ok && tampered_rejected;

    // 6) Negative path: the default allowlist (ES256 only) must refuse.
    DpopValidationSettings strict;
    strict.set_window(std::chrono::seconds{300});
    DpopProofValidator strict_validator(strict);  // default alg allowlist
    const bool strict_refused =
        !strict_validator.validate_proof(parsed, action, expected_uri,
                                         jwk_thumb);
    std::cout << "[5] Relay (default allowlist, PS256 not opted in): "
              << (strict_refused ? "PASS (refused as expected)"
                                 : "FAIL (unexpectedly admitted)")
              << "\n";
    all_ok = all_ok && strict_refused;
  } catch (const std::exception& e) {
    std::cerr << "fatal: " << e.what() << "\n";
    return EXIT_FAILURE;
  }

  std::cout << "\n=== " << (all_ok ? "ALL CHECKS PASSED" : "SOME CHECKS FAILED")
            << " ===\n";
  return all_ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
