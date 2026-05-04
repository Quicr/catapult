/**
 * @file client_token_usage.cpp
 * @brief Client-side: Using CAT tokens with DPoP proofs for MOQT operations
 */

#include <chrono>
#include <iostream>

#include "catapult/catapult_minimal.hpp"  // Core CAT/CWT functionality
#include "catapult/dpop.hpp"              // DPoP proof support

using namespace catapult;

int main() {
  std::cout << "=== MOQT Client: Token Usage ===\n\n";

  // Client's DPoP key pair (persisted across sessions)
  auto client_algo = std::make_unique<Es256Algorithm>();
  DpopKeyPair client_keys(std::move(client_algo));
  std::cout << "Client thumbprint: " << client_keys.get_public_key_thumbprint()
            << "\n\n";

  // Token received from auth server (simulated)
  std::string received_token =
      "eyJhbGciOi...";  // In practice, received from auth flow
  std::cout << "Received token from auth server\n\n";

  // Operation: PUBLISH to "my-stream" namespace, "video" track
  const std::string relay = "relay.moqt-cdn.example.com:4433";
  const std::string ns = "my-stream";
  const std::string track = "video";
  const int action = moqt_actions::PUBLISH;

  std::cout << "Preparing PUBLISH request:\n";
  std::cout << "  Relay: " << relay << "\n";
  std::cout << "  Namespace: " << ns << "\n";
  std::cout << "  Track: " << track << "\n\n";

  // Generate DPoP proof for this specific request
  auto jti = moqt_dpop::generate_jti();
  auto proof = client_keys.generate_proof(action, ns, track, relay, jti);

  // Serialize proof for transmission
  std::string dpop_header = proof.serialize();
  std::cout << "DPoP proof generated (" << dpop_header.size() << " bytes)\n";
  std::cout << "  JTI: " << jti << "\n";
  std::cout << "  URI: " << moqt_dpop::construct_moqt_uri(relay, ns, track)
            << "\n\n";

  // Headers to send with MOQT request
  std::cout << "Request headers:\n";
  std::cout << "  Authorization: DPoP " << received_token.substr(0, 20)
            << "...\n";
  std::cout << "  DPoP: " << dpop_header.substr(0, 50) << "...\n";

  return 0;
}
