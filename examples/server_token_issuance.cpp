/**
 * @file server_token_issuance.cpp
 * @brief Server-side: Auth server creating CAT tokens for MOQT clients
 */

#include <chrono>
#include <iostream>
#include <vector>

#include "catapult/catapult.hpp"

using namespace catapult;

int main() {
  std::cout << "=== Auth Server: Token Issuance ===\n\n";

  // Server's signing key (in production, load from secure storage)
  auto [server_private_key, server_public_key] =
      Es256Algorithm::generateSecureKeyPair();
  Es256Algorithm signer(server_private_key, server_public_key);

  // Client's public key thumbprint (received during authentication)
  auto client_keypair = std::make_unique<Es256Algorithm>();
  DpopKeyPair client_dpop(std::move(client_keypair));
  std::string client_thumbprint = client_dpop.get_public_key_thumbprint();
  std::cout << "Client key thumbprint: " << client_thumbprint << "\n\n";

  // Build token for authenticated client. The thumbprint is a hex string; bind
  // it via `kid` on the confirmation (CTA-5007-B §4.6.9 / RFC 8747 §3.4).
  auto token = CatToken::builder()
                   .issuer("auth.moqt-cdn.example.com")
                   .audience("relay.moqt-cdn.example.com")
                   .subject("user-12345")
                   .expiresIn(std::chrono::hours{1})
                   .build();
  {
    CatConfirmation cnf;
    cnf.kid = client_thumbprint;
    token.dpop.cnf = std::move(cnf);
  }

  // Add MOQT-specific permissions
  MoqtClaims moqt;
  std::vector<int> publish_actions = {moqt_actions::PUBLISH,
                                      moqt_actions::ANNOUNCE};
  moqt.addScope(publish_actions, MoqtBinaryMatch::exact("user-12345-stream"),
                MoqtBinaryMatch::any());
  std::vector<int> read_actions = {moqt_actions::SUBSCRIBE,
                                   moqt_actions::FETCH};
  moqt.addScope(read_actions, MoqtBinaryMatch::any(),
                MoqtBinaryMatch::prefix("public-"));
  moqt.setRevalidationInterval(std::chrono::minutes{30});
  token.extended.setMoqtClaims(std::move(moqt));

  // Create signed CWT
  Cwt cwt(ALG_ES256, token);
  cwt.withKeyId("auth-server-key-2024");
  std::string signed_token = cwt.createCwtBase64(CwtMode::Signed, signer);

  std::cout << "Issued token:\n" << signed_token << "\n\n";
  std::cout << "Token length: " << signed_token.size() << " bytes\n";
  std::cout << "Permissions granted:\n";
  std::cout << "  - PUBLISH/ANNOUNCE to namespace 'user-12345-stream'\n";
  std::cout
      << "  - SUBSCRIBE/FETCH from any namespace, tracks prefixed 'public-'\n";

  return 0;
}
