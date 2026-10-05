/**
 * @file cat_cwt_ps256_example.cpp
 * @brief End-to-end PS256 (RSASSA-PSS SHA-256) example for a CAT token
 *        carried as a signed CWT, with no DPoP in the loop.
 *
 * The flow this demonstrates is the "plain CAT" case: an issuer signs a
 * CWT with a PS256 private key, a verifier (relay / resource server)
 * reconstructs the CWT, validates the Sig_structure signature using
 * the issuer's PS256 public key, and inspects the claims. Both pass
 * (correct key + untouched token) and fail (wrong key + tampered token)
 * paths are exercised so the exit status reflects whether the full flow
 * behaved as expected.
 */

#include <chrono>
#include <cstdlib>
#include <iostream>

#include "catapult/base64.hpp"
#include "catapult/crypto.hpp"
#include "catapult/cwt.hpp"
#include "catapult/token.hpp"

using namespace catapult;

namespace {

CatToken makeToken() {
  CatToken token;
  token.core.iss = "https://issuer.example.com";
  token.core.aud = std::vector<std::string>{"https://relay.example.com"};
  token.core.exp = std::chrono::system_clock::to_time_t(
      std::chrono::system_clock::now() + std::chrono::hours{1});
  token.core.setCwtIdFromString("ps256-demo-cti");
  token.cat.catv = 1u;
  return token;
}

}  // namespace

int main() {
  std::cout << "=== CAT + PS256 (non-DPoP) end-to-end example ===\n\n";

  bool all_ok = true;
  try {
    // 1) Issuer side: generate a PS256 key pair and sign the CWT.
    std::cout << "[1] Issuer: generating PS256 key pair (2048-bit RSA)...\n";
    auto kp = Ps256Algorithm::generateSecureKeyPair();
    Ps256Algorithm signer(kp.first, kp.second);
    std::cout << "    algorithm id = " << signer.algorithmId()
              << " (ALG_PS256 is " << ALG_PS256 << ")\n";
    std::cout << "    DER public key is " << kp.second.size()
              << " bytes (SubjectPublicKeyInfo)\n\n";

    auto token = makeToken();
    Cwt cwt(ALG_PS256, token);
    cwt.withKeyId("ps256-demo-key");
    const std::string signed_cwt =
        cwt.createCwtBase64(CwtMode::Signed, signer);
    std::cout << "[2] Issuer: signed CWT emitted (" << signed_cwt.size()
              << " base64url chars)\n\n";

    // 2) Happy path: verifier owns the matching public key.
    Ps256Algorithm verifier(kp.second);
    try {
      Cwt validated = Cwt::validateCwtBase64(signed_cwt, verifier);
      bool ok = (validated.payload.core.iss == token.core.iss) &&
                (validated.payload.core.aud == token.core.aud) &&
                (validated.header.alg == ALG_PS256);
      std::cout << "[3] Verifier (correct key): "
                << (ok ? "PASS" : "FAIL — payload mismatch") << "\n";
      all_ok = all_ok && ok;
    } catch (const std::exception& e) {
      std::cout << "[3] Verifier (correct key): FAIL — " << e.what() << "\n";
      all_ok = false;
    }

    // 3) Negative path #1: wrong key must reject.
    auto wrong_kp = Ps256Algorithm::generateSecureKeyPair();
    Ps256Algorithm wrong(wrong_kp.second);
    try {
      Cwt::validateCwtBase64(signed_cwt, wrong);
      std::cout << "[4] Verifier (wrong key): FAIL — unexpectedly accepted\n";
      all_ok = false;
    } catch (const CryptoError&) {
      std::cout << "[4] Verifier (wrong key): PASS (rejected as expected)\n";
    }

    // 4) Negative path #2: a byte flip in the base64url body must reject.
    std::string tampered = signed_cwt;
    if (!tampered.empty()) {
      size_t pos = std::min<size_t>(10, tampered.size() - 1);
      tampered[pos] = (tampered[pos] == 'A') ? 'B' : 'A';
    }
    try {
      Cwt::validateCwtBase64(tampered, verifier);
      std::cout << "[5] Verifier (tampered CWT): FAIL — unexpectedly accepted\n";
      all_ok = false;
    } catch (const std::exception&) {
      std::cout << "[5] Verifier (tampered CWT): PASS (rejected as expected)\n";
    }

    // 5) Negative path #3: ES256-verifier against a PS256-signed CWT.
    auto es_kp = Es256Algorithm::generateSecureKeyPair();
    Es256Algorithm es256(es_kp.second);
    try {
      Cwt::validateCwtBase64(signed_cwt, es256);
      std::cout << "[6] Verifier (ES256 verifier for PS256 token): "
                   "FAIL — unexpectedly accepted\n";
      all_ok = false;
    } catch (const CryptoError&) {
      std::cout << "[6] Verifier (ES256 verifier for PS256 token): "
                   "PASS (alg mismatch rejected)\n";
    }
  } catch (const std::exception& e) {
    std::cerr << "fatal: " << e.what() << "\n";
    return EXIT_FAILURE;
  }

  std::cout << "\n=== " << (all_ok ? "ALL CHECKS PASSED" : "SOME CHECKS FAILED")
            << " ===\n";
  return all_ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
