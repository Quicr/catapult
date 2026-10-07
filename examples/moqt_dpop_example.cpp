/**
 * @file moqt_dpop_example.cpp
 * @brief End-to-end example demonstrating MOQT with DPoP proof-of-possession.
 *
 * Parameterised by signing algorithm and DPoP encoding so one example covers
 * every supported combination:
 *
 *   ./moqt_dpop_example                          # default: ES256 + CWT
 *   ./moqt_dpop_example --alg=PS256              # PS256 + CWT
 *   ./moqt_dpop_example --encoding=jwt           # ES256 + JWT
 *   ./moqt_dpop_example --alg=PS256 --encoding=jwt
 *   ./moqt_dpop_example --all                    # walk every alg x encoding
 *
 * The CAT token + MOQT authorization checks are identical in every
 * configuration — only the DPoP key pair, the proof-encoding call, and the
 * thumbprint used for `cnf` binding change.
 */

#include <cstring>
#include <chrono>
#include <iostream>
#include <string>

#include "catapult/claims.hpp"
#include "catapult/crypto.hpp"
#include "catapult/cwt.hpp"
#include "catapult/dpop.hpp"
#include "catapult/moqt_claims.hpp"
#include "catapult/token.hpp"
#ifdef CATAPULT_ENABLE_JSON
#include "catapult/jwk.hpp"
#endif

using namespace catapult;

namespace {

// Which algorithm to use for the DPoP key pair.
std::unique_ptr<CryptographicAlgorithm> make_algorithm(int64_t alg_id) {
  switch (alg_id) {
    case ALG_ES256:
      return std::make_unique<Es256Algorithm>();
    case ALG_PS256:
      return std::make_unique<Ps256Algorithm>();
    default:
      throw CryptoError("Unsupported alg in example: " +
                        std::to_string(alg_id));
  }
}

const char* alg_name(int64_t alg_id) {
  switch (alg_id) {
    case ALG_ES256:
      return "ES256";
    case ALG_PS256:
      return "PS256";
    default:
      return "Unknown";
  }
}

const char* encoding_name(DpopEncoding e) {
  return e == DpopEncoding::CWT ? "CWT" : "JWT";
}

// JWT proofs bind to the RFC 7638 JWK thumbprint; CWT proofs bind to the
// COSE_Key thumbprint. DpopKeyPair exposes the latter directly, so the
// JWT path needs an explicit calculateJWKThumbprint call.
std::string thumbprint_for(const DpopKeyPair& keys, DpopEncoding encoding) {
  if (encoding == DpopEncoding::CWT) {
    return keys.get_public_key_thumbprint();
  }
#ifdef CATAPULT_ENABLE_JSON
  return jwk::calculateJWKThumbprint(keys.get_public_key_jwk());
#else
  (void)encoding;
  throw CryptoError("JWT DPoP requires CATAPULT_ENABLE_JSON");
#endif
}

}  // namespace

int run_demo(int64_t alg_id, DpopEncoding encoding) {
  std::cout << "MOQT + DPoP End-to-End Example  "
            << "[alg=" << alg_name(alg_id) << ", encoding="
            << encoding_name(encoding) << "]\n";

  try {
    // Step 1: Create a DPoP key pair for the client. The algorithm and
    // encoding selected here steer every subsequent step: signing the
    // proof, choosing the thumbprint form used in `cnf`, and the
    // DpopValidationSettings allowlist.
    std::cout << "1. Creating DPoP key pair (" << alg_name(alg_id)
              << ")...\n";
    auto crypto_alg = make_algorithm(alg_id);
    DpopKeyPair client_keypair(std::move(crypto_alg));
    const std::string key_thumb = thumbprint_for(client_keypair, encoding);
    std::cout << "   Key thumbprint ("
              << (encoding == DpopEncoding::CWT ? "COSE_Key" : "JWK")
              << "): " << key_thumb << "\n\n";

    // Step 2: Create CAT token with MOQT claims and DPoP binding
    std::cout << "2. Creating CAT token with MOQT claims and DPoP binding...\n";

    CoreClaims core_claims;
    core_claims.iss = "moqt-authority.example.com";
    core_claims.aud = std::vector<std::string>{"moqt-relay.example.com"};
    core_claims.exp = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now() + std::chrono::hours{1});

    InformationalClaims info_claims;
    info_claims.sub = "client-123";
    info_claims.iat =
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

    MoqtClaims moqt_claims = MoqtClaims::create(2);

    // Scope 1: Allow PUBLISH action for any track in "live-stream" namespace
    std::vector<int> publish_actions = {moqt_actions::PUBLISH};
    moqt_claims.addScope(publish_actions, MoqtBinaryMatch::exact("live-stream"),
                         MoqtBinaryMatch::any()  // Empty match = any track
    );

    // Scope 2: Allow SUBSCRIBE and FETCH for tracks starting with "public-" in
    // any namespace
    std::vector<int> read_actions = {moqt_actions::SUBSCRIBE,
                                     moqt_actions::FETCH};
    moqt_claims.addScope(read_actions, MoqtBinaryMatch::exact("live-stream"),
                         MoqtBinaryMatch::prefix("public-"));

    // Set revalidation interval
    moqt_claims.setRevalidationInterval(
        std::chrono::seconds{1800});  // 30 minutes

    // Create DPoP settings. For non-ES256 proofs we also widen the
    // algorithm allowlist, which otherwise defaults to {ALG_ES256} and
    // would reject the proof before signature verification runs.
    DpopValidationSettings dpop_settings;
    dpop_settings.set_window(std::chrono::seconds{300});  // 5 minute window
    dpop_settings.set_jti_processing(true);  // Enable JTI validation
    if (alg_id != ALG_ES256) {
      dpop_settings.set_allowed_dpop_algorithms({ALG_ES256, alg_id});
    }

    // Create enhanced DPoP claims
    EnhancedDpopClaims dpop_claims;
    dpop_claims.set_confirmation(key_thumb);
    dpop_claims.set_dpop_settings(dpop_settings);

    // Create CAT token
    CatToken token;
    token.core = std::move(core_claims);
    token.informational = std::move(info_claims);
    token.extended.setMoqtClaims(std::move(moqt_claims));

    // Set DPoP claims — CTA-5007-B §4.6.9 `cnf` conveys the key thumbprint
    // the proof must prove possession of. For a CWT-encoded proof this is
    // the COSE_Key thumbprint; for a JWT-encoded proof it is the JWK
    // thumbprint (RFC 7638). `key_thumb` captured the correct one above.
    {
      CatConfirmation cnf;
      cnf.kid = key_thumb;
      token.dpop.cnf = std::move(cnf);
    }
    // Note: catdpop would contain serialized settings in real implementation
    std::cout << "   CAT token created successfully\n\n";

    // Step 2.5: Encode token to CWT format
    Cwt cwt_token(ALG_ES256, token);            // CAT token itself always ES256-signed in this demo
    cwt_token.withKeyId("sixteen-char-keyid");  // Example key ID

    auto cwt_payload = cwt_token.encodePayload();
    std::cout << "   CWT payload encoded (" << cwt_payload.size()
              << " bytes)\n";

    // Step 2.6: Base64 encode the CWT
    auto base64_encoded = base64UrlEncode(cwt_payload);
    std::cout << "   Base64 encoded CWT (" << base64_encoded.length()
              << " chars):\n";
    std::cout << "   " << base64_encoded << "\n\n";

    // Step 2.7: Base64 decode the CWT
    auto decoded_cwt_bytes = base64UrlDecode(base64_encoded);
    std::cout << "   Base64 decoded (" << decoded_cwt_bytes.size()
              << " bytes)\n";

    // Verify the decoded bytes match the original
    bool decode_match = (decoded_cwt_bytes == cwt_payload);
    std::cout << "   Decode verification: " << (decode_match ? "PASS" : "FAIL")
              << "\n";

    // Step 2.8: CWT decode back to token
    auto decoded_token = Cwt::decodePayload(decoded_cwt_bytes);
    std::cout << "   CWT payload decoded successfully\n";

    // Step 3: Client wants to publish to a track
    std::cout << "3. Client publishing to MOQT track...\n";
    const std::string endpoint = "relay.example.com:4433";
    const std::string namespace_name = "live-stream";
    const std::string track_name = "video-feed-1";
    const int moqt_action = moqt_actions::PUBLISH;

    std::cout << "   Action: " << moqt_actions::action_name(moqt_action)
              << "\n";
    std::cout << "   Namespace: " << namespace_name << "\n";
    std::cout << "   Track: " << track_name << "\n";
    std::cout << "   Endpoint: " << endpoint << "\n\n";

    // Step 4: Generate DPoP proof for the action, using the selected
    // encoding. The proof's payload (actx, iat, jti, [ath]) is identical
    // across encodings; what changes is the wire format of the proof
    // itself (COSE_Sign1 vs base64url JOSE JWT).
    auto jti = moqt_dpop::generate_jti();
    auto dpop_proof = client_keypair.generate_proof(moqt_action, namespace_name,
                                                    track_name, endpoint, jti,
                                                    encoding);

    auto dpop_serialized = dpop_proof.serialize();
    std::cout << "   DPoP proof (" << encoding_name(encoding)
              << ", first 50 chars): "
              << dpop_serialized.substr(
                     0, std::min<size_t>(50, dpop_serialized.size()))
              << "...\n";
    std::cout << "   JTI: " << jti << "\n\n";

    // Step 5: Server-side validation
    std::cout << "5. Server validating request...\n";

    const auto& parsed_claims = decoded_token;

    // Check MOQT authorization
    bool moqt_authorized = false;
    if (parsed_claims.extended.hasMoqtClaims()) {
      const auto* moqt_claims_ptr =
          parsed_claims.extended.getMoqtClaimsReadOnly();
      moqt_authorized = moqt_claims_ptr->isAuthorized(
          moqt_action, namespace_name, track_name);
    }

    std::cout << "   MOQT authorization: "
              << (moqt_authorized ? "GRANTED" : "DENIED") << "\n";
    std::cout << "     Expected: GRANTED (PUBLISH allowed for 'live-stream' "
                 "namespace)\n";
    std::cout << "     Obtained: " << (moqt_authorized ? "GRANTED" : "DENIED")
              << "\n";

    // Validate DPoP proof
    DpopProofValidator dpop_validator(dpop_settings);
    // Signature verification is mandatory (CTA-5007-B §4.6.9). CWT proofs
    // need an externally-supplied verifier because COSE_Key does not
    // expose a key the library can import on demand; JWT proofs
    // self-resolve from the embedded JWK, so `set_cwt_verifier` is only
    // meaningful on the CWT path.
    if (encoding == DpopEncoding::CWT) {
      dpop_validator.set_cwt_verifier(&client_keypair.get_algorithm());
    }
    auto expected_uri =
        moqt_dpop::construct_moqt_uri(endpoint, namespace_name, track_name);

    bool dpop_valid = dpop_validator.validate_proof(
        dpop_proof, moqt_action, expected_uri, key_thumb);

    std::cout << "   DPoP proof validation: "
              << (dpop_valid ? "VALID" : "INVALID") << "\n";
    std::cout
        << "     Expected: VALID (correct action, URI, and key thumbprint)\n";
    std::cout << "     Obtained: " << (dpop_valid ? "VALID" : "INVALID")
              << "\n";
    std::cout << "     MOQT Action: " << moqt_action << " ("
              << moqt_actions::action_name(moqt_action) << ")\n";
    std::cout << "     URI: " << expected_uri << "\n";
    std::cout << "     Context Type: " << dpop_proof.get_payload().actx.type
              << "\n";
    std::cout << "     Track Namespace (tns): "
              << dpop_proof.get_payload().actx.tns << "\n";
    std::cout << "     Track Name (tn): " << dpop_proof.get_payload().actx.tn
              << "\n";

    // Check DPoP binding in token
    bool dpop_binding_valid = false;
    if (parsed_claims.dpop.cnf.has_value() &&
        parsed_claims.dpop.cnf->kid.has_value()) {
      dpop_binding_valid = (parsed_claims.dpop.cnf->kid.value() == key_thumb);
    }

    std::cout << "   DPoP binding validation: "
              << (dpop_binding_valid ? "VALID" : "INVALID") << "\n";
    std::cout
        << "     Expected: VALID (token cnf matches proof key thumbprint)\n";
    std::cout << "     Obtained: " << (dpop_binding_valid ? "VALID" : "INVALID")
              << "\n";
    std::cout << "     Token cnf: "
              << (parsed_claims.dpop.cnf.has_value()
                      ? parsed_claims.dpop.cnf->kid.value_or("none")
                      : "none")
              << "\n";
    std::cout << "     Proof key: " << key_thumb << "\n";

    // Final authorization decision
    bool final_authorized = moqt_authorized && dpop_valid && dpop_binding_valid;
    std::cout << "\n   FINAL AUTHORIZATION: "
              << (final_authorized ? "GRANTED" : "DENIED") << "\n";
    std::cout << "     Expected: GRANTED (all validations pass)\n";
    std::cout << "     Obtained: " << (final_authorized ? "GRANTED" : "DENIED")
              << "\n\n";

    // Step 6: Demonstrate different scenarios
    std::cout << "6. Testing different authorization scenarios...\n";

    // Test unauthorized action
    std::cout << "   Testing ANNOUNCE action (should be denied):\n";
    bool announce_auth = false;
    if (parsed_claims.extended.hasMoqtClaims()) {
      const auto* moqt_claims_ptr =
          parsed_claims.extended.getMoqtClaimsReadOnly();
      announce_auth = moqt_claims_ptr->isAuthorized(moqt_actions::PUBLISH_NAMESPACE,
                                                    namespace_name, track_name);
    }
    std::cout << "     Expected: DENIED (ANNOUNCE not in allowed actions)\n";
    std::cout << "     Obtained: " << (announce_auth ? "GRANTED" : "DENIED")
              << "\n";
    std::cout << "     Action: "
              << moqt_actions::action_name(moqt_actions::PUBLISH_NAMESPACE) << "\n";
    std::cout << "     Namespace: " << namespace_name << "\n";
    std::cout << "     Track: " << track_name << "\n";

    // Test authorized read action
    std::cout
        << "\n   Testing SUBSCRIBE to public track (should be granted):\n";
    bool subscribe_auth = false;
    const std::string test_namespace = "live-stream";
    const std::string test_public_track = "public-data";
    if (parsed_claims.extended.hasMoqtClaims()) {
      const auto* moqt_claims_ptr =
          parsed_claims.extended.getMoqtClaimsReadOnly();
      subscribe_auth = moqt_claims_ptr->isAuthorized(
          moqt_actions::SUBSCRIBE, test_namespace, test_public_track);
    }
    std::cout << "     Expected: GRANTED (SUBSCRIBE allowed for tracks with "
                 "'public-' prefix)\n";
    std::cout << "     Obtained: " << (subscribe_auth ? "GRANTED" : "DENIED")
              << "\n";
    std::cout << "     Action: "
              << moqt_actions::action_name(moqt_actions::SUBSCRIBE) << "\n";
    std::cout << "     Namespace: " << test_namespace << "\n";
    std::cout << "     Track: " << test_public_track
              << " (matches prefix 'public-')\n";

    // Test unauthorized read action (private track)
    std::cout
        << "\n   Testing SUBSCRIBE to private track (should be denied):\n";
    bool private_auth = false;
    const std::string test_private_namespace = "live-stream";
    const std::string test_private_track = "private-data";
    if (parsed_claims.extended.hasMoqtClaims()) {
      const auto* moqt_claims_ptr =
          parsed_claims.extended.getMoqtClaimsReadOnly();
      private_auth = moqt_claims_ptr->isAuthorized(
          moqt_actions::SUBSCRIBE, test_private_namespace, test_private_track);
    }
    std::cout << "     Expected: DENIED (track doesn't match 'public-' prefix "
                 "requirement)\n";
    std::cout << "     Obtained: " << (private_auth ? "GRANTED" : "DENIED")
              << "\n";
    std::cout << "     Action: "
              << moqt_actions::action_name(moqt_actions::SUBSCRIBE) << "\n";
    std::cout << "     Namespace: " << test_private_namespace << "\n";
    std::cout << "     Track: " << test_private_track
              << " (does NOT match prefix 'public-')\n\n";

    // Step 7: Demonstrate revalidation
    std::cout << "7. Token revalidation example...\n";
    if (parsed_claims.extended.hasMoqtClaims()) {
      const auto* moqt_claims_ptr =
          parsed_claims.extended.getMoqtClaimsReadOnly();
      auto revalidation_interval = moqt_claims_ptr->getRevalidationInterval();
      if (revalidation_interval.has_value()) {
        std::cout
            << "   Expected revalidation interval: 1800 seconds (30 minutes)\n";
        std::cout << "   Obtained revalidation interval: "
                  << revalidation_interval->count() << " seconds\n";
        if (parsed_claims.core.exp.has_value()) {
          auto refresh_time =
              parsed_claims.core.exp.value() + revalidation_interval->count();
          std::cout << "   Token expiry: " << parsed_claims.core.exp.value()
                    << "\n";
          std::cout << "   Client should refresh token before: " << refresh_time
                    << "\n";
        }
      }
    }

  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  }

  return 0;
}

namespace {

void print_help(const char* argv0) {
  std::cout
      << "Usage: " << argv0 << " [--alg=ES256|PS256] [--encoding=cwt|jwt]\n"
      << "       " << argv0 << " --all\n"
      << "       " << argv0 << " --help\n\n"
      << "Flags:\n"
      << "  --alg=NAME       Signing algorithm (default ES256).\n"
      << "  --encoding=ENC   DPoP wire encoding, cwt or jwt (default cwt).\n"
      << "  --all            Walk every alg x encoding combination.\n"
      << "  --help           Print this help.\n";
}

bool starts_with(const char* s, const char* prefix) {
  return std::strncmp(s, prefix, std::strlen(prefix)) == 0;
}

}  // namespace

int main(int argc, char** argv) {
  int64_t alg_id = ALG_ES256;
  DpopEncoding encoding = DpopEncoding::CWT;
  bool run_all = false;

  for (int i = 1; i < argc; ++i) {
    const char* arg = argv[i];
    if (std::strcmp(arg, "--help") == 0 || std::strcmp(arg, "-h") == 0) {
      print_help(argv[0]);
      return 0;
    }
    if (std::strcmp(arg, "--all") == 0) {
      run_all = true;
    } else if (starts_with(arg, "--alg=")) {
      std::string v = arg + std::strlen("--alg=");
      if (v == "ES256") alg_id = ALG_ES256;
      else if (v == "PS256") alg_id = ALG_PS256;
      else {
        std::cerr << "Unknown --alg value: " << v << "\n";
        print_help(argv[0]);
        return 2;
      }
    } else if (starts_with(arg, "--encoding=")) {
      std::string v = arg + std::strlen("--encoding=");
      if (v == "cwt" || v == "CWT") encoding = DpopEncoding::CWT;
      else if (v == "jwt" || v == "JWT") encoding = DpopEncoding::JWT;
      else {
        std::cerr << "Unknown --encoding value: " << v << "\n";
        print_help(argv[0]);
        return 2;
      }
    } else {
      std::cerr << "Unknown argument: " << arg << "\n";
      print_help(argv[0]);
      return 2;
    }
  }

#ifndef CATAPULT_ENABLE_JSON
  if (encoding == DpopEncoding::JWT || run_all) {
    std::cerr << "JWT DPoP encoding requires a CATAPULT_ENABLE_JSON=ON build.\n";
    return 2;
  }
#endif

  if (!run_all) {
    return run_demo(alg_id, encoding);
  }

  // --all: walk every supported combination. The CAT token and MOQT
  // authorization output are the same each time; only the DPoP wire
  // format and key thumbprint change — which is exactly the surface
  // this example is meant to illuminate.
  const struct {
    int64_t alg;
    DpopEncoding enc;
  } combos[] = {
      {ALG_ES256, DpopEncoding::CWT},
#ifdef CATAPULT_ENABLE_JSON
      {ALG_ES256, DpopEncoding::JWT},
#endif
      {ALG_PS256, DpopEncoding::CWT},
#ifdef CATAPULT_ENABLE_JSON
      {ALG_PS256, DpopEncoding::JWT},
#endif
  };
  int worst = 0;
  for (const auto& c : combos) {
    std::cout << "\n============================================================"
                 "===============\n";
    int rc = run_demo(c.alg, c.enc);
    if (rc != 0) worst = rc;
  }
  return worst;
}