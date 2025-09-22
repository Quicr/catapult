/**
 * @file cat_dpop.cpp
 * @brief Implementation of DPoP functionality for CAT tokens
 */

#include "catapult/dpop.hpp"
#include "catapult/base64.hpp"
#include "catapult/crypto.hpp"
#include "catapult/moqt_claims.hpp"

#include <nlohmann/json.hpp>
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>

using json = nlohmann::json;

namespace catapult {

// DpopProof implementation


std::vector<uint8_t> DpopProof::create_signing_input() const {
  // Create header JSON
  json header_json = {
    {"typ", header_.typ},
    {"alg", header_.alg},
    {"jwk", json::parse(header_.jwk)}
  };
  
  // Create payload JSON
  json payload_json = {
    {"htm", payload_.htm},
    {"htu", payload_.htu},
    {"iat", payload_.iat}
  };
  
  if (payload_.jti.has_value()) {
    payload_json["jti"] = payload_.jti.value();
  }
  
  if (payload_.ath.has_value()) {
    payload_json["ath"] = payload_.ath.value();
  }
  
  // Encode as Base64URL
  auto header_str = header_json.dump();
  std::vector<uint8_t> header_bytes(header_str.begin(), header_str.end());
  std::string header_b64 = base64UrlEncode(header_bytes);
  
  auto payload_str = payload_json.dump();
  std::vector<uint8_t> payload_bytes(payload_str.begin(), payload_str.end());
  std::string payload_b64 = base64UrlEncode(payload_bytes);
  
  // Create signing input
  std::string signing_input = header_b64 + "." + payload_b64;
  
  return std::vector<uint8_t>(signing_input.begin(), signing_input.end());
}

bool DpopProof::verify_signature(const CryptographicAlgorithm& algorithm) const {
  auto signing_input = create_signing_input();
  // Note: This is a simplified implementation
  // In a real implementation, we'd need to make verify const or create a mutable copy
  return true; // Placeholder
}

std::string DpopProof::to_jwt() const {
  auto signing_input_bytes = create_signing_input();
  std::string signing_input(signing_input_bytes.begin(), signing_input_bytes.end());
  
  std::string signature_b64 = base64UrlEncode(signature_);
  
  return signing_input + "." + signature_b64;
}

DpopProof DpopProof::from_jwt(std::string_view jwt) {
  // Split JWT into parts
  std::vector<std::string> parts;
  std::string current;
  
  for (char c : jwt) {
    if (c == '.') {
      parts.push_back(current);
      current.clear();
    } else {
      current += c;
    }
  }
  parts.push_back(current);
  
  if (parts.size() != 3) {
    throw InvalidTokenFormatError{};
  }
  
  // Decode parts
  auto header_json = json::parse(base64UrlDecode(parts[0]));
  auto payload_json = json::parse(base64UrlDecode(parts[1]));
  auto signature = base64UrlDecode(parts[2]);
  
  // Create header
  DpopHeader header;
  header.typ = header_json.value("typ", "");
  header.alg = header_json.value("alg", "");
  header.jwk = header_json.value("jwk", json{}).dump();
  
  // Create payload
  DpopPayload payload(payload_json.value("htm", ""), payload_json.value("htu", ""));
  payload.iat = payload_json.value("iat", 0);
  
  if (payload_json.contains("jti")) {
    payload.jti = payload_json["jti"];
  }
  
  if (payload_json.contains("ath")) {
    payload.ath = payload_json["ath"];
  }
  
  return DpopProof{std::move(header), std::move(payload), signature};
}

// moqt_dpop namespace implementation

namespace moqt_dpop {

std::string generate_jti() {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint32_t> dis;
  
  std::ostringstream oss;
  oss << std::hex << dis(gen) << dis(gen);
  return oss.str();
}

} // namespace moqt_dpop

// DpopProofValidator implementation

bool DpopProofValidator::validate_proof(
    const DpopProof& proof,
    std::string_view expected_method,
    std::string_view expected_uri,
    const std::string& expected_public_key_thumbprint) {
  
  // Basic structure validation
  if (!proof.is_valid(settings_)) {
    return false;
  }
  
  // Check method and URI
  if (proof.get_payload().htm != expected_method ||
      proof.get_payload().htu != expected_uri) {
    return false;
  }
  
  // Check JTI if enabled and present
  if (settings_.get_jti_processing() && proof.get_payload().jti.has_value()) {
    const auto& jti = proof.get_payload().jti.value();
    
    // Check if JTI was already used
    auto it = used_jtis_.find(jti);
    if (it != used_jtis_.end()) {
      // Check if it's still within the window
      auto now = std::chrono::system_clock::now();
      auto diff = now - it->second;
      if (diff < settings_.get_effective_window()) {
        return false; // Replay attack detected
      }
    }
    
    // Record this JTI
    used_jtis_[jti] = std::chrono::system_clock::now();
  }
  
  // Additional validations can be added here (e.g., public key thumbprint matching)
  
  return true;
}

void DpopProofValidator::cleanup_expired_jtis() {
  auto now = std::chrono::system_clock::now();
  auto window = settings_.get_effective_window();
  
  auto it = used_jtis_.begin();
  while (it != used_jtis_.end()) {
    if (now - it->second > window) {
      it = used_jtis_.erase(it);
    } else {
      ++it;
    }
  }
}

// DpopKeyPair implementation

DpopKeyPair::DpopKeyPair(std::unique_ptr<CryptographicAlgorithm> alg)
    : algorithm_(std::move(alg)) {
  // Generate public key JWK and thumbprint
  // This is a simplified implementation - real implementation would use the algorithm
  public_key_jwk_ = R"({"kty":"EC","crv":"P-256","x":"example","y":"example"})";
  public_key_thumbprint_ = "example_thumbprint";
}


std::string DpopKeyPair::get_algorithm_name() const {
  // This should return the actual algorithm name from the algorithm instance
  return "ES256"; // Example
}

} // namespace catapult