/**
 * @file cat_dpop.hpp
 * @brief DPoP (Demonstrating Proof-of-Possession) support for CAT tokens
 * 
 * This file implements DPoP functionality as defined in RFC 9449 and integrated
 * with CAT tokens according to draft-law-moq-cat4moqt specification.
 */

#pragma once

#include <string>
#include <string_view>
#include <optional>
#include <unordered_map>
#include <chrono>
#include <memory>
#include <span>
#include <concepts>

#include "error.hpp"
#include "crypto.hpp"
#include "moqt_claims.hpp"

namespace catapult {

/**
 * @brief DPoP header parameters
 */
struct DpopHeader {
  std::string typ = "dpop+jwt";     ///< Token type, must be "dpop+jwt"
  std::string alg;                  ///< Signing algorithm (e.g., "ES256", "RS256")
  std::string jwk;                  ///< JSON Web Key (public key)
  
  /**
   * @brief Validate header parameters
   */
  [[nodiscard]] bool is_valid() const noexcept {
    return typ == "dpop+jwt" && !alg.empty() && !jwk.empty();
  }
};

/**
 * @brief DPoP payload claims
 */
struct DpopPayload {
  std::optional<std::string> jti;   ///< JWT ID for replay protection
  std::string htm;                  ///< HTTP method (or equivalent MOQT action)
  std::string htu;                  ///< HTTP URI (or MOQT resource identifier)
  int64_t iat;                      ///< Issued at timestamp
  std::optional<std::string> ath;   ///< Access token hash (optional)
  
  /**
   * @brief Constructor with required fields
   */
  DpopPayload(std::string_view method, std::string_view uri)
    : htm(method), htu(uri), iat(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())) {}
  
  /**
   * @brief Validate payload claims
   */
  [[nodiscard]] bool is_valid() const noexcept {
    return !htm.empty() && !htu.empty() && iat > 0;
  }
  
  /**
   * @brief Check if timestamp is within acceptable window
   */
  [[nodiscard]] bool is_fresh(std::chrono::seconds window = std::chrono::seconds{300}) const noexcept {
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    auto diff = std::abs(now - iat);
    return diff <= window.count();
  }
};

/**
 * @brief CAT DPoP settings claim (catdpop)
 */
struct CatDpopSettings {
  std::optional<std::chrono::seconds> window;     ///< Time window for proof validity
  std::optional<bool> honor_jti;                  ///< Whether to honor JTI claims
  std::vector<int> critical_settings;             ///< Critical settings that must be understood
  
  /**
   * @brief Default constructor with reasonable defaults
   */
  CatDpopSettings() = default;
  
  /**
   * @brief Constructor with window setting
   */
  explicit CatDpopSettings(std::chrono::seconds time_window)
    : window(time_window), honor_jti(true) {}
  
  /**
   * @brief Set window setting
   */
  void set_window(std::chrono::seconds time_window) {
    window = time_window;
  }
  
  /**
   * @brief Set JTI processing preference
   */
  void set_jti_processing(bool honor) {
    honor_jti = honor;
  }
  
  /**
   * @brief Add critical setting
   */
  void add_critical_setting(int setting_key) {
    critical_settings.push_back(setting_key);
  }
  
  /**
   * @brief Get effective window (default 300 seconds if not set)
   */
  [[nodiscard]] std::chrono::seconds get_effective_window() const noexcept {
    return window.value_or(std::chrono::seconds{300});
  }
  
  /**
   * @brief Get JTI processing preference (default true if not set)
   */
  [[nodiscard]] bool get_jti_processing() const noexcept {
    return honor_jti.value_or(true);
  }
};

/**
 * @brief DPoP proof JWT
 */
class DpopProof {
private:
  DpopHeader header_;
  DpopPayload payload_;
  std::vector<uint8_t> signature_;
  
public:
  /**
   * @brief Constructor
   */
  DpopProof(DpopHeader header, DpopPayload payload, std::span<const uint8_t> signature)
    : header_(std::move(header)), payload_(std::move(payload)), 
      signature_(signature.begin(), signature.end()) {}
  
  /**
   * @brief Create DPoP proof for MOQT action
   */
  template<MoqtActionType ActionT>
  static DpopProof create_for_moqt_action(
    ActionT moqt_action,
    std::string_view namespace_name,
    std::string_view track_name,
    std::string_view endpoint_uri,
    const std::string& algorithm,
    const std::string& public_key_jwk,
    std::optional<std::string> jti = std::nullopt
  );
  
  /**
   * @brief Create signing input for verification
   */
  [[nodiscard]] std::vector<uint8_t> create_signing_input() const;
  
  /**
   * @brief Verify the proof signature
   */
  [[nodiscard]] bool verify_signature(const CryptographicAlgorithm& algorithm) const;
  
  /**
   * @brief Get header
   */
  [[nodiscard]] const DpopHeader& get_header() const noexcept { return header_; }
  
  /**
   * @brief Get payload
   */
  [[nodiscard]] const DpopPayload& get_payload() const noexcept { return payload_; }
  
  /**
   * @brief Get signature
   */
  [[nodiscard]] std::span<const uint8_t> get_signature() const noexcept { 
    return std::span<const uint8_t>{signature_}; 
  }
  
  /**
   * @brief Serialize to JWT format
   */
  [[nodiscard]] std::string to_jwt() const;
  
  /**
   * @brief Parse from JWT string
   */
  static DpopProof from_jwt(std::string_view jwt);
  
  /**
   * @brief Validate proof structure and freshness
   */
  [[nodiscard]] bool is_valid(const CatDpopSettings& settings = {}) const noexcept {
    return header_.is_valid() && 
           payload_.is_valid() && 
           payload_.is_fresh(settings.get_effective_window()) &&
           !signature_.empty();
  }
};

/**
 * @brief MOQT-specific DPoP utilities
 */
namespace moqt_dpop {
  
  /**
   * @brief Map MOQT action to HTTP method equivalent
   */
  template<MoqtActionType ActionT>
  [[nodiscard]] constexpr std::string_view action_to_http_method(ActionT moqt_action) noexcept {
    switch (moqt_action) {
      case 0: // CLIENT_SETUP
      case 1: // SERVER_SETUP
      case 6: // PUBLISH
        return "POST";
      case 2: // ANNOUNCE
        return "PUT";
      case 3: // SUBSCRIBE_NAMESPACE
      case 4: // SUBSCRIBE
      case 5: // SUBSCRIBE_UPDATE
      case 7: // FETCH
        return "GET";
      case 8: // TRACK_STATUS
        return "GET";
      default:
        return "POST"; // Default fallback
    }
  }
  
  /**
   * @brief Construct MOQT resource URI
   */
  [[nodiscard]] inline std::string construct_moqt_uri(
    std::string_view endpoint,
    std::string_view namespace_name = {},
    std::string_view track_name = {}
  ) {
    std::string uri = "moqt://";
    uri += endpoint;
    
    if (!namespace_name.empty()) {
      uri += "/";
      uri += namespace_name;
      
      if (!track_name.empty()) {
        uri += "/";
        uri += track_name;
      }
    }
    
    return uri;
  }
  
  /**
   * @brief Generate JTI for replay protection
   */
  [[nodiscard]] std::string generate_jti();
  
} // namespace moqt_dpop

/**
 * @brief DPoP proof validator
 */
class DpopProofValidator {
private:
  std::unordered_map<std::string, std::chrono::system_clock::time_point> used_jtis_;
  CatDpopSettings settings_;
  
public:
  /**
   * @brief Constructor with settings
   */
  explicit DpopProofValidator(CatDpopSettings settings = {})
    : settings_(std::move(settings)) {}
  
  /**
   * @brief Validate DPoP proof
   */
  [[nodiscard]] bool validate_proof(
    const DpopProof& proof,
    std::string_view expected_method,
    std::string_view expected_uri,
    const std::string& expected_public_key_thumbprint
  );
  
  /**
   * @brief Clean up expired JTIs
   */
  void cleanup_expired_jtis();
  
  /**
   * @brief Get current settings
   */
  [[nodiscard]] const CatDpopSettings& get_settings() const noexcept {
    return settings_;
  }
  
  /**
   * @brief Update settings
   */
  void update_settings(CatDpopSettings new_settings) {
    settings_ = std::move(new_settings);
  }
};

/**
 * @brief DPoP key pair for proof generation
 */
class DpopKeyPair {
private:
  std::unique_ptr<CryptographicAlgorithm> algorithm_;
  std::string public_key_jwk_;
  std::string public_key_thumbprint_;
  
public:
  /**
   * @brief Constructor with algorithm
   */
  explicit DpopKeyPair(std::unique_ptr<CryptographicAlgorithm> alg);
  
  /**
   * @brief Generate proof for MOQT action
   */
  template<MoqtActionType ActionT>
  [[nodiscard]] DpopProof generate_proof(
    ActionT moqt_action,
    std::string_view namespace_name,
    std::string_view track_name,
    std::string_view endpoint_uri,
    std::optional<std::string> jti = std::nullopt
  ) const;
  
  /**
   * @brief Get public key JWK
   */
  [[nodiscard]] const std::string& get_public_key_jwk() const noexcept {
    return public_key_jwk_;
  }
  
  /**
   * @brief Get public key thumbprint
   */
  [[nodiscard]] const std::string& get_public_key_thumbprint() const noexcept {
    return public_key_thumbprint_;
  }
  
  /**
   * @brief Get algorithm name
   */
  [[nodiscard]] std::string get_algorithm_name() const;
};

/**
 * @brief Enhanced DPoP claims structure for CAT tokens
 */
struct EnhancedDpopClaims {
  std::optional<std::string> cnf;           ///< Confirmation claim (JWK thumbprint)
  std::optional<CatDpopSettings> catdpop;   ///< CAT DPoP settings
  
  /**
   * @brief Default constructor
   */
  EnhancedDpopClaims() = default;
  
  /**
   * @brief Set confirmation with JWK thumbprint
   */
  void set_confirmation(const std::string& jwk_thumbprint) {
    cnf = jwk_thumbprint;
  }
  
  /**
   * @brief Set DPoP settings
   */
  void set_dpop_settings(CatDpopSettings settings) {
    catdpop = std::move(settings);
  }
  
  /**
   * @brief Get effective DPoP settings
   */
  [[nodiscard]] CatDpopSettings get_effective_settings() const {
    return catdpop.value_or(CatDpopSettings{});
  }
  
  /**
   * @brief Check if confirmation is present
   */
  [[nodiscard]] bool has_confirmation() const noexcept {
    return cnf.has_value() && !cnf->empty();
  }
  
  /**
   * @brief Validate DPoP binding
   */
  [[nodiscard]] bool validate_binding(const std::string& proof_public_key_thumbprint) const noexcept {
    return has_confirmation() && cnf.value() == proof_public_key_thumbprint;
  }
};

// Template implementations (defined after moqt_dpop namespace)

template<MoqtActionType ActionT>
DpopProof DpopProof::create_for_moqt_action(
    ActionT moqt_action,
    std::string_view namespace_name,
    std::string_view track_name,
    std::string_view endpoint_uri,
    const std::string& algorithm,
    const std::string& public_key_jwk,
    std::optional<std::string> jti) {
  
  // Create header
  DpopHeader header;
  header.typ = "dpop+jwt";
  header.alg = algorithm;
  header.jwk = public_key_jwk;
  
  // Create payload
  auto http_method = moqt_dpop::action_to_http_method(moqt_action);
  auto resource_uri = moqt_dpop::construct_moqt_uri(endpoint_uri, namespace_name, track_name);
  
  DpopPayload payload(http_method, resource_uri);
  if (jti.has_value()) {
    payload.jti = std::move(jti.value());
  }
  
  // For now, create empty signature - this should be signed by the caller
  std::vector<uint8_t> empty_signature;
  
  return DpopProof{std::move(header), std::move(payload), empty_signature};
}

template<MoqtActionType ActionT>
DpopProof DpopKeyPair::generate_proof(
    ActionT moqt_action,
    std::string_view namespace_name,
    std::string_view track_name,
    std::string_view endpoint_uri,
    std::optional<std::string> jti) const {
  
  auto proof = DpopProof::create_for_moqt_action(
    moqt_action, namespace_name, track_name, endpoint_uri,
    get_algorithm_name(), public_key_jwk_, std::move(jti)
  );
  
  // Sign the proof
  auto signing_input = proof.create_signing_input();
  auto signature = algorithm_->sign(signing_input);
  
  // Create new proof with signature
  return DpopProof{proof.get_header(), proof.get_payload(), signature};
}

} // namespace catapult