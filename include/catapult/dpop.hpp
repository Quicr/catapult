/**
 * @file cat_dpop.hpp
 * @brief DPoP (Demonstrating Proof-of-Possession) support for CAT tokens
 *
 * This file implements DPoP functionality as defined in
 * https://www.ietf.org/archive/id/draft-nandakumar-moq-generic-dpop-proof-00.html
 * and integrated with CAT tokens according to draft-law-moq-cat4moqt
 * specification.
 *
 * Supports both JWT and CWT encoding formats:
 * - JWT: dpop-proof+jwt (JSON-based, interoperable with OAuth 2.0)
 * - CWT: dpop-proof+cwt (CBOR-based, compact, suitable for constrained
 * environments)
 */

#pragma once

#include <chrono>
#include <concepts>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

#include "crypto.hpp"
#include "error.hpp"
#include "moqt_claims.hpp"

namespace catapult {

/**
 * @brief DPoP proof encoding format
 *
 * Per draft-nandakumar-moq-generic-dpop-proof-00:
 * - JWT: Use when integrating with OAuth 2.0 infrastructure or debugging
 * - CWT: Use when integrating with CAT systems or in bandwidth-constrained
 * environments
 */
enum class DpopEncoding {
  JWT,  ///< JSON Web Token format (typ: dpop-proof+jwt)
  CWT   ///< CBOR Web Token format (typ: dpop-proof+cwt, uses COSE_Sign1)
};

/**
 * @brief COSE header labels for CWT DPoP proofs
 */
namespace dpop_labels {
constexpr int64_t ALG = 1;       ///< Algorithm (COSE header)
constexpr int64_t TYP = 16;      ///< Type (COSE header)
constexpr int64_t COSE_KEY = 4;  ///< COSE_Key in header
constexpr int64_t CTI = 7;       ///< Unique identifier (CWT claim)
constexpr int64_t IAT = 6;       ///< Issued-at timestamp (CWT claim)
constexpr int64_t ACTX = 400;    ///< Authorization context (TBD in spec)
constexpr int64_t ATH = 401;     ///< Access token hash (TBD in spec)
constexpr int64_t NONCE = 402;   ///< Server-provided nonce (TBD in spec)
}  // namespace dpop_labels

/**
 * @brief Get recommended encoding based on context
 * @param for_cat_integration True if integrating with CAT token systems
 * @param bandwidth_constrained True if operating in constrained environment
 * @return Recommended DpopEncoding
 */
[[nodiscard]] constexpr DpopEncoding recommended_dpop_encoding(
    bool for_cat_integration = true,
    bool bandwidth_constrained = false) noexcept {
  if (for_cat_integration || bandwidth_constrained) {
    return DpopEncoding::CWT;
  }
  return DpopEncoding::JWT;
}

/**
 * @brief DPoP header parameters
 */
struct DpopHeader {
  std::string typ =
      "dpop-proof+cwt";  ///< Token type (dpop-proof+jwt or dpop-proof+cwt)
  std::string alg;       ///< Signing algorithm (e.g., "ES256", "RS256")
  std::string jwk;       ///< JSON Web Key (public key) - for JWT format
  std::vector<uint8_t> cose_key;  ///< COSE_Key (public key) - for CWT format
  int64_t alg_id = 0;             ///< COSE algorithm ID - for CWT format

  /**
   * @brief Get the encoding format from typ
   */
  [[nodiscard]] DpopEncoding encoding() const noexcept {
    return typ == "dpop-proof+jwt" ? DpopEncoding::JWT : DpopEncoding::CWT;
  }

  /**
   * @brief Set encoding format (updates typ accordingly)
   */
  void set_encoding(DpopEncoding enc) noexcept {
    typ = (enc == DpopEncoding::JWT) ? "dpop-proof+jwt" : "dpop-proof+cwt";
  }

  /**
   * @brief Validate header parameters
   */
  [[nodiscard]] bool is_valid() const noexcept {
    bool valid_typ = (typ == "dpop-proof+jwt" || typ == "dpop-proof+cwt");
    if (encoding() == DpopEncoding::JWT) {
      return valid_typ && !alg.empty() && !jwk.empty();
    }
    return valid_typ && alg_id != 0 && !cose_key.empty();
  }
};

/**
 * @brief Authorization Context for application-agnostic DPoP proof
 */
struct AuthorizationContext {
  std::string type;  ///< Protocol type identifier (e.g., "moqt")
  int action;        ///< Protocol-specific action code
  std::string
      resource_uri;  ///< Protocol-specific resource identifier (optional)
  std::string tns;   ///< Track namespace (required for MOQT)
  std::string tn;    ///< Track name (required for MOQT)

  /**
   * @brief Constructor for MOQT context
   */
  AuthorizationContext(int moqt_action, std::string_view uri)
      : type("moqt"), action(moqt_action), resource_uri(uri) {}

  /**
   * @brief Constructor for MOQT context with track namespace and name
   */
  AuthorizationContext(int moqt_action, std::string_view track_namespace,
                       std::string_view track_name, std::string_view uri = "")
      : type("moqt"),
        action(moqt_action),
        resource_uri(uri),
        tns(track_namespace),
        tn(track_name) {}

  /**
   * @brief Validate context
   */
  [[nodiscard]] bool is_valid() const noexcept {
    return !type.empty() && action >= 0 && !tns.empty() && !tn.empty();
  }
};

/**
 * @brief DPoP payload claims (Application-Agnostic Framework)
 */
struct DpopPayload {
  std::optional<std::string> jti;  ///< JWT ID for replay protection
  AuthorizationContext actx;       ///< Authorization context
  int64_t iat;                     ///< Issued at timestamp
  std::optional<std::string> ath;  ///< Access token hash (optional)

  /**
   * @brief Constructor with required fields for MOQT
   */
  DpopPayload(int action, std::string_view track_namespace,
              std::string_view track_name, std::string_view uri = "")
      : actx(action, track_namespace, track_name, uri),
        iat(std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now())) {}

  /**
   * @brief Validate payload claims
   */
  [[nodiscard]] bool is_valid() const noexcept {
    return actx.is_valid() && iat > 0;
  }

  /**
   * @brief Check if timestamp is within acceptable window
   * @note Rejects future timestamps beyond a small clock skew tolerance
   */
  [[nodiscard]] bool is_fresh(
      std::chrono::seconds window = std::chrono::seconds{300},
      std::chrono::seconds future_tolerance = std::chrono::seconds{60}) const noexcept {
    auto now =
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    // Reject timestamps too far in the future (prevents pre-generated proofs)
    if (iat > now + future_tolerance.count()) {
      return false;
    }
    // Check if timestamp is within the past window
    auto age = now - iat;
    return age >= 0 && age <= window.count();
  }
};

/**
 * @brief CAT DPoP settings claim (catdpop)
 */
struct CatDpopSettings {
  std::optional<std::chrono::seconds>
      window;                     ///< Time window for proof validity
  std::optional<bool> honor_jti;  ///< Whether to honor JTI claims
  std::optional<size_t> max_jti_entries;     ///< Max JTI cache size for replay protection
  std::optional<size_t> jti_cleanup_interval;  ///< How often to run JTI cleanup
  std::vector<int>
      critical_settings;  ///< Critical settings that must be understood

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
  void set_window(std::chrono::seconds time_window) { window = time_window; }

  /**
   * @brief Set JTI processing preference
   */
  void set_jti_processing(bool honor) { honor_jti = honor; }

  /**
   * @brief Set maximum JTI cache entries for replay protection
   * @param max_entries Maximum number of JTIs to track (default 1M)
   */
  void set_max_jti_entries(size_t max_entries) { max_jti_entries = max_entries; }

  /**
   * @brief Set JTI cleanup interval
   * @param interval Run cleanup every N insertions (default 10000)
   */
  void set_jti_cleanup_interval(size_t interval) { jti_cleanup_interval = interval; }

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

  /**
   * @brief Get max JTI entries (default 1M for large-scale deployments)
   */
  [[nodiscard]] size_t get_max_jti_entries() const noexcept {
    return max_jti_entries.value_or(1000000);
  }

  /**
   * @brief Get JTI cleanup interval (default 10000)
   */
  [[nodiscard]] size_t get_jti_cleanup_interval() const noexcept {
    return jti_cleanup_interval.value_or(10000);
  }
};

/**
 * @brief DPoP proof supporting both JWT and CWT formats
 *
 * Per draft-nandakumar-moq-generic-dpop-proof-00:
 * - CWT format uses COSE_Sign1 envelope with CBOR-encoded claims
 * - JWT format uses JSON encoding (requires CATAPULT_ENABLE_JSON)
 */
class DpopProof {
 private:
  DpopHeader header_;
  DpopPayload payload_;
  std::vector<uint8_t> signature_;
  DpopEncoding encoding_ = DpopEncoding::CWT;

 public:
  /**
   * @brief Constructor
   */
  DpopProof(DpopHeader header, DpopPayload payload,
            std::span<const uint8_t> signature,
            DpopEncoding encoding = DpopEncoding::CWT)
      : header_(std::move(header)),
        payload_(std::move(payload)),
        signature_(signature.begin(), signature.end()),
        encoding_(encoding) {
    header_.set_encoding(encoding);
  }

  /**
   * @brief Create DPoP proof for MOQT action (CWT format)
   */
  template <MoqtActionType ActionT>
  static DpopProof create_for_moqt_action_cwt(
      ActionT moqt_action, std::string_view namespace_name,
      std::string_view track_name, std::string_view endpoint_uri,
      int64_t alg_id, std::vector<uint8_t> cose_key,
      std::optional<std::string> jti = std::nullopt);

#ifdef CATAPULT_ENABLE_JSON
  /**
   * @brief Create DPoP proof for MOQT action (JWT format, requires JSON
   * support)
   */
  template <MoqtActionType ActionT>
  static DpopProof create_for_moqt_action_jwt(
      ActionT moqt_action, std::string_view namespace_name,
      std::string_view track_name, std::string_view endpoint_uri,
      const std::string& algorithm, const std::string& public_key_jwk,
      std::optional<std::string> jti = std::nullopt);
#endif

  /**
   * @brief Create DPoP proof for MOQT action (legacy, defaults to CWT)
   * @deprecated Use create_for_moqt_action_cwt or create_for_moqt_action_jwt
   */
  template <MoqtActionType ActionT>
  static DpopProof create_for_moqt_action(
      ActionT moqt_action, std::string_view namespace_name,
      std::string_view track_name, std::string_view endpoint_uri,
      const std::string& algorithm, const std::string& public_key_jwk,
      std::optional<std::string> jti = std::nullopt);

  /**
   * @brief Create signing input for verification
   */
  [[nodiscard]] std::vector<uint8_t> create_signing_input() const;

  /**
   * @brief Verify the proof signature
   */
  [[nodiscard]] bool verify_signature(
      const CryptographicAlgorithm& algorithm) const;

  /**
   * @brief Verify the proof signature using public key from header
   */
  [[nodiscard]] bool verify_signature() const;

  /**
   * @brief Get header
   */
  [[nodiscard]] const DpopHeader& get_header() const noexcept {
    return header_;
  }

  /**
   * @brief Get payload
   */
  [[nodiscard]] const DpopPayload& get_payload() const noexcept {
    return payload_;
  }

  /**
   * @brief Get signature
   */
  [[nodiscard]] std::span<const uint8_t> get_signature() const noexcept {
    return std::span<const uint8_t>{signature_};
  }

  /**
   * @brief Get encoding format
   */
  [[nodiscard]] DpopEncoding encoding() const noexcept { return encoding_; }

  /**
   * @brief Serialize to wire format (CWT or JWT based on encoding)
   */
  [[nodiscard]] std::string serialize() const;

  /**
   * @brief Serialize to CWT format (COSE_Sign1)
   */
  [[nodiscard]] std::string serialize_cwt() const;

#ifdef CATAPULT_ENABLE_JSON
  /**
   * @brief Serialize to JWT format (requires JSON support)
   */
  [[nodiscard]] std::string serialize_jwt() const;
#endif

  /**
   * @brief Deserialize from wire format (auto-detects CWT vs JWT)
   */
  static DpopProof deserialize(std::string_view data);

  /**
   * @brief Deserialize from CWT format
   */
  static DpopProof deserialize_cwt(std::string_view cwt_data);

#ifdef CATAPULT_ENABLE_JSON
  /**
   * @brief Deserialize from JWT format (requires JSON support)
   */
  static DpopProof deserialize_jwt(std::string_view jwt_data);
#endif

  /**
   * @brief Validate proof structure and freshness
   */
  [[nodiscard]] bool is_valid(
      const CatDpopSettings& settings = {}) const noexcept {
    return header_.is_valid() && payload_.is_valid() &&
           payload_.is_fresh(settings.get_effective_window()) &&
           !signature_.empty();
  }
};

/**
 * @brief MOQT-specific DPoP utilities
 */
namespace moqt_dpop {

/**
 * @brief Get MOQT action code as string
 */
template <MoqtActionType ActionT>
[[nodiscard]] constexpr std::string_view action_to_string(
    ActionT moqt_action) noexcept {
  switch (moqt_action) {
    case 0:
      return "CLIENT_SETUP";
    case 1:
      return "SERVER_SETUP";
    case 2:
      return "ANNOUNCE";
    case 3:
      return "SUBSCRIBE_NAMESPACE";
    case 4:
      return "SUBSCRIBE";
    case 5:
      return "SUBSCRIBE_UPDATE";
    case 6:
      return "PUBLISH";
    case 7:
      return "FETCH";
    case 8:
      return "TRACK_STATUS";
    default:
      return "UNKNOWN";
  }
}

/**
 * @brief Construct MOQT resource URI
 */
[[nodiscard]] inline std::string construct_moqt_uri(
    std::string_view endpoint, std::string_view namespace_name = {},
    std::string_view track_name = {}) {
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

}  // namespace moqt_dpop

/**
 * @brief DPoP proof validator
 * @note Thread-safe: JTI tracking is protected by mutex
 */
class DpopProofValidator {
 private:
  mutable std::mutex jti_mutex_;  ///< Mutex for thread-safe JTI tracking
  std::unordered_map<std::string, std::chrono::system_clock::time_point>
      used_jtis_;
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
      const DpopProof& proof, int expected_action,
      std::string_view expected_uri,
      const std::string& expected_public_key_thumbprint);

  /**
   * @brief Validate DPoP proof with compile-time action set for optimized
   * validation
   */
  template <typename ActionSet>
  [[nodiscard]] bool validate_proof_with_role(
      const DpopProof& proof, const ActionSet& allowed_actions,
      std::string_view expected_uri,
      const std::string& expected_public_key_thumbprint) {
    // Basic structure validation
    if (!proof.is_valid(settings_)) {
      return false;
    }

    // Check if action is allowed by the role (compile-time optimized)
    const int actual_action = proof.get_payload().actx.action;
    if (!allowed_actions.contains(actual_action)) {
      return false;
    }

    // Continue with standard validation
    return validate_proof(proof, actual_action, expected_uri,
                          expected_public_key_thumbprint);
  }

  /**
   * @brief Clean up expired JTIs (acquires lock)
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

 private:
  /**
   * @brief Clean up expired JTIs (must be called with lock held)
   */
  void cleanup_expired_jtis_locked();
};

/**
 * @brief DPoP key pair for proof generation
 *
 * Supports generating proofs in both CWT and JWT formats.
 * CWT is the default and recommended format for CAT integrations.
 */
class DpopKeyPair {
 private:
  std::unique_ptr<CryptographicAlgorithm> algorithm_;
  std::vector<uint8_t> public_key_der_;
  std::vector<uint8_t> cose_key_;
  std::string public_key_thumbprint_;
#ifdef CATAPULT_ENABLE_JSON
  std::string public_key_jwk_;
#endif

 public:
  /**
   * @brief Constructor with algorithm
   */
  explicit DpopKeyPair(std::unique_ptr<CryptographicAlgorithm> alg);

  /**
   * @brief Generate proof for MOQT action (uses recommended encoding)
   */
  template <MoqtActionType ActionT>
  [[nodiscard]] DpopProof generate_proof(
      ActionT moqt_action, std::string_view namespace_name,
      std::string_view track_name, std::string_view endpoint_uri,
      std::optional<std::string> jti = std::nullopt,
      DpopEncoding encoding = DpopEncoding::CWT) const;

  /**
   * @brief Generate proof in CWT format (always available)
   */
  template <MoqtActionType ActionT>
  [[nodiscard]] DpopProof generate_proof_cwt(
      ActionT moqt_action, std::string_view namespace_name,
      std::string_view track_name, std::string_view endpoint_uri,
      std::optional<std::string> jti = std::nullopt) const;

#ifdef CATAPULT_ENABLE_JSON
  /**
   * @brief Generate proof in JWT format (requires JSON support)
   */
  template <MoqtActionType ActionT>
  [[nodiscard]] DpopProof generate_proof_jwt(
      ActionT moqt_action, std::string_view namespace_name,
      std::string_view track_name, std::string_view endpoint_uri,
      std::optional<std::string> jti = std::nullopt) const;

  /**
   * @brief Get public key JWK (requires JSON support)
   */
  [[nodiscard]] const std::string& get_public_key_jwk() const noexcept {
    return public_key_jwk_;
  }
#endif

  /**
   * @brief Get public key as COSE_Key bytes
   */
  [[nodiscard]] const std::vector<uint8_t>& get_cose_key() const noexcept {
    return cose_key_;
  }

  /**
   * @brief Get public key thumbprint (base64url-encoded SHA-256)
   */
  [[nodiscard]] const std::string& get_public_key_thumbprint() const noexcept {
    return public_key_thumbprint_;
  }

  /**
   * @brief Get algorithm name (e.g., "ES256", "PS256")
   */
  [[nodiscard]] std::string get_algorithm_name() const;

  /**
   * @brief Get COSE algorithm ID
   */
  [[nodiscard]] int64_t get_algorithm_id() const noexcept {
    return algorithm_ ? algorithm_->algorithmId() : 0;
  }
};

/**
 * @brief Enhanced DPoP claims structure for CAT tokens
 */
struct EnhancedDpopClaims {
  std::optional<std::string> cnf;  ///< Confirmation claim (JWK thumbprint)
  std::optional<CatDpopSettings> catdpop;  ///< CAT DPoP settings

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
  [[nodiscard]] bool validate_binding(
      const std::string& proof_public_key_thumbprint) const noexcept {
    return has_confirmation() && cnf.value() == proof_public_key_thumbprint;
  }
};

template <MoqtActionType ActionT>
DpopProof DpopProof::create_for_moqt_action_cwt(
    ActionT moqt_action, std::string_view namespace_name,
    std::string_view track_name, std::string_view endpoint_uri, int64_t alg_id,
    std::vector<uint8_t> cose_key, std::optional<std::string> jti) {
  DpopHeader header;
  header.set_encoding(DpopEncoding::CWT);
  header.alg_id = alg_id;
  header.cose_key = std::move(cose_key);

  auto resource_uri =
      moqt_dpop::construct_moqt_uri(endpoint_uri, namespace_name, track_name);

  DpopPayload payload(static_cast<int>(moqt_action), namespace_name, track_name,
                      resource_uri);
  if (jti.has_value()) {
    payload.jti = std::move(jti.value());
  }

  std::vector<uint8_t> empty_signature;
  return DpopProof{std::move(header), std::move(payload), empty_signature,
                   DpopEncoding::CWT};
}

#ifdef CATAPULT_ENABLE_JSON
template <MoqtActionType ActionT>
DpopProof DpopProof::create_for_moqt_action_jwt(
    ActionT moqt_action, std::string_view namespace_name,
    std::string_view track_name, std::string_view endpoint_uri,
    const std::string& algorithm, const std::string& public_key_jwk,
    std::optional<std::string> jti) {
  DpopHeader header;
  header.set_encoding(DpopEncoding::JWT);
  header.alg = algorithm;
  header.jwk = public_key_jwk;

  auto resource_uri =
      moqt_dpop::construct_moqt_uri(endpoint_uri, namespace_name, track_name);

  DpopPayload payload(static_cast<int>(moqt_action), namespace_name, track_name,
                      resource_uri);
  if (jti.has_value()) {
    payload.jti = std::move(jti.value());
  }

  std::vector<uint8_t> empty_signature;
  return DpopProof{std::move(header), std::move(payload), empty_signature,
                   DpopEncoding::JWT};
}
#endif

template <MoqtActionType ActionT>
DpopProof DpopProof::create_for_moqt_action(ActionT moqt_action,
                                            std::string_view namespace_name,
                                            std::string_view track_name,
                                            std::string_view endpoint_uri,
                                            const std::string& algorithm,
                                            const std::string& public_key_jwk,
                                            std::optional<std::string> jti) {
#ifdef CATAPULT_ENABLE_JSON
  return create_for_moqt_action_jwt(moqt_action, namespace_name, track_name,
                                    endpoint_uri, algorithm, public_key_jwk,
                                    std::move(jti));
#else
  (void)algorithm;
  (void)public_key_jwk;
  (void)jti;
  throw CryptoError(
      "JWT DPoP format requires CATAPULT_ENABLE_JSON. Use CWT format instead.");
#endif
}

template <MoqtActionType ActionT>
DpopProof DpopKeyPair::generate_proof_cwt(
    ActionT moqt_action, std::string_view namespace_name,
    std::string_view track_name, std::string_view endpoint_uri,
    std::optional<std::string> jti) const {
  auto proof = DpopProof::create_for_moqt_action_cwt(
      moqt_action, namespace_name, track_name, endpoint_uri,
      algorithm_->algorithmId(), cose_key_, std::move(jti));

  auto signing_input = proof.create_signing_input();
  auto signature = algorithm_->sign(signing_input);

  return DpopProof{proof.get_header(), proof.get_payload(), signature,
                   DpopEncoding::CWT};
}

#ifdef CATAPULT_ENABLE_JSON
template <MoqtActionType ActionT>
DpopProof DpopKeyPair::generate_proof_jwt(
    ActionT moqt_action, std::string_view namespace_name,
    std::string_view track_name, std::string_view endpoint_uri,
    std::optional<std::string> jti) const {
  auto proof = DpopProof::create_for_moqt_action_jwt(
      moqt_action, namespace_name, track_name, endpoint_uri,
      get_algorithm_name(), public_key_jwk_, std::move(jti));

  auto signing_input = proof.create_signing_input();
  auto signature = algorithm_->sign(signing_input);

  return DpopProof{proof.get_header(), proof.get_payload(), signature,
                   DpopEncoding::JWT};
}
#endif

template <MoqtActionType ActionT>
DpopProof DpopKeyPair::generate_proof(ActionT moqt_action,
                                      std::string_view namespace_name,
                                      std::string_view track_name,
                                      std::string_view endpoint_uri,
                                      std::optional<std::string> jti,
                                      DpopEncoding encoding) const {
  if (encoding == DpopEncoding::CWT) {
    return generate_proof_cwt(moqt_action, namespace_name, track_name,
                              endpoint_uri, std::move(jti));
  }
#ifdef CATAPULT_ENABLE_JSON
  return generate_proof_jwt(moqt_action, namespace_name, track_name,
                            endpoint_uri, std::move(jti));
#else
  throw CryptoError(
      "JWT DPoP format requires CATAPULT_ENABLE_JSON. Use CWT format instead.");
#endif
}

}  // namespace catapult