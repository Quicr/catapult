/**
 * @file cat_dpop.hpp
 * @brief DPoP (Demonstrating Proof-of-Possession) support for CAT tokens
 *
 * This file implements DPoP functionality as defined in
 * https://www.ietf.org/archive/id/draft-nandakumar-moq-generic-dpop-proof-00.html
 * and integrated with CAT tokens according to draft-ietf-moq-c4m-01
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
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

#include "claims.hpp"
#include "crypto.hpp"
#include "error.hpp"
#include "moqt_claims.hpp"
#include "replay_store.hpp"

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

  // MOQT actions differ in what portion of the resource identifier is
  // meaningful:
  //   - CLIENT_SETUP / SERVER_SETUP address the endpoint itself; there is
  //     no namespace or track to bind to.
  //   - PUBLISH_NAMESPACE / SUBSCRIBE_NAMESPACE authorize an entire
  //     namespace and have no per-track identity.
  //   - SUBSCRIBE / REQUEST_UPDATE / PUBLISH / FETCH / TRACK_STATUS act on
  //     a specific track and require both.
  // A single "tns and tn are required" rule would reject correct proofs
  // for setup and namespace-scoped actions.
  [[nodiscard]] bool is_valid() const noexcept {
    if (type.empty() || action < 0) {
      return false;
    }
    switch (action) {
      case 0:  // CLIENT_SETUP
      case 1:  // SERVER_SETUP
        return true;
      case 2:  // PUBLISH_NAMESPACE
      case 3:  // SUBSCRIBE_NAMESPACE
        return !tns.empty();
      default:
        return !tns.empty() && !tn.empty();
    }
  }
};

/**
 * @brief DPoP payload claims (Application-Agnostic Framework)
 */
struct DpopPayload {
  std::optional<std::string> jti;  ///< JWT ID for replay protection
  AuthorizationContext actx;       ///< Authorization context
  // `iat` is intentionally optional: `std::nullopt` distinguishes "the
  // wire form did not carry an `iat` claim" from "iat present and zero".
  // The deserializer MUST NOT synthesise a value (e.g. Clock::now()) for
  // a missing claim — doing so silently lets an unauthenticated proof
  // pass `is_fresh()`, which reads back exactly the value that was
  // synthesised a moment earlier. `is_valid()` and `is_fresh()` fail
  // closed when this is unset. Producer paths still default-initialise
  // `iat` to the current time so a freshly-constructed payload stays
  // signable.
  std::optional<int64_t> iat;
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
    return actx.is_valid() && iat.has_value() && *iat > 0;
  }

  /**
   * @brief Check if timestamp is within acceptable window
   * @note Rejects future timestamps beyond a small clock skew tolerance
   */
  [[nodiscard]] bool is_fresh(
      std::chrono::seconds window = std::chrono::seconds{300},
      std::chrono::seconds future_tolerance = std::chrono::seconds{
          60}) const noexcept {
    // No `iat` on the wire ⇒ we have no freshness anchor. Fail closed
    // rather than treat "unknown" as "fresh": a proof that omitted iat
    // cannot be replayed against a window we never measured.
    if (!iat.has_value()) {
      return false;
    }
    auto now =
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    // Reject timestamps too far in the future (prevents pre-generated proofs)
    if (*iat > now + future_tolerance.count()) {
      return false;
    }
    // Check if timestamp is within the past window
    auto age = now - *iat;
    return age >= 0 && age <= window.count();
  }
};

/**
 * @brief DPoP proof-validator configuration.
 *
 * Validator-side tuning (window, JTI cache size) — not the on-wire
 * `catdpop` claim. The wire-form struct is `catapult::CatDpopSettings` in
 * `claims.hpp`.
 */
struct DpopValidationSettings {
  std::optional<std::chrono::seconds>
      window;                     ///< Time window for proof validity
  std::optional<bool> honor_jti;  ///< Whether to honor JTI claims
  std::optional<size_t>
      max_jti_entries;  ///< Max JTI cache size for replay protection
  std::optional<size_t> jti_cleanup_interval;  ///< How often to run JTI cleanup
  std::vector<int>
      critical_settings;  ///< Critical settings that must be understood
  // Allowlist of COSE algorithm identifiers accepted for the DPoP proof
  // header `alg` (RFC 9449 §4.1 requires asymmetric algorithms). Empty ⇒
  // use the built-in safe default `{ALG_ES256}`. Populating the set
  // narrows or widens the accepted set — but symmetric algorithms
  // (`ALG_HMAC256_256`) and the sentinel `0` (representing `alg: none`)
  // MUST NOT be added: a proof signed with a symmetric key cannot
  // demonstrate proof-of-possession because the verifier holds the same
  // secret used to sign it. The allowlist is checked *before* the
  // signature verifier is invoked so a rogue `alg` cannot even provoke
  // key-material handling.
  std::unordered_set<int64_t> allowed_dpop_algorithms;
  // Maximum number of parsed JWK → `CryptographicAlgorithm` entries the
  // validator will retain across proofs. JWK import (BIGNUM decode,
  // OSSL_PARAM_BLD, EVP_PKEY_fromdata, DER round-trip) is measurably
  // more expensive than the ECDSA verify itself; caching by JWK
  // thumbprint (SHA-256 of the RFC 7638 canonical form) turns each
  // repeat-client validation from three parsing passes into one. The
  // cache is bounded — an attacker who rotated JWKs endlessly would
  // otherwise pin arbitrary memory in the relay. `0` disables the cache
  // (imports every time); `std::nullopt` uses the built-in default of
  // 256 keys, which fits ~64 KiB in typical deployments.
  std::optional<size_t> parsed_key_cache_max_size;

  /**
   * @brief Default constructor with reasonable defaults
   */
  DpopValidationSettings() = default;

  /**
   * @brief Constructor with window setting
   */
  explicit DpopValidationSettings(std::chrono::seconds time_window)
      : window(time_window), honor_jti(true) {}

  /**
   * @brief Set window setting
   */
  void set_window(std::chrono::seconds time_window) { window = time_window; }

  /**
   * @brief Set JTI *replay-tracking* preference.
   *
   * This knob controls whether the validator consults the ReplayStore
   * on `jti` — it does NOT control whether `jti` is required on the
   * wire. RFC 9449 §4.2 and draft-nandakumar-moq-generic-dpop-proof-00
   * §3.2 both make `jti` a MUST-be-present claim on the proof payload,
   * and `validate_proof` enforces that unconditionally: a jti-less
   * proof is refused even when this knob is `false`. Setting it to
   * `false` is a legitimate opt-out only for deployments that have an
   * out-of-band replay defence — for example, a shared cache upstream
   * of this validator — and want to skip the per-request replay-store
   * roundtrip without weakening wire compliance.
   */
  void set_jti_processing(bool honor) { honor_jti = honor; }

  /**
   * @brief Replace the DPoP proof algorithm allowlist.
   *
   * Passing an empty set restores the built-in default (`{ALG_ES256}`).
   * The set MUST NOT contain symmetric or `none`-equivalent algorithms;
   * `is_dpop_algorithm_allowed()` explicitly refuses `ALG_HMAC256_256`
   * and the sentinel `0` regardless of what the caller placed here, so
   * misconfiguration cannot silently weaken proof-of-possession.
   *
   * The intended way to *widen* the set is to add other asymmetric
   * identifiers once the underlying `createAlgorithmFromJWK` /
   * CWT-verifier plumbing gains support for them (RS256, PS256, EdDSA,
   * etc.). Until then only ES256 will actually verify — the allowlist
   * is the policy layer, not the algorithm implementation.
   */
  void set_allowed_dpop_algorithms(std::unordered_set<int64_t> algs) {
    allowed_dpop_algorithms = std::move(algs);
  }

  /**
   * @brief Check whether an incoming proof's `alg` is permitted.
   *
   * A hard blocklist rejects `ALG_HMAC256_256` (symmetric — cannot prove
   * possession) and `0` (unregistered / the CWT `alg: none` sentinel)
   * before consulting the allowlist. The remaining algorithms are
   * accepted only if the configured allowlist (or its default of
   * `{ALG_ES256}`) contains them.
   */
  [[nodiscard]] bool is_dpop_algorithm_allowed(int64_t alg_id) const noexcept {
    // Hard-blocked identifiers stay blocked even if a caller adds them
    // to the allowlist by mistake — proof-of-possession semantics
    // require an asymmetric algorithm.
    if (alg_id == 0 || alg_id == ALG_HMAC256_256) {
      return false;
    }
    if (allowed_dpop_algorithms.empty()) {
      return alg_id == ALG_ES256;
    }
    return allowed_dpop_algorithms.find(alg_id) !=
           allowed_dpop_algorithms.end();
  }

  /**
   * @brief Set maximum JTI cache entries for replay protection
   * @param max_entries Maximum number of JTIs to track (default 1M)
   */
  void set_max_jti_entries(size_t max_entries) {
    max_jti_entries = max_entries;
  }

  /**
   * @brief Set JTI cleanup interval
   * @param interval Run cleanup every N insertions (default 10000)
   */
  void set_jti_cleanup_interval(size_t interval) {
    jti_cleanup_interval = interval;
  }

  /**
   * @brief Set maximum entries in the validator's parsed-key cache.
   * @param max_entries `0` disables caching entirely. Values > 0 bound
   *        the cache; the least-recently-used entry is evicted on
   *        overflow. Default (unset) is 256.
   */
  void set_parsed_key_cache_max_size(size_t max_entries) {
    parsed_key_cache_max_size = max_entries;
  }

  /**
   * @brief Get the effective parsed-key cache size (default 256).
   */
  [[nodiscard]] size_t get_parsed_key_cache_max_size() const noexcept {
    return parsed_key_cache_max_size.value_or(256);
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

  /**
   * @brief Get max JTI entries (default 1M for large-scale deployments)
   */
  [[nodiscard]] size_t get_max_jti_entries() const noexcept {
    return max_jti_entries.value_or(1000000);
  }

  /**
   * @brief Overlay an on-wire `CatDpopSettings` binding onto this
   *        validator config.
   *
   * The token's `catdpop` claim declares the *policy the issuer wants
   * enforced* — an acceptance-window ceiling and whether replay tracking
   * on `jti` is mandatory. The relay side owns the *validator-side
   * knobs* — JTI cache sizing, cleanup interval, critical-setting
   * requirements. Only the fields present on the wire form are copied,
   * so a relay can start from a hardened baseline (this instance) and
   * tighten it per-token from the on-wire binding.
   *
   * The window is tightened: if the token requests a shorter window than
   * the current setting, the token wins. If the token requests a longer
   * window than the current setting the current (relay-set) window is
   * preserved — the relay's ceiling is not weakened by a permissive
   * token. Similarly, `honor_jti=true` from the token overrides a
   * validator that had it off, but a token setting `honor_jti=false`
   * does NOT relax a validator that had it on.
   *
   * This is the intended binding point between token state and DPoP
   * validation behaviour (audit R-16). The library does not call this
   * automatically — a relay that wants issuer-declared tightening
   * invokes it explicitly, typically from
   * `AuthorizationPolicyHook::acceptDpopBinding` against its per-request
   * settings before the DPoP proof is verified. Callers who want the
   * exact on-wire values without a floor should overwrite fields
   * directly.
   */
  void overlayCatDpopSettings(const CatDpopSettings& wire) noexcept {
    if (wire.window_seconds.has_value() && *wire.window_seconds > 0) {
      const std::chrono::seconds requested{*wire.window_seconds};
      if (!window.has_value() || requested < *window) {
        window = requested;
      }
    }
    if (wire.honor_jti.value_or(false)) {
      // Token demands replay tracking; enable if not already enabled.
      honor_jti = true;
    }
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
  // Original wire signing input as it was signed by the issuer. For JWT
  // proofs this is `base64url(header) "." base64url(payload)` taken
  // verbatim from the wire; for CWT proofs it is the Sig_structure
  // computed from the wire-protected header and wire payload bytes. This
  // is populated on deserialization so that verification checks the
  // exact bytes that were signed rather than a re-serialization from the
  // parsed struct — otherwise re-canonicalising JSON (key order, escape
  // rules, whitespace) or CBOR fields can silently break signature
  // matching or, worse, produce a re-serialization that still verifies
  // even though the wire had been tampered with (HN-03).
  std::vector<uint8_t> wire_signing_input_;

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
   * @brief Set the original wire signing input (used by deserializers).
   *
   * Verifiers use these bytes verbatim so that signature checks bind to
   * the exact bytes that were signed.
   */
  void set_wire_signing_input(std::vector<uint8_t> bytes) {
    wire_signing_input_ = std::move(bytes);
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
      const DpopValidationSettings& settings = {}) const noexcept {
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
      return "PUBLISH_NAMESPACE";
    case 3:
      return "SUBSCRIBE_NAMESPACE";
    case 4:
      return "SUBSCRIBE";
    case 5:
      return "REQUEST_UPDATE";
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

// CAT-4-MOQT (draft-ietf-moq-c4m-01) §DPoP resource identifiers: the
// resource URI is `moqt://<endpoint>` with the track namespace and track
// name carried as `tns` / `tn` query parameters. The earlier path form
// (`moqt://endpoint/ns/track`) is ambiguous — a slash inside a
// namespace segment is indistinguishable from a namespace / track
// separator — and is not what the draft actually specifies.
//
// Percent-encode any character that is not unreserved per RFC 3986 §2.3.
// This is intentionally narrow: we only need enough encoding to survive
// the query string, not full IRI treatment.
namespace detail {
[[nodiscard]] inline std::string percent_encode_query_component(
    std::string_view v) {
  auto is_unreserved = [](unsigned char c) noexcept -> bool {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
           c == '~';
  };
  std::string out;
  out.reserve(v.size());
  for (char raw : v) {
    // `std::string_view::value_type` is `char`; `is_unreserved` and the
    // hex-lookup arithmetic below both require an unsigned byte to avoid
    // implementation-defined behaviour on negative `char` values.
    const auto c = static_cast<unsigned char>(raw);
    if (is_unreserved(c)) {
      out.push_back(static_cast<char>(c));
    } else {
      static constexpr char hex[] = "0123456789ABCDEF";
      out.push_back('%');
      out.push_back(hex[c >> 4]);
      out.push_back(hex[c & 0x0f]);
    }
  }
  return out;
}
}  // namespace detail

/**
 * @brief Construct a MOQT resource URI in the CAT-4-MOQT draft form.
 *
 * Output is `moqt://<endpoint>` optionally followed by `?tns=<...>` and
 * `&tn=<...>` when the caller supplies those components. Setup actions
 * (CLIENT_SETUP / SERVER_SETUP) pass empty namespace and track and get an
 * endpoint-only URI back.
 */
[[nodiscard]] inline std::string construct_moqt_uri(
    std::string_view endpoint, std::string_view namespace_name = {},
    std::string_view track_name = {}) {
  std::string uri = "moqt://";
  uri += endpoint;

  const bool has_ns = !namespace_name.empty();
  const bool has_tn = !track_name.empty();
  if (!has_ns && !has_tn) {
    return uri;
  }

  uri += '?';
  bool needs_amp = false;
  if (has_ns) {
    uri += "tns=";
    uri += detail::percent_encode_query_component(namespace_name);
    needs_amp = true;
  }
  if (has_tn) {
    if (needs_amp) {
      uri += '&';
    }
    uri += "tn=";
    uri += detail::percent_encode_query_component(track_name);
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
 *
 * Replay detection is delegated to a pluggable `ReplayStore`. By default
 * the validator instantiates an in-memory store sized from `settings`; to
 * share state across processes or to survive restarts, construct the
 * validator with an external store implementation.
 */
class DpopProofValidator {
 private:
  DpopValidationSettings settings_;
  std::shared_ptr<ReplayStore> replay_store_;
  // Optional external verifier used for CWT-encoded proofs (which do not
  // carry an algorithm resolvable from their protected header alone). Set
  // via `set_cwt_verifier()`. When null and the proof is CWT-encoded, the
  // validator fails closed rather than silently skipping signature check.
  const CryptographicAlgorithm* cwt_verifier_{nullptr};

  // Bounded LRU cache from JWK thumbprint → parsed `CryptographicAlgorithm`.
  // JWK import is roughly an order of magnitude more expensive than the
  // ECDSA verify it enables; caching avoids re-parsing the same client
  // key on every proof from that client. Bounding + LRU eviction keeps a
  // rotation-heavy peer from pinning arbitrary memory.
  //
  // Rotation-aware identity: entries are keyed by the SHA-256 thumbprint
  // of the RFC 7638 canonical JWK form. A rotated key produces a fresh
  // thumbprint → fresh entry; the old entry ages out via LRU. No
  // time-based invalidation is needed because the identity is
  // content-derived — a stale entry cannot silently start referring to
  // different key material.
  struct ParsedKeyEntry {
    std::string thumbprint;
    std::shared_ptr<CryptographicAlgorithm> algorithm;
  };
  using LruList = std::list<ParsedKeyEntry>;
  mutable std::mutex parsed_key_cache_mu_;
  mutable LruList parsed_key_lru_;
  mutable std::unordered_map<std::string, LruList::iterator> parsed_key_index_;

  // Look up (or import + cache) the `CryptographicAlgorithm` for a JWT
  // DPoP proof. Non-owning `shared_ptr` — the cache retains ownership.
  // Returns null on unusable material (unsupported alg, malformed JWK,
  // cache disabled + import failure).
  std::shared_ptr<CryptographicAlgorithm> get_or_import_jwk_algorithm(
      const std::string& alg_name, const std::string& jwk_json);

 public:
  /**
   * @brief Construct with settings and a default in-memory replay store.
   *
   * The store is sized from `settings.get_max_jti_entries()` and its
   * cleanup interval from `settings.get_jti_cleanup_interval()`.
   */
  explicit DpopProofValidator(DpopValidationSettings settings = {})
      : settings_(std::move(settings)),
        replay_store_(std::make_shared<InMemoryReplayStore>(
            settings_.get_max_jti_entries(),
            settings_.get_jti_cleanup_interval())) {}

  /**
   * @brief Construct with settings and a caller-supplied replay store.
   *
   * Use this overload to plug in an external backend (Redis, database,
   * etc.) that persists replay state across process restarts or shares it
   * across relay instances. The store must be non-null; a null pointer
   * would silently disable replay protection and is rejected as a
   * programming error.
   */
  DpopProofValidator(DpopValidationSettings settings,
                     std::shared_ptr<ReplayStore> store)
      : settings_(std::move(settings)), replay_store_(std::move(store)) {
    if (!replay_store_) {
      throw InvalidClaimValueError(
          "DpopProofValidator requires a non-null replay store");
    }
  }

  /**
   * @brief Register the verifier used for CWT-encoded DPoP proofs.
   *
   * Required for CWT proofs: the COSE_Key present in the proof header
   * carries public key material but not the algorithm binding needed by
   * `CryptographicAlgorithm::verify`. Pass the algorithm instance that
   * matches the expected key (typically resolved from the CAT's `cnf.jkt`
   * out of band).
   *
   * Passing `nullptr` disables CWT verification, which will cause
   * `validate_proof` to reject every CWT-encoded proof. JWT-encoded proofs
   * are unaffected — they self-resolve their algorithm from the embedded
   * JWK.
   */
  void set_cwt_verifier(const CryptographicAlgorithm* verifier) noexcept {
    cwt_verifier_ = verifier;
  }

  /**
   * @brief Validate DPoP proof.
   *
   * CTA-5007-B / CAT-4-MOQT: signature verification is MANDATORY. This
   * method fails closed if the proof signature cannot be verified —
   * including the case where a CWT-encoded proof is submitted without a
   * verifier having been configured via `set_cwt_verifier`.
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
   * @brief Drop expired jtis from the replay store.
   */
  void cleanup_expired_jtis();

  /**
   * @brief Access the underlying replay store (for observability / tests).
   */
  [[nodiscard]] ReplayStore& replay_store() const noexcept {
    return *replay_store_;
  }

  /**
   * @brief Current number of entries in the parsed-key cache.
   *
   * Exposed for tests and metrics; not part of the wire contract.
   */
  [[nodiscard]] size_t parsed_key_cache_size() const noexcept {
    std::lock_guard<std::mutex> lock(parsed_key_cache_mu_);
    return parsed_key_lru_.size();
  }

  /**
   * @brief Get current settings
   */
  [[nodiscard]] const DpopValidationSettings& get_settings() const noexcept {
    return settings_;
  }

  /**
   * @brief Replace the validator's live settings.
   *
   * ## Concurrency contract — not atomic with in-flight validations
   *
   * `settings_` is a plain member, not an atomic snapshot. A concurrent
   * `validate_proof()` call that has already read one field (e.g. the
   * acceptance window) but has not yet read another (e.g.
   * `honor_jti`) may observe a mix of pre- and post-update values.
   * The library does not guarantee atomic visibility.
   *
   * Consequences for operators:
   *   - Use this method during admin / reload windows (ACL rotation,
   *     policy push), not on the request hot path.
   *   - If a settings change must be visible to every in-flight
   *     request atomically, drain in-flight requests through a
   *     higher-level barrier (e.g. quiesce the dispatcher) before
   *     calling.
   *   - For per-token tightening driven by the wire form, prefer
   *     `DpopValidationSettings::overlayCatDpopSettings()` on a
   *     request-scoped copy rather than mutating the shared instance.
   */
  void update_settings(DpopValidationSettings new_settings) {
    settings_ = std::move(new_settings);
  }
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
   * @brief Access the algorithm bound to this key pair.
   *
   * Intended for callers that need to hand a verifier to
   * `DpopProofValidator::set_cwt_verifier()` when validating CWT proofs
   * signed by this key pair. The returned reference is owned by this
   * object; do not outlive the DpopKeyPair.
   */
  [[nodiscard]] const CryptographicAlgorithm& get_algorithm() const noexcept {
    return *algorithm_;
  }

  /**
   * @brief Get algorithm name (e.g., "ES256")
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
  std::optional<DpopValidationSettings> catdpop;  ///< CAT DPoP settings

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
  void set_dpop_settings(DpopValidationSettings settings) {
    catdpop = std::move(settings);
  }

  /**
   * @brief Get effective DPoP settings
   */
  [[nodiscard]] DpopValidationSettings get_effective_settings() const {
    return catdpop.value_or(DpopValidationSettings{});
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