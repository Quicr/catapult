/**
 * @file claims.hpp
 * @brief Typed CAT claim structures aligned with CTA-5007-B (December 2024,
 *        revised January 2025).
 *
 * Every claim below carries the CBOR type required by the specification.
 * Do not substitute std::string for values that are byte strings, maps,
 * arrays, or tagged values on the wire — a mismatched serialisation is
 * silently non-interoperable and can grant broader authorisation than the
 * issuer intended.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

#include "error.hpp"

namespace catapult {

/**
 * @defgroup ClaimIdentifiers Claim Identifiers
 * @brief Standard claim identifiers for CWT and CAT tokens
 * @{
 */

/// Core CWT claim identifiers
constexpr int64_t CLAIM_ISS = 1;  ///< Issuer claim
constexpr int64_t CLAIM_AUD = 3;  ///< Audience claim
constexpr int64_t CLAIM_EXP = 4;  ///< Expiration time claim
constexpr int64_t CLAIM_NBF = 5;  ///< Not before claim
constexpr int64_t CLAIM_CTI = 7;  ///< CWT ID claim (CBOR byte string)

// Compile-time validation of claim identifiers
static_assert(CLAIM_ISS > 0, "Claim identifiers must be positive");
static_assert(CLAIM_AUD > 0, "Claim identifiers must be positive");
static_assert(CLAIM_EXP > 0, "Claim identifiers must be positive");
static_assert(CLAIM_NBF > 0, "Claim identifiers must be positive");
static_assert(CLAIM_CTI > 0, "Claim identifiers must be positive");

/// CAT-specific claim identifiers
constexpr int64_t CLAIM_CATREPLAY = 308;      ///< uint mode (0/1/2/...)
constexpr int64_t CLAIM_CATPOR = 309;         ///< array [prob, id, ?expiry]
constexpr int64_t CLAIM_CATV = 310;           ///< uint version (1)
constexpr int64_t CLAIM_CATNIP = 311;         ///< array of tagged NIP entries
constexpr int64_t CLAIM_CATU = 312;           ///< URI-component match map
constexpr int64_t CLAIM_CATM = 313;           ///< array of method text strings
constexpr int64_t CLAIM_CATALPN = 314;        ///< array of ALPN byte strings
constexpr int64_t CLAIM_CATH = 315;           ///< header-name → match-map
constexpr int64_t CLAIM_CATGEOISO3166 = 316;  ///< array of ISO 3166 codes
constexpr int64_t CLAIM_CATGEOCOORD = 317;    ///< array [lat, lon, radius]
constexpr int64_t CLAIM_GEOHASH = 282;        ///< string OR structured array
constexpr int64_t CLAIM_CATGEOALT = 318;      ///< array [alt, ?deviation]
constexpr int64_t CLAIM_CATTPK = 319;         ///< token public key thumbprint

/// Informational Claims
constexpr int64_t CLAIM_SUB = 2;          ///< Subject claim
constexpr int64_t CLAIM_IAT = 6;          ///< Issued at claim
constexpr int64_t CLAIM_CATIFDATA = 320;  ///< string or array

/// DPoP Claims
constexpr int64_t CLAIM_CNF = 8;        ///< Confirmation map (RFC 8747)
constexpr int64_t CLAIM_CATDPOP = 321;  ///< structured DPoP settings map

/// Request Claims
constexpr int64_t CLAIM_CATIF = 322;  ///< CAT interface claim map
constexpr int64_t CLAIM_CATR = 323;   ///< CAT renewal claim map

/// Composite Claims (RFC draft-lemmons-cose-composite-claims-01)
constexpr int64_t CLAIM_OR = 324;   ///< Logical OR composite claim
constexpr int64_t CLAIM_NOR = 325;  ///< Logical NOR composite claim
constexpr int64_t CLAIM_AND = 326;  ///< Logical AND composite claim

/** @} */  // end of ClaimIdentifiers group

/**
 * @brief Input validation utilities
 */
namespace validation {
inline std::string sanitizeString(std::string_view input) {
  std::string result;
  result.reserve(input.size());
  for (char c : input) {
    if (c >= 32 || c == '\t' || c == '\n' || c == '\r') {
      result.push_back(c);
    }
  }
  return result;
}

constexpr bool isValidStringLength(std::string_view str,
                                   size_t maxLen = 1024) noexcept {
  return !str.empty() && str.size() <= maxLen;
}

inline bool isValidIssuer(std::string_view issuer) noexcept {
  return isValidStringLength(issuer, 256) &&
         issuer.find('\0') == std::string_view::npos;
}

inline bool isValidAudience(std::string_view audience) noexcept {
  return isValidStringLength(audience, 256) &&
         audience.find('\0') == std::string_view::npos;
}
}  // namespace validation

// ---------------------------------------------------------------------------
// Geographic types
// ---------------------------------------------------------------------------

/**
 * @brief Geographic coordinate (CTA-5007-B §4.6.x).
 *
 * On the wire this is a CBOR array `[latitude, longitude, radius]`. The
 * radius (metres) is the accuracy/uncertainty circle around the point; a
 * missing radius on the wire is represented by std::nullopt here.
 *
 * CTA-5007-B classifies precise coordinates as privacy-sensitive; a
 * relay accepting them SHOULD require the token to be delivered inside
 * an encrypted COSE_Encrypt0 wrapper. That check lives in the validator.
 */
struct GeoCoordinate {
  double lat = 0.0;
  double lon = 0.0;
  std::optional<double> radius;  // metres; formerly "accuracy"

  GeoCoordinate() = default;
  GeoCoordinate(double latitude, double longitude,
                std::optional<double> r = std::nullopt)
      : lat(latitude), lon(longitude), radius(r) {}

  static std::optional<GeoCoordinate> createSafe(
      double lat, double lon,
      std::optional<double> r = std::nullopt) noexcept {
    if (lat >= -90.0 && lat <= 90.0 && lon >= -180.0 && lon <= 180.0 &&
        (!r.has_value() || (r.value() >= 0.0 && r.value() <= 4e7))) {
      GeoCoordinate coord;
      coord.lat = lat;
      coord.lon = lon;
      coord.radius = r;
      return coord;
    }
    return std::nullopt;
  }

  template <int64_t LatScaled, int64_t LonScaled>
  static constexpr GeoCoordinate create_validated() noexcept {
    constexpr double lat = static_cast<double>(LatScaled) / 10000.0;
    constexpr double lon = static_cast<double>(LonScaled) / 10000.0;
    static_assert(lat >= -90.0 && lat <= 90.0, "Invalid latitude");
    static_assert(lon >= -180.0 && lon <= 180.0, "Invalid longitude");
    GeoCoordinate coord;
    coord.lat = lat;
    coord.lon = lon;
    return coord;
  }

  constexpr bool is_valid() const noexcept {
    return lat >= -90.0 && lat <= 90.0 && lon >= -180.0 && lon <= 180.0 &&
           (!radius.has_value() || radius.value() >= 0.0);
  }
};

/// CTA-5007-B `catgeoalt` — array [altitude, ?deviation] in metres.
struct GeoAltitude {
  int32_t altitude = 0;
  std::optional<int32_t> deviation;  // ± metres

  GeoAltitude() = default;
  explicit GeoAltitude(int32_t alt) : altitude(alt) {}
  GeoAltitude(int32_t alt, int32_t dev) : altitude(alt), deviation(dev) {}
};

/// CTA-5007-B `geohash` — either a plain string form OR a structured array.
/// The structured form appears in longer/encrypted contexts; keep both so
/// producers can round-trip issuer input without losing type information.
struct GeohashClaimValue {
  std::variant<std::string, std::vector<std::string>> value;

  GeohashClaimValue() : value(std::string{}) {}
  /*implicit*/ GeohashClaimValue(std::string s) : value(std::move(s)) {}
  /*implicit*/ GeohashClaimValue(std::vector<std::string> v)
      : value(std::move(v)) {}

  bool isString() const noexcept {
    return std::holds_alternative<std::string>(value);
  }
  const std::string& asString() const { return std::get<std::string>(value); }
  const std::vector<std::string>& asArray() const {
    return std::get<std::vector<std::string>>(value);
  }
};

// ---------------------------------------------------------------------------
// CAT `catpor` — proof of possession requirement
// ---------------------------------------------------------------------------

/**
 * @brief CTA-5007-B §4.6.x `catpor`: [probability, identifier, ?expiry].
 *
 * `probability` is the fraction of requests the recipient MUST validate
 * proof-of-possession on (0.0 to 1.0). `identifier` is the issuer's block
 * list identifier bytes. `expiry` (optional) is a POSIX timestamp after
 * which the block list check is no longer required.
 */
struct CatProofOfPossession {
  double probability = 1.0;
  std::vector<uint8_t> identifier;
  std::optional<int64_t> expiry;

  bool is_valid() const noexcept {
    return probability >= 0.0 && probability <= 1.0 && !identifier.empty();
  }
};

// ---------------------------------------------------------------------------
// CAT `catreplay` — replay-protection mode enum
// ---------------------------------------------------------------------------

/// CTA-5007-B §4.6.9 replay-protection modes.
enum class CatReplayMode : uint32_t {
  None = 0,           ///< Recipient MAY replay
  RejectOnReplay = 1, ///< Recipient MUST reject duplicate CTI
  RevokeOnReplay = 2, ///< Recipient MUST revoke on duplicate CTI
};

// ---------------------------------------------------------------------------
// CAT `catnip` — tagged network-interface-parameter entries
// ---------------------------------------------------------------------------

/// One entry of `catnip`. `tag` is the CBOR tag identifier assigned by the
/// draft (e.g. IPv4/IPv6/ASN); `value` is the tagged byte string. Consumers
/// MUST NOT interpret the value without checking the tag.
struct CatNipEntry {
  uint64_t tag = 0;
  std::vector<uint8_t> value;
};

// ---------------------------------------------------------------------------
// CAT `catu` — URI-component match map
// ---------------------------------------------------------------------------

/// CTA-5007-B §4.6.10 URI-component match type discriminant.
enum class UriMatchType : uint32_t {
  Exact = 0,
  Prefix = 1,
  Suffix = 2,
  Contains = 3,
  Regex = 4,
  SHA256 = 5,
  SHA512_256 = 6,
};

/// A single component match: `[type, value_bytes]`.
struct UriComponentMatch {
  UriMatchType type = UriMatchType::Exact;
  std::vector<uint8_t> value;
};

/// CTA-5007-B `catu` — map from component label (int) to component match.
/// Component labels: 0 scheme, 1 host, 2 port, 3 path, 4 query, 5 parent-path,
/// 6 filename, 7 stem, 8 extension. Full matcher lives under task #20 (H-03);
/// this struct only preserves the wire form.
struct CatUriMatchMap {
  std::unordered_map<int64_t, UriComponentMatch> components;

  bool empty() const noexcept { return components.empty(); }
};

// ---------------------------------------------------------------------------
// CAT `cath` — header name → header value match
// ---------------------------------------------------------------------------

/// Match against one HTTP header. `name` is the header field name (ASCII);
/// `match` is a UriComponentMatch reused for the value.
struct CatHeaderMatch {
  std::string name;
  UriComponentMatch match;
};

/// CTA-5007-B `cath` — array of header-name→match entries. Multiple entries
/// with the same header name imply AND semantics.
struct CatHostHeaderMatchList {
  std::vector<CatHeaderMatch> entries;

  bool empty() const noexcept { return entries.empty(); }
};

// ---------------------------------------------------------------------------
// RFC 8747 `cnf` — confirmation claim
// ---------------------------------------------------------------------------

/**
 * @brief RFC 8747 §3.1 confirmation claim.
 *
 * Common forms carried today:
 *  - `jkt`  (label 3): SHA-256 thumbprint of a JWK (byte string).
 *  - `kid`  (label 3): key identifier when `jwk` is absent.
 *  - raw thumbprint bytes: used when a JWK is referenced by digest only.
 *
 * We currently model the two forms most CAT deployments emit. Additional
 * forms (`jwk`, `x5u`) round-trip as opaque map bytes in `raw` and can be
 * introspected via [[cnf-jwk-decoding]].
 */
struct CatConfirmation {
  std::optional<std::vector<uint8_t>> jkt;  ///< JWK SHA-256 thumbprint
  std::optional<std::string> kid;           ///< key identifier
  std::optional<std::vector<uint8_t>> raw;  ///< opaque map bytes for unknown forms
};

// ---------------------------------------------------------------------------
// `catdpop` — structured DPoP settings
// ---------------------------------------------------------------------------

/**
 * @brief CTA-5007-B `catdpop` — DPoP proof requirements delivered inside a
 *        CAT token. Fields correspond to the map keys in the draft.
 */
struct CatDpopSettings {
  std::optional<std::vector<int64_t>> critical;      ///< required proof fields
  std::optional<int64_t> proof_lifetime_seconds;     ///< acceptance window
  std::optional<std::vector<uint8_t>> jti_challenge; ///< server challenge
  std::optional<std::vector<uint8_t>> raw;           ///< opaque residual bytes
};

// ---------------------------------------------------------------------------
// `catif` / `catr` — request-context claims
// ---------------------------------------------------------------------------

/**
 * @brief `catifdata` — either a text string or a CBOR array. Preserves the
 *        wire form so relay-side interface authorisation can match on the
 *        exact type the issuer chose.
 */
struct CatIfData {
  std::variant<std::string, std::vector<std::string>> value;

  CatIfData() : value(std::string{}) {}
  /*implicit*/ CatIfData(std::string s) : value(std::move(s)) {}
  /*implicit*/ CatIfData(std::vector<std::string> v) : value(std::move(v)) {}

  bool isString() const noexcept {
    return std::holds_alternative<std::string>(value);
  }
  const std::string& asString() const { return std::get<std::string>(value); }
  const std::vector<std::string>& asArray() const {
    return std::get<std::vector<std::string>>(value);
  }
};

/// CTA-5007-B `catif`/`catr` — request/renewal directives modeled as an
/// opaque map with typed accessors as the draft firms up. For now we
/// preserve the map bytes so downstream verifiers can inspect them.
struct CatRequestDirective {
  std::vector<uint8_t> raw;

  bool empty() const noexcept { return raw.empty(); }
};

// ---------------------------------------------------------------------------
// Core / grouped claim structs
// ---------------------------------------------------------------------------

/**
 * @brief Core CWT claims.
 *
 * `cti` is a CBOR **byte string** per RFC 8392 §3.1.7 — not a text string.
 * Previously the model used std::string which lost the byte semantics on
 * serialisation. Callers that used to store an ASCII identifier can
 * continue to do so by copying its bytes into the vector.
 */
struct CoreClaims {
  std::optional<std::string> iss;
  std::optional<std::vector<std::string>> aud;
  std::optional<int64_t> exp;
  std::optional<int64_t> nbf;
  std::optional<std::vector<uint8_t>> cti;

  CoreClaims() = default;
  CoreClaims(const CoreClaims&) = default;
  CoreClaims(CoreClaims&&) noexcept = default;
  CoreClaims& operator=(const CoreClaims&) = default;
  CoreClaims& operator=(CoreClaims&&) noexcept = default;

  void setIssuer(std::string_view issuer) {
    if (!validation::isValidIssuer(issuer)) {
      throw InvalidClaimValueError("Invalid issuer format");
    }
    iss = validation::sanitizeString(issuer);
  }

  void addAudience(std::string_view audience) {
    if (!validation::isValidAudience(audience)) {
      throw InvalidClaimValueError("Invalid audience format");
    }
    if (!aud.has_value()) {
      aud = std::vector<std::string>{};
      aud->reserve(4);
    }
    aud->emplace_back(validation::sanitizeString(audience));
  }

  /// Convenience: set `cti` from a UTF-8 string. The bytes go on the wire
  /// unchanged; the type on the wire is still a CBOR byte string.
  void setCwtIdFromString(std::string_view id) {
    cti = std::vector<uint8_t>(id.begin(), id.end());
  }
};

/**
 * @brief Informational claims.
 */
struct InformationalClaims {
  std::optional<std::string> sub;
  std::optional<int64_t> iat;
  std::optional<CatIfData> catifdata;

  InformationalClaims() = default;
  InformationalClaims(const InformationalClaims&) = default;
  InformationalClaims(InformationalClaims&&) noexcept = default;
  InformationalClaims& operator=(const InformationalClaims&) = default;
  InformationalClaims& operator=(InformationalClaims&&) noexcept = default;

  void setSubject(std::string_view subject) {
    if (!validation::isValidStringLength(subject, 256)) {
      throw InvalidClaimValueError("Invalid subject format");
    }
    sub = validation::sanitizeString(subject);
  }
};

/**
 * @brief DPoP-related claims.
 */
struct DpopClaims {
  std::optional<CatConfirmation> cnf;
  std::optional<CatDpopSettings> catdpop;

  DpopClaims() = default;
  DpopClaims(const DpopClaims&) = default;
  DpopClaims(DpopClaims&&) noexcept = default;
  DpopClaims& operator=(const DpopClaims&) = default;
  DpopClaims& operator=(DpopClaims&&) noexcept = default;
};

/**
 * @brief Request-specific claims.
 */
struct RequestClaims {
  std::optional<CatRequestDirective> catif;
  std::optional<CatRequestDirective> catr;

  RequestClaims() = default;
  RequestClaims(const RequestClaims&) = default;
  RequestClaims(RequestClaims&&) noexcept = default;
  RequestClaims& operator=(const RequestClaims&) = default;
  RequestClaims& operator=(RequestClaims&&) noexcept = default;
};

/**
 * @brief CAT-specific claims — every field carries the type CTA-5007-B
 *        requires on the wire.
 */
struct CatClaims {
  std::optional<CatReplayMode> catreplay;               ///< uint mode
  std::optional<CatProofOfPossession> catpor;           ///< [prob, id, ?exp]
  std::optional<uint32_t> catv;                         ///< uint version
  std::optional<std::vector<CatNipEntry>> catnip;       ///< tagged NIP entries
  std::optional<CatUriMatchMap> catu;                   ///< URI component match
  std::optional<std::vector<std::string>> catm;         ///< HTTP methods
  std::optional<std::vector<std::vector<uint8_t>>> catalpn;  ///< ALPN byte strs
  std::optional<CatHostHeaderMatchList> cath;           ///< header matches
  std::optional<std::vector<std::string>> catgeoiso3166;
  std::optional<GeoCoordinate> catgeocoord;             ///< [lat, lon, radius]
  std::optional<GeohashClaimValue> geohash;
  std::optional<GeoAltitude> catgeoalt;                 ///< [alt, ?deviation]
  std::optional<std::vector<uint8_t>> cattpk;           ///< pubkey thumbprint
};

}  // namespace catapult
