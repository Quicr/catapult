/**
 * @file cat_claims.hpp
 * @brief Core claim definitions and structures for CAT tokens
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
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
constexpr int64_t CLAIM_CTI = 7;  ///< CWT ID claim

// Compile-time validation of claim identifiers
static_assert(CLAIM_ISS > 0, "Claim identifiers must be positive");
static_assert(CLAIM_AUD > 0, "Claim identifiers must be positive");
static_assert(CLAIM_EXP > 0, "Claim identifiers must be positive");
static_assert(CLAIM_NBF > 0, "Claim identifiers must be positive");
static_assert(CLAIM_CTI > 0, "Claim identifiers must be positive");

/// CAT-specific claim identifiers
constexpr int64_t CLAIM_CATREPLAY = 308;    ///< CAT replay protection
constexpr int64_t CLAIM_CATPOR = 309;       ///< CAT proof of possession
constexpr int64_t CLAIM_CATV = 310;         ///< CAT version
constexpr int64_t CLAIM_CATNIP = 311;       ///< CAT network interfaces
constexpr int64_t CLAIM_CATU = 312;         ///< CAT usage limit
constexpr int64_t CLAIM_CATM = 313;         ///< CAT methods
constexpr int64_t CLAIM_CATALPN = 314;      ///< CAT ALPN protocols
constexpr int64_t CLAIM_CATH = 315;         ///< CAT hosts
constexpr int64_t CLAIM_CATGEOISO3166 = 316;///< CAT geographic ISO 3166
constexpr int64_t CLAIM_CATGEOCOORD = 317;  ///< CAT geographic coordinates
constexpr int64_t CLAIM_GEOHASH = 282;      ///< Geohash claim
constexpr int64_t CLAIM_CATGEOALT = 318;    ///< CAT geographic altitude
constexpr int64_t CLAIM_CATTPK = 319;       ///< CAT token public key

/// Informational Claims
constexpr int64_t CLAIM_SUB = 2;         ///< Subject claim
constexpr int64_t CLAIM_IAT = 6;         ///< Issued at claim
constexpr int64_t CLAIM_CATIFDATA = 320; ///< CAT interface data

/// DPoP Claims
constexpr int64_t CLAIM_CNF = 8;       ///< Confirmation claim
constexpr int64_t CLAIM_CATDPOP = 321; ///< CAT DPoP claim

/// Request Claims
constexpr int64_t CLAIM_CATIF = 322; ///< CAT interface claim
constexpr int64_t CLAIM_CATR = 323;  ///< CAT request claim

/// Composite Claims (RFC draft-lemmons-cose-composite-claims-01)
constexpr int64_t CLAIM_OR = 324;  ///< Logical OR composite claim
constexpr int64_t CLAIM_NOR = 325; ///< Logical NOR composite claim
constexpr int64_t CLAIM_AND = 326; ///< Logical AND composite claim

/** @} */ // end of ClaimIdentifiers group


/**
 * @brief Input validation utilities
 */
namespace validation {
  /**
   * @brief Sanitize string input by removing dangerous characters
   */
  inline std::string sanitizeString(std::string_view input) {
    std::string result;
    result.reserve(input.size());
    for (char c : input) {
      // Remove control characters except tab, newline, carriage return
      if (c >= 32 || c == '\t' || c == '\n' || c == '\r') {
        result.push_back(c);
      }
    }
    return result;
  }
  
  /**
   * @brief Validate string length
   */
  constexpr bool isValidStringLength(std::string_view str, size_t maxLen = 1024) noexcept {
    return !str.empty() && str.size() <= maxLen;
  }
  
  /**
   * @brief Validate issuer format (simple validation)
   */
  inline bool isValidIssuer(std::string_view issuer) noexcept {
    return isValidStringLength(issuer, 256) && issuer.find('\0') == std::string_view::npos;
  }
  
  /**
   * @brief Validate audience format
   */
  inline bool isValidAudience(std::string_view audience) noexcept {
    return isValidStringLength(audience, 256) && audience.find('\0') == std::string_view::npos;
  }
}

/**
 * @brief Geographic coordinate representation with enhanced validation
 */
struct GeoCoordinate {
  double lat;  ///< Latitude
  double lon;  ///< Longitude
  std::optional<double> accuracy;  ///< Optional accuracy in meters

  /**
   * @brief Construct a geographic coordinate (validation happens during token validation)
   * @param latitude Latitude in degrees
   * @param longitude Longitude in degrees
   * @param acc Optional accuracy in meters
   */
  GeoCoordinate(double latitude, double longitude,
                std::optional<double> acc = std::nullopt)
      : lat(latitude), lon(longitude), accuracy(acc) {
    // Note: Validation is deferred to token validation stage
  }
  
  /**
   * @brief Static factory for validated coordinates with compile-time checks
   * Template parameters are scaled by 10000 to avoid floating point template issues
   */
  template<int64_t LatScaled, int64_t LonScaled>
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
  
  /**
   * @brief Safe factory method with validation
   */
  static std::optional<GeoCoordinate> createSafe(double lat, double lon, 
                                               std::optional<double> acc = std::nullopt) noexcept {
    if (lat >= -90.0 && lat <= 90.0 && lon >= -180.0 && lon <= 180.0) {
      GeoCoordinate coord;
      coord.lat = lat;
      coord.lon = lon;
      coord.accuracy = acc;
      return coord;
    }
    return std::nullopt;
  }
  
  constexpr GeoCoordinate() = default;

  constexpr bool is_valid() const noexcept {
    return lat >= -90.0 && lat <= 90.0 && lon >= -180.0 && lon <= 180.0 &&
           (!accuracy.has_value() || accuracy.value() >= 0.0);
  }

};

/**
 * @brief Core CWT claims structure with enhanced string handling
 */
struct CoreClaims {
  std::optional<std::string> iss;                     ///< Issuer
  std::optional<std::vector<std::string>> aud;        ///< Audience
  std::optional<int64_t> exp;                         ///< Expiration time
  std::optional<int64_t> nbf;                         ///< Not before time
  std::optional<std::string> cti;                     ///< CWT ID
  
  CoreClaims() = default;
  CoreClaims(const CoreClaims&) = default;
  CoreClaims(CoreClaims&&) noexcept = default;
  CoreClaims& operator=(const CoreClaims&) = default;
  CoreClaims& operator=(CoreClaims&&) noexcept = default;
  
  /**
   * @brief Set issuer with validation and optimized string handling
   */
  void setIssuer(std::string_view issuer) {
    if (!validation::isValidIssuer(issuer)) {
      throw InvalidClaimValueError("Invalid issuer format");
    }
    iss = std::move(validation::sanitizeString(issuer));
  }
  
  /**
   * @brief Add audience with validation and optimized string handling
   */
  void addAudience(std::string_view audience) {
    if (!validation::isValidAudience(audience)) {
      throw InvalidClaimValueError("Invalid audience format");
    }
    if (!aud.has_value()) {
      aud = std::vector<std::string>{};
      aud->reserve(4);  // Reserve space for common case of few audiences
    }
    aud->emplace_back(std::move(validation::sanitizeString(audience)));
  }
};

/**
 * @brief Informational claims structure with enhanced string handling
 */
struct InformationalClaims {
  std::optional<std::string> sub;       ///< Subject
  std::optional<int64_t> iat;           ///< Issued at time
  std::optional<std::string> catifdata; ///< CAT interface data
  
  InformationalClaims() = default;
  InformationalClaims(const InformationalClaims&) = default;
  InformationalClaims(InformationalClaims&&) noexcept = default;
  InformationalClaims& operator=(const InformationalClaims&) = default;
  InformationalClaims& operator=(InformationalClaims&&) noexcept = default;
  
  /**
   * @brief Set subject with validation
   */
  void setSubject(std::string_view subject) {
    if (!validation::isValidStringLength(subject, 256)) {
      throw InvalidClaimValueError("Invalid subject format");
    }
    sub = validation::sanitizeString(subject);
  }
};

/**
 * @brief DPoP (Demonstration of Proof-of-Possession) claims structure
 */
struct DpopClaims {
  std::optional<std::string> cnf;     ///< Confirmation claim
  std::optional<std::string> catdpop; ///< CAT DPoP claim
  
  DpopClaims() = default;
  DpopClaims(const DpopClaims&) = default;
  DpopClaims(DpopClaims&&) noexcept = default;
  DpopClaims& operator=(const DpopClaims&) = default;
  DpopClaims& operator=(DpopClaims&&) noexcept = default;
};

/**
 * @brief Request-specific claims structure
 */
struct RequestClaims {
  std::optional<std::string> catif; ///< CAT interface claim
  std::optional<std::string> catr;  ///< CAT request claim
  
  RequestClaims() = default;
  RequestClaims(const RequestClaims&) = default;
  RequestClaims(RequestClaims&&) noexcept = default;
  RequestClaims& operator=(const RequestClaims&) = default;
  RequestClaims& operator=(RequestClaims&&) noexcept = default;
};

/**
 * @brief CAT-specific claims structure
 */
struct CatClaims {
  std::optional<std::string> catreplay;                   ///< Replay protection nonce
  std::optional<bool> catpor;                             ///< Proof of possession required
  std::optional<std::string> catv;                        ///< CAT version
  std::optional<std::vector<std::string>> catnip;         ///< Network interfaces
  std::optional<uint32_t> catu;                           ///< Usage limit
  std::optional<std::string> catm;                        ///< Allowed methods
  std::optional<std::vector<std::string>> catalpn;        ///< ALPN protocols
  std::optional<std::vector<std::string>> cath;            ///< Host patterns
  std::optional<std::vector<std::string>> catgeoiso3166;  ///< Geographic restrictions (ISO 3166)
  std::optional<GeoCoordinate> catgeocoord;               ///< Geographic coordinates
  std::optional<std::string> geohash;                     ///< Geohash representation
  std::optional<int32_t> catgeoalt;                       ///< Geographic altitude
  std::optional<std::string> cattpk;                      ///< Token public key thumbprint
};


}  // namespace catapult