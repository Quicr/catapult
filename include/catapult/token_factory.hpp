/**
 * @file cat_token_factory.hpp
 * @brief Factory utilities and helpers for creating CAT tokens
 */

#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <stdexcept>

// Include necessary headers for template implementation
#include "token.hpp"
#include "claims.hpp"
#include "composite.hpp"

namespace catapult {

/**
 * @brief Runtime token factory functions
 */
namespace token_factory {
  
  /**
   * @brief Create a token with geographic restrictions (runtime version)
   * @param issuer Token issuer
   * @param audience Token audience
   * @param lat Latitude coordinate
   * @param lon Longitude coordinate
   * @return CatToken with geographic coordinate restrictions
   */
  inline CatToken create_geo_token(const std::string& issuer, const std::string& audience, 
                                   double lat, double lon) {
    // Runtime validation
    if (lat < -90.0 || lat > 90.0 || lon < -180.0 || lon > 180.0) {
      throw std::invalid_argument("Invalid geographic coordinates");
    }
    
    CatToken token;
    token.core.iss = issuer;
    token.core.aud = std::vector<std::string>{audience};
    
    // Set geographic coordinate claim
    auto coord = GeoCoordinate::createSafe(lat, lon);
    if (!coord.has_value()) {
      throw std::invalid_argument("Failed to create valid geographic coordinate");
    }
    token.cat.catgeocoord = coord.value();
    
    return token;
  }
  
  /**
   * @brief Create a token with geographic restrictions (compile-time version)
   * @param issuer Token issuer
   * @param audience Token audience
   * @tparam LatInt Latitude as integer (lat * 10000)
   * @tparam LonInt Longitude as integer (lon * 10000)
   * @return CatToken with geographic coordinate restrictions
   */
  template<int LatInt, int LonInt>
  CatToken create_geo_token_fixed(const std::string& issuer, const std::string& audience) {
    constexpr double lat = static_cast<double>(LatInt) / 10000.0;
    constexpr double lon = static_cast<double>(LonInt) / 10000.0;
    
    static_assert(composite_constants::is_valid_latitude(lat), "Invalid latitude at compile time");
    static_assert(composite_constants::is_valid_longitude(lon), "Invalid longitude at compile time");
    
    CatToken token;
    token.core.iss = issuer;
    token.core.aud = std::vector<std::string>{audience};
    
    // Set geographic coordinate claim using compile-time validated coordinates
    GeoCoordinate coord;
    coord.lat = lat;
    coord.lon = lon;
    token.cat.catgeocoord = coord;
    
    return token;
  }
}


/**
 * @brief Literal operators for common claim values
 */
namespace literals {
  /**
   * @brief Create a CAT version string
   */
  inline std::string operator""_catv(const char* str, size_t len) {
    return std::string(str, len);
  }
  
  /**
   * @brief Create an issuer string
   */
  inline std::string operator""_iss(const char* str, size_t len) {
    return std::string(str, len);
  }
}

} // namespace catapult