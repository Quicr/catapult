/**
 * @file json_serialization.hpp
 * @brief JSON serialization utilities for CAT tokens
 */

#pragma once

#include <nlohmann/json.hpp>
#include "token.hpp"
#include "claims.hpp"
#include "moqt_claims.hpp"
#include "composite.hpp"
#include "base64.hpp"

namespace catapult {

/**
 * @brief JSON serialization utilities for CAT tokens
 */
namespace json_serialization {

/**
 * @brief Convert CoreClaims to JSON
 */
void to_json(nlohmann::json& j, const CoreClaims& claims);

/**
 * @brief Convert CatClaims to JSON
 */
void to_json(nlohmann::json& j, const CatClaims& claims);

/**
 * @brief Convert InformationalClaims to JSON
 */
void to_json(nlohmann::json& j, const InformationalClaims& claims);

/**
 * @brief Convert DpopClaims to JSON
 */
void to_json(nlohmann::json& j, const DpopClaims& claims);

/**
 * @brief Convert RequestClaims to JSON
 */
void to_json(nlohmann::json& j, const RequestClaims& claims);

/**
 * @brief Convert ExtendedCatClaims to JSON
 */
void to_json(nlohmann::json& j, const ExtendedCatClaims& claims);

/**
 * @brief Convert ClaimSet to JSON
 */
void to_json(nlohmann::json& j, const ClaimSet& claimSet);

/**
 * @brief Convert OrClaim to JSON
 */
void to_json(nlohmann::json& j, const OrClaim& orClaim);

/**
 * @brief Convert AndClaim to JSON
 */
void to_json(nlohmann::json& j, const AndClaim& andClaim);

/**
 * @brief Convert NorClaim to JSON
 */
void to_json(nlohmann::json& j, const NorClaim& norClaim);

/**
 * @brief Convert CompositeClaims to JSON
 */
void to_json(nlohmann::json& j, const CompositeClaims& claims);

/**
 * @brief Convert CatToken to JSON
 */
void to_json(nlohmann::json& j, const CatToken& token);

/**
 * @brief Parse CatToken from JSON
 */
void from_json(const nlohmann::json& j, CatToken& token);

/**
 * @brief Get pretty printed JSON string for a CAT token
 * @param token The token to serialize
 * @param indent Number of spaces to indent (default: 2)
 * @return Pretty printed JSON string
 */
std::string to_pretty_json(const CatToken& token, int indent = 2);

/**
 * @brief Get compact JSON string for a CAT token
 * @param token The token to serialize
 * @return Compact JSON string
 */
std::string to_compact_json(const CatToken& token);

/**
 * @brief Convert CAT token to base64-encoded JSON
 * @param token The token to serialize
 * @param pretty Whether to use pretty printing (default: false)
 * @param indent Number of spaces to indent if pretty printing (default: 2)
 * @return Base64-encoded JSON string
 */
std::string to_base64_json(const CatToken& token, bool pretty = false, int indent = 2);

/**
 * @brief Parse CAT token from base64-encoded JSON
 * @param base64_json Base64-encoded JSON string
 * @return Parsed CatToken object
 * @throws std::invalid_argument if base64 decoding fails
 * @throws nlohmann::json::exception if JSON parsing fails
 */
CatToken from_base64_json(const std::string& base64_json);

/**
 * @brief Utility functions for base64 JSON operations
 */
namespace base64_utils {

/**
 * @brief Convert JSON string to base64
 * @param json_string The JSON string to encode
 * @return Base64-encoded string
 */
std::string json_to_base64(const std::string& json_string);

/**
 * @brief Convert base64 string to JSON
 * @param base64_string The base64 string to decode
 * @return JSON string
 * @throws std::invalid_argument if base64 decoding fails
 */
std::string base64_to_json(const std::string& base64_string);

/**
 * @brief Validate base64 string format
 * @param base64_string The string to validate
 * @return true if valid base64 format
 */
bool is_valid_base64(const std::string& base64_string);

} // namespace base64_utils

} // namespace json_serialization

} // namespace catapult