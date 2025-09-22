/**
 * @file json_serialization.cpp
 * @brief JSON serialization implementation for CAT tokens
 */

#include "catapult/json_serialization.hpp"
#include "catapult/claims.hpp"
#include "catapult/moqt_claims.hpp"

namespace catapult {
namespace json_serialization {

void to_json(nlohmann::json& j, const CoreClaims& claims) {
    j = nlohmann::json::object();
    
    if (claims.iss.has_value()) {
        j["iss"] = claims.iss.value();
    }
    if (claims.aud.has_value()) {
        j["aud"] = claims.aud.value();
    }
    if (claims.exp.has_value()) {
        j["exp"] = claims.exp.value();
    }
    if (claims.nbf.has_value()) {
        j["nbf"] = claims.nbf.value();
    }
    if (claims.cti.has_value()) {
        j["cti"] = claims.cti.value();
    }
}

void to_json(nlohmann::json& j, const GeoCoordinate& coord) {
    j = nlohmann::json::object();
    j["lat"] = coord.lat;
    j["lon"] = coord.lon;
    if (coord.accuracy.has_value()) {
        j["accuracy"] = coord.accuracy.value();
    }
}

void to_json(nlohmann::json& j, const CatClaims& claims) {
    j = nlohmann::json::object();
    
    if (claims.catv.has_value()) {
        j["catv"] = claims.catv.value();
    }
    if (claims.catu.has_value()) {
        j["catu"] = claims.catu.value();
    }
    if (claims.catreplay.has_value()) {
        j["catreplay"] = claims.catreplay.value();
    }
    if (claims.catpor.has_value()) {
        j["catpor"] = claims.catpor.value();
    }
    if (claims.catgeocoord.has_value()) {
        to_json(j["catgeocoord"], claims.catgeocoord.value());
    }
    if (claims.geohash.has_value()) {
        j["geohash"] = claims.geohash.value();
    }
    if (claims.catgeoalt.has_value()) {
        j["catgeoalt"] = claims.catgeoalt.value();
    }
    if (claims.catnip.has_value()) {
        j["catnip"] = claims.catnip.value();
    }
    if (claims.catm.has_value()) {
        j["catm"] = claims.catm.value();
    }
    if (claims.catalpn.has_value()) {
        j["catalpn"] = claims.catalpn.value();
    }
    if (claims.cath.has_value()) {
        j["cath"] = claims.cath.value();
    }
    if (claims.catgeoiso3166.has_value()) {
        j["catgeoiso3166"] = claims.catgeoiso3166.value();
    }
    if (claims.cattpk.has_value()) {
        j["cattpk"] = claims.cattpk.value();
    }
}

void to_json(nlohmann::json& j, const InformationalClaims& claims) {
    j = nlohmann::json::object();
    
    if (claims.sub.has_value()) {
        j["sub"] = claims.sub.value();
    }
    if (claims.iat.has_value()) {
        j["iat"] = claims.iat.value();
    }
    if (claims.catifdata.has_value()) {
        j["catifdata"] = claims.catifdata.value();
    }
}

void to_json(nlohmann::json& j, const DpopClaims& claims) {
    j = nlohmann::json::object();
    
    if (claims.cnf.has_value()) {
        j["cnf"] = claims.cnf.value();
    }
    if (claims.catdpop.has_value()) {
        j["catdpop"] = claims.catdpop.value();
    }
}

void to_json(nlohmann::json& j, const RequestClaims& claims) {
    j = nlohmann::json::object();
    
    if (claims.catif.has_value()) {
        j["catif"] = claims.catif.value();
    }
    if (claims.catr.has_value()) {
        j["catr"] = claims.catr.value();
    }
}

void to_json(nlohmann::json& j, const MoqtBinaryMatch& match) {
    j = nlohmann::json::object();
    j["type"] = static_cast<int>(match.match_type);
    
    // Convert binary pattern back to string for JSON readability
    std::string pattern_str;
    pattern_str.reserve(match.pattern.size());
    for (uint8_t byte : match.pattern) {
        pattern_str.push_back(static_cast<char>(byte));
    }
    j["pattern"] = pattern_str;
}

void to_json(nlohmann::json& j, const MoqtActionScope& scope) {
    j = nlohmann::json::object();
    j["actions"] = scope.actions;
    to_json(j["namespace_match"], scope.namespace_match);
    to_json(j["track_match"], scope.track_match);
}

void to_json(nlohmann::json& j, const MoqtClaims& claims) {
    j = nlohmann::json::object();
    
    auto scopes = nlohmann::json::array();
    const auto& scope_list = claims.getScopes();
    for (const auto& scope : scope_list) {
        nlohmann::json scope_json;
        to_json(scope_json, scope);
        scopes.push_back(scope_json);
    }
    j["scopes"] = scopes;
    
    if (claims.getRevalidationInterval().has_value()) {
        j["revalidation_interval"] = claims.getRevalidationInterval().value().count();
    }
}

void to_json(nlohmann::json& j, const ExtendedCatClaims& claims) {
    j = nlohmann::json::object();
    
    if (claims.hasMoqtClaims()) {
        const auto* moqt_claims = claims.getMoqtClaimsReadOnly();
        to_json(j["moqt"], *moqt_claims);
    }
}

void to_json(nlohmann::json& j, const ClaimSet& claimSet) {
    j = nlohmann::json::object();
    
    if (claimSet.hasToken()) {
        j["type"] = "token";
        to_json(j["content"], *claimSet.token);
    } else if (claimSet.orComposite) {
        j["type"] = "or_composite";
        to_json(j["content"], *claimSet.orComposite);
    } else if (claimSet.andComposite) {
        j["type"] = "and_composite";
        to_json(j["content"], *claimSet.andComposite);
    } else if (claimSet.norComposite) {
        j["type"] = "nor_composite";
        to_json(j["content"], *claimSet.norComposite);
    } else {
        j["type"] = "empty";
        j["content"] = nullptr;
    }
}

void to_json(nlohmann::json& j, const OrClaim& orClaim) {
    j = nlohmann::json::object();
    j["operator"] = "OR";
    j["depth"] = orClaim.getDepth();
    
    auto claims_array = nlohmann::json::array();
    for (const auto& claim : orClaim.claims) {
        nlohmann::json claim_json;
        to_json(claim_json, claim);
        claims_array.push_back(claim_json);
    }
    j["claims"] = claims_array;
}

void to_json(nlohmann::json& j, const AndClaim& andClaim) {
    j = nlohmann::json::object();
    j["operator"] = "AND";
    j["depth"] = andClaim.getDepth();
    
    auto claims_array = nlohmann::json::array();
    for (const auto& claim : andClaim.claims) {
        nlohmann::json claim_json;
        to_json(claim_json, claim);
        claims_array.push_back(claim_json);
    }
    j["claims"] = claims_array;
}

void to_json(nlohmann::json& j, const NorClaim& norClaim) {
    j = nlohmann::json::object();
    j["operator"] = "NOR";
    j["depth"] = norClaim.getDepth();
    
    auto claims_array = nlohmann::json::array();
    for (const auto& claim : norClaim.claims) {
        nlohmann::json claim_json;
        to_json(claim_json, claim);
        claims_array.push_back(claim_json);
    }
    j["claims"] = claims_array;
}

void to_json(nlohmann::json& j, const CompositeClaims& claims) {
    j = nlohmann::json::object();
    
    if (claims.orClaim.has_value() && claims.orClaim.value()) {
        to_json(j["or"], *claims.orClaim.value());
    }
    
    if (claims.andClaim.has_value() && claims.andClaim.value()) {
        to_json(j["and"], *claims.andClaim.value());
    }
    
    if (claims.norClaim.has_value() && claims.norClaim.value()) {
        to_json(j["nor"], *claims.norClaim.value());
    }
}

void to_json(nlohmann::json& j, const CatToken& token) {
    j = nlohmann::json::object();
    
    // Add core claims if they have any values
    nlohmann::json core_json;
    to_json(core_json, token.core);
    if (!core_json.empty()) {
        j["core"] = core_json;
    }
    
    // Add CAT claims if they have any values
    nlohmann::json cat_json;
    to_json(cat_json, token.cat);
    if (!cat_json.empty()) {
        j["cat"] = cat_json;
    }
    
    // Add informational claims if they have any values
    nlohmann::json info_json;
    to_json(info_json, token.informational);
    if (!info_json.empty()) {
        j["informational"] = info_json;
    }
    
    // Add DPoP claims if they have any values
    nlohmann::json dpop_json;
    to_json(dpop_json, token.dpop);
    if (!dpop_json.empty()) {
        j["dpop"] = dpop_json;
    }
    
    // Add request claims if they have any values
    nlohmann::json request_json;
    to_json(request_json, token.request);
    if (!request_json.empty()) {
        j["request"] = request_json;
    }
    
    // Add extended claims if they have any values
    nlohmann::json extended_json;
    to_json(extended_json, token.extended);
    if (!extended_json.empty()) {
        j["extended"] = extended_json;
    }
    
    // Add composite claims if they have any values
    nlohmann::json composite_json;
    to_json(composite_json, token.composite);
    if (!composite_json.empty()) {
        j["composite"] = composite_json;
    }
    
    // Add custom claims if any exist
    if (!token.custom.empty()) {
        j["custom"] = token.custom;
    }
}

std::string to_pretty_json(const CatToken& token, int indent) {
    nlohmann::json j;
    to_json(j, token);
    return j.dump(indent);
}

std::string to_compact_json(const CatToken& token) {
    nlohmann::json j;
    to_json(j, token);
    return j.dump();
}

void from_json(const nlohmann::json& j, CatToken& token) {
    // Clear the token first
    token = CatToken{};
    
    // Parse core claims
    if (j.contains("core") && j["core"].is_object()) {
        const auto& core_json = j["core"];
        if (core_json.contains("iss") && core_json["iss"].is_string()) {
            token.core.iss = core_json["iss"];
        }
        if (core_json.contains("aud") && core_json["aud"].is_array()) {
            token.core.aud = core_json["aud"];
        }
        if (core_json.contains("exp") && core_json["exp"].is_number()) {
            token.core.exp = core_json["exp"];
        }
        if (core_json.contains("nbf") && core_json["nbf"].is_number()) {
            token.core.nbf = core_json["nbf"];
        }
        if (core_json.contains("cti") && core_json["cti"].is_string()) {
            token.core.cti = core_json["cti"];
        }
    }
    
    // Parse CAT claims
    if (j.contains("cat") && j["cat"].is_object()) {
        const auto& cat_json = j["cat"];
        if (cat_json.contains("catv") && cat_json["catv"].is_string()) {
            token.cat.catv = cat_json["catv"];
        }
        if (cat_json.contains("catu") && cat_json["catu"].is_number()) {
            token.cat.catu = cat_json["catu"];
        }
        if (cat_json.contains("catreplay") && cat_json["catreplay"].is_string()) {
            token.cat.catreplay = cat_json["catreplay"];
        }
        if (cat_json.contains("catpor") && cat_json["catpor"].is_boolean()) {
            token.cat.catpor = cat_json["catpor"];
        }
        if (cat_json.contains("catgeocoord") && cat_json["catgeocoord"].is_object()) {
            const auto& coord_json = cat_json["catgeocoord"];
            if (coord_json.contains("lat") && coord_json.contains("lon")) {
                double lat = coord_json["lat"];
                double lon = coord_json["lon"];
                std::optional<double> accuracy;
                if (coord_json.contains("accuracy")) {
                    accuracy = coord_json["accuracy"];
                }
                auto coord = GeoCoordinate::createSafe(lat, lon, accuracy);
                if (coord.has_value()) {
                    token.cat.catgeocoord = coord.value();
                }
            }
        }
        if (cat_json.contains("geohash") && cat_json["geohash"].is_string()) {
            token.cat.geohash = cat_json["geohash"];
        }
        if (cat_json.contains("catgeoalt") && cat_json["catgeoalt"].is_number()) {
            token.cat.catgeoalt = cat_json["catgeoalt"];
        }
        if (cat_json.contains("catnip") && cat_json["catnip"].is_array()) {
            token.cat.catnip = cat_json["catnip"];
        }
        if (cat_json.contains("catm") && cat_json["catm"].is_string()) {
            token.cat.catm = cat_json["catm"];
        }
        if (cat_json.contains("catalpn") && cat_json["catalpn"].is_array()) {
            token.cat.catalpn = cat_json["catalpn"];
        }
        if (cat_json.contains("cath") && cat_json["cath"].is_array()) {
            token.cat.cath = cat_json["cath"];
        }
        if (cat_json.contains("catgeoiso3166") && cat_json["catgeoiso3166"].is_array()) {
            token.cat.catgeoiso3166 = cat_json["catgeoiso3166"];
        }
        if (cat_json.contains("cattpk") && cat_json["cattpk"].is_string()) {
            token.cat.cattpk = cat_json["cattpk"];
        }
    }
    
    // Parse informational claims
    if (j.contains("informational") && j["informational"].is_object()) {
        const auto& info_json = j["informational"];
        if (info_json.contains("sub") && info_json["sub"].is_string()) {
            token.informational.sub = info_json["sub"];
        }
        if (info_json.contains("iat") && info_json["iat"].is_number()) {
            token.informational.iat = info_json["iat"];
        }
        if (info_json.contains("catifdata") && info_json["catifdata"].is_string()) {
            token.informational.catifdata = info_json["catifdata"];
        }
    }
    
    // Parse DPoP claims
    if (j.contains("dpop") && j["dpop"].is_object()) {
        const auto& dpop_json = j["dpop"];
        if (dpop_json.contains("cnf") && dpop_json["cnf"].is_string()) {
            token.dpop.cnf = dpop_json["cnf"];
        }
        if (dpop_json.contains("catdpop") && dpop_json["catdpop"].is_string()) {
            token.dpop.catdpop = dpop_json["catdpop"];
        }
    }
    
    // Parse request claims
    if (j.contains("request") && j["request"].is_object()) {
        const auto& request_json = j["request"];
        if (request_json.contains("catif") && request_json["catif"].is_string()) {
            token.request.catif = request_json["catif"];
        }
        if (request_json.contains("catr") && request_json["catr"].is_string()) {
            token.request.catr = request_json["catr"];
        }
    }
    
    // Parse custom claims
    if (j.contains("custom") && j["custom"].is_array()) {
        for (const auto& custom_pair : j["custom"]) {
            if (custom_pair.is_array() && custom_pair.size() == 2) {
                int64_t key = custom_pair[0];
                std::string value = custom_pair[1];
                token.custom[key] = value;
            }
        }
    }
    
    // Note: Extended claims (MOQT) and composite claims parsing would require
    // more complex logic and is intentionally simplified for this example
    // In a production implementation, you'd want full bidirectional parsing
}

std::string to_base64_json(const CatToken& token, bool pretty, int indent) {
    std::string json_str = pretty ? to_pretty_json(token, indent) : to_compact_json(token);
    return base64_utils::json_to_base64(json_str);
}

CatToken from_base64_json(const std::string& base64_json) {
    if (!base64_utils::is_valid_base64(base64_json)) {
        throw std::invalid_argument("Invalid base64 format");
    }
    
    std::string json_str = base64_utils::base64_to_json(base64_json);
    
    nlohmann::json j = nlohmann::json::parse(json_str);
    
    CatToken token;
    from_json(j, token);
    return token;
}

namespace base64_utils {

std::string json_to_base64(const std::string& json_string) {
    // Convert string to vector<uint8_t> for base64 encoding
    std::vector<uint8_t> data(json_string.begin(), json_string.end());
    return base64UrlEncode(data);
}

std::string base64_to_json(const std::string& base64_string) {
    try {
        // Decode base64 to vector<uint8_t>
        std::vector<uint8_t> decoded_data = base64UrlDecode(base64_string);
        // Convert back to string
        return std::string(decoded_data.begin(), decoded_data.end());
    } catch (const std::exception& e) {
        throw std::invalid_argument("Failed to decode base64: " + std::string(e.what()));
    }
}

bool is_valid_base64(const std::string& base64_string) {
    if (base64_string.empty()) {
        return false;
    }
    
    // Use the actual base64UrlDecode function to validate
    try {
        base64UrlDecode(base64_string);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

} // namespace base64_utils

} // namespace json_serialization
} // namespace catapult