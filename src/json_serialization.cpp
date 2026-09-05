/**
 * @file json_serialization.cpp
 * @brief JSON serialization implementation for CAT tokens
 *
 * JSON is a debugging/interop surface only — the wire form is CBOR per
 * CTA-5007-B. Byte-string typed fields (cti, catalpn entries, jkt, catnip
 * value, cattpk, catpor identifier, catif/catr raw bytes, UriComponentMatch
 * value, catdpop opaque fields) are encoded as base64url strings to preserve
 * type information across the JSON boundary. Typed enums serialise as their
 * numeric value so JSON round-trips are unambiguous.
 */

#include "catapult/json_serialization.hpp"

#include "catapult/claims.hpp"
#include "catapult/moqt_claims.hpp"

namespace catapult {
namespace json_serialization {

namespace {

std::string bytes_to_b64(const std::vector<uint8_t>& bytes) {
  return base64UrlEncode(bytes);
}

std::vector<uint8_t> b64_to_bytes(const std::string& s) {
  return base64UrlDecode(s);
}

nlohmann::json component_match_to_json(const UriComponentMatch& m) {
  nlohmann::json out = nlohmann::json::object();
  out["type"] = static_cast<uint32_t>(m.type);
  out["value_b64"] = bytes_to_b64(m.value);
  return out;
}

UriComponentMatch component_match_from_json(const nlohmann::json& j) {
  UriComponentMatch m;
  if (j.contains("type") && j["type"].is_number_unsigned()) {
    m.type = static_cast<UriMatchType>(j["type"].get<uint32_t>());
  }
  if (j.contains("value_b64") && j["value_b64"].is_string()) {
    m.value = b64_to_bytes(j["value_b64"].get<std::string>());
  }
  return m;
}

}  // namespace

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
    // cti is a CBOR byte string (RFC 8392 §3.1.7). Emit base64url so JSON
    // round-trips preserve the byte-string typing.
    j["cti_b64"] = bytes_to_b64(claims.cti.value());
  }
}

void to_json(nlohmann::json& j, const GeoCoordinate& coord) {
  j = nlohmann::json::object();
  j["lat"] = coord.lat;
  j["lon"] = coord.lon;
  if (coord.radius.has_value()) {
    j["radius"] = coord.radius.value();
  }
}

static void to_json(nlohmann::json& j, const CatProofOfPossession& por) {
  j = nlohmann::json::object();
  j["probability"] = por.probability;
  j["identifier_b64"] = bytes_to_b64(por.identifier);
  if (por.expiry.has_value()) {
    j["expiry"] = por.expiry.value();
  }
}

static void to_json(nlohmann::json& j, const CatNipEntry& entry) {
  j = nlohmann::json::object();
  j["tag"] = entry.tag;
  j["value_b64"] = bytes_to_b64(entry.value);
}

static void to_json(nlohmann::json& j, const GeoAltitude& alt) {
  j = nlohmann::json::object();
  j["altitude"] = alt.altitude;
  if (alt.deviation.has_value()) {
    j["deviation"] = alt.deviation.value();
  }
}

static void to_json(nlohmann::json& j, const CatUriMatchMap& map) {
  j = nlohmann::json::object();
  for (const auto& [component, match] : map.components) {
    j[std::to_string(component)] = component_match_to_json(match);
  }
}

static void to_json(nlohmann::json& j, const CatHostHeaderMatchList& list) {
  j = nlohmann::json::array();
  for (const auto& entry : list.entries) {
    nlohmann::json e = nlohmann::json::object();
    e["name"] = entry.name;
    e["match"] = component_match_to_json(entry.match);
    j.push_back(std::move(e));
  }
}

static void to_json(nlohmann::json& j, const GeohashClaimValue& gh) {
  if (gh.isString()) {
    j = gh.asString();
  } else {
    j = gh.asArray();
  }
}

static void to_json(nlohmann::json& j, const CatIfData& d) {
  if (d.isString()) {
    j = d.asString();
  } else {
    j = d.asArray();
  }
}

static void to_json(nlohmann::json& j, const CatConfirmation& cnf) {
  j = nlohmann::json::object();
  if (cnf.jkt.has_value()) {
    j["jkt_b64"] = bytes_to_b64(cnf.jkt.value());
  }
  if (cnf.kid.has_value()) {
    j["kid"] = cnf.kid.value();
  }
  if (cnf.raw.has_value()) {
    j["raw_b64"] = bytes_to_b64(cnf.raw.value());
  }
}

static void to_json(nlohmann::json& j, const CatDpopSettings& dp) {
  j = nlohmann::json::object();
  if (dp.critical.has_value()) {
    j["critical"] = dp.critical.value();
  }
  if (dp.proof_lifetime_seconds.has_value()) {
    j["proof_lifetime_seconds"] = dp.proof_lifetime_seconds.value();
  }
  if (dp.jti_challenge.has_value()) {
    j["jti_challenge_b64"] = bytes_to_b64(dp.jti_challenge.value());
  }
  if (dp.raw.has_value()) {
    j["raw_b64"] = bytes_to_b64(dp.raw.value());
  }
}

static void to_json(nlohmann::json& j, const CatRequestDirective& d) {
  j = nlohmann::json::object();
  j["raw_b64"] = bytes_to_b64(d.raw);
}

void to_json(nlohmann::json& j, const CatClaims& claims) {
  j = nlohmann::json::object();

  if (claims.catv.has_value()) {
    j["catv"] = claims.catv.value();
  }
  if (claims.catu.has_value()) {
    to_json(j["catu"], claims.catu.value());
  }
  if (claims.catreplay.has_value()) {
    j["catreplay"] = static_cast<uint32_t>(claims.catreplay.value());
  }
  if (claims.catpor.has_value()) {
    to_json(j["catpor"], claims.catpor.value());
  }
  if (claims.catgeocoord.has_value()) {
    to_json(j["catgeocoord"], claims.catgeocoord.value());
  }
  if (claims.geohash.has_value()) {
    to_json(j["geohash"], claims.geohash.value());
  }
  if (claims.catgeoalt.has_value()) {
    to_json(j["catgeoalt"], claims.catgeoalt.value());
  }
  if (claims.catnip.has_value()) {
    auto arr = nlohmann::json::array();
    for (const auto& entry : claims.catnip.value()) {
      nlohmann::json e;
      to_json(e, entry);
      arr.push_back(std::move(e));
    }
    j["catnip"] = std::move(arr);
  }
  if (claims.catm.has_value()) {
    j["catm"] = claims.catm.value();
  }
  if (claims.catalpn.has_value()) {
    auto arr = nlohmann::json::array();
    for (const auto& proto : claims.catalpn.value()) {
      arr.push_back(bytes_to_b64(proto));
    }
    j["catalpn"] = std::move(arr);
  }
  if (claims.cath.has_value()) {
    to_json(j["cath"], claims.cath.value());
  }
  if (claims.catgeoiso3166.has_value()) {
    j["catgeoiso3166"] = claims.catgeoiso3166.value();
  }
  if (claims.cattpk.has_value()) {
    j["cattpk_b64"] = bytes_to_b64(claims.cattpk.value());
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
    to_json(j["catifdata"], claims.catifdata.value());
  }
}

void to_json(nlohmann::json& j, const DpopClaims& claims) {
  j = nlohmann::json::object();

  if (claims.cnf.has_value()) {
    to_json(j["cnf"], claims.cnf.value());
  }
  if (claims.catdpop.has_value()) {
    to_json(j["catdpop"], claims.catdpop.value());
  }
}

void to_json(nlohmann::json& j, const RequestClaims& claims) {
  j = nlohmann::json::object();

  if (claims.catif.has_value()) {
    to_json(j["catif"], claims.catif.value());
  }
  if (claims.catr.has_value()) {
    to_json(j["catr"], claims.catr.value());
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

void to_json(nlohmann::json& j, const MoqtCompoundMatch& match) {
  if (match.is_empty()) {
    j = nlohmann::json::object();
    j["type"] = "any";
    return;
  }
  if (match.size() == 1) {
    to_json(j, match.conditions()[0]);
    return;
  }
  j = nlohmann::json::array();
  for (const auto& cond : match.conditions()) {
    nlohmann::json cond_json;
    to_json(cond_json, cond);
    j.push_back(std::move(cond_json));
  }
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
    j["revalidation_interval"] =
        claims.getRevalidationInterval().value().count();
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
      token.core.iss = core_json["iss"].get<std::string>();
    }
    if (core_json.contains("aud") && core_json["aud"].is_array()) {
      token.core.aud = core_json["aud"].get<std::vector<std::string>>();
    }
    if (core_json.contains("exp") && core_json["exp"].is_number()) {
      token.core.exp = core_json["exp"].get<int64_t>();
    }
    if (core_json.contains("nbf") && core_json["nbf"].is_number()) {
      token.core.nbf = core_json["nbf"].get<int64_t>();
    }
    if (core_json.contains("cti_b64") && core_json["cti_b64"].is_string()) {
      token.core.cti = b64_to_bytes(core_json["cti_b64"].get<std::string>());
    }
  }

  // Parse CAT claims
  if (j.contains("cat") && j["cat"].is_object()) {
    const auto& cat_json = j["cat"];
    if (cat_json.contains("catv") && cat_json["catv"].is_number_unsigned()) {
      token.cat.catv = cat_json["catv"].get<uint32_t>();
    }
    if (cat_json.contains("catu") && cat_json["catu"].is_object()) {
      CatUriMatchMap m;
      for (auto it = cat_json["catu"].begin(); it != cat_json["catu"].end();
           ++it) {
        try {
          int64_t component = std::stoll(it.key());
          m.components[component] = component_match_from_json(it.value());
        } catch (const std::exception&) {
          // Skip malformed entries
        }
      }
      token.cat.catu = std::move(m);
    }
    if (cat_json.contains("catreplay") &&
        cat_json["catreplay"].is_number_unsigned()) {
      token.cat.catreplay =
          static_cast<CatReplayMode>(cat_json["catreplay"].get<uint32_t>());
    }
    if (cat_json.contains("catpor") && cat_json["catpor"].is_object()) {
      CatProofOfPossession por;
      const auto& p = cat_json["catpor"];
      if (p.contains("probability") && p["probability"].is_number()) {
        por.probability = p["probability"].get<double>();
      }
      if (p.contains("identifier_b64") && p["identifier_b64"].is_string()) {
        por.identifier = b64_to_bytes(p["identifier_b64"].get<std::string>());
      }
      if (p.contains("expiry") && p["expiry"].is_number()) {
        por.expiry = p["expiry"].get<int64_t>();
      }
      token.cat.catpor = std::move(por);
    }
    if (cat_json.contains("catgeocoord") &&
        cat_json["catgeocoord"].is_object()) {
      const auto& coord_json = cat_json["catgeocoord"];
      if (coord_json.contains("lat") && coord_json.contains("lon")) {
        double lat = coord_json["lat"].get<double>();
        double lon = coord_json["lon"].get<double>();
        std::optional<double> radius;
        if (coord_json.contains("radius") && coord_json["radius"].is_number()) {
          radius = coord_json["radius"].get<double>();
        }
        auto coord = GeoCoordinate::createSafe(lat, lon, radius);
        if (coord.has_value()) {
          token.cat.catgeocoord = coord.value();
        }
      }
    }
    if (cat_json.contains("geohash")) {
      const auto& g = cat_json["geohash"];
      if (g.is_string()) {
        token.cat.geohash = GeohashClaimValue(g.get<std::string>());
      } else if (g.is_array()) {
        token.cat.geohash =
            GeohashClaimValue(g.get<std::vector<std::string>>());
      }
    }
    if (cat_json.contains("catgeoalt") && cat_json["catgeoalt"].is_object()) {
      const auto& a = cat_json["catgeoalt"];
      GeoAltitude alt;
      if (a.contains("altitude") && a["altitude"].is_number()) {
        alt.altitude = a["altitude"].get<int32_t>();
      }
      if (a.contains("deviation") && a["deviation"].is_number()) {
        alt.deviation = a["deviation"].get<int32_t>();
      }
      token.cat.catgeoalt = alt;
    }
    if (cat_json.contains("catnip") && cat_json["catnip"].is_array()) {
      std::vector<CatNipEntry> entries;
      for (const auto& e : cat_json["catnip"]) {
        CatNipEntry entry;
        if (e.contains("tag") && e["tag"].is_number_unsigned()) {
          entry.tag = e["tag"].get<uint64_t>();
        }
        if (e.contains("value_b64") && e["value_b64"].is_string()) {
          entry.value = b64_to_bytes(e["value_b64"].get<std::string>());
        }
        entries.push_back(std::move(entry));
      }
      token.cat.catnip = std::move(entries);
    }
    if (cat_json.contains("catm") && cat_json["catm"].is_array()) {
      token.cat.catm = cat_json["catm"].get<std::vector<std::string>>();
    }
    if (cat_json.contains("catalpn") && cat_json["catalpn"].is_array()) {
      std::vector<std::vector<uint8_t>> protocols;
      for (const auto& p : cat_json["catalpn"]) {
        if (p.is_string()) {
          protocols.push_back(b64_to_bytes(p.get<std::string>()));
        }
      }
      token.cat.catalpn = std::move(protocols);
    }
    if (cat_json.contains("cath") && cat_json["cath"].is_array()) {
      CatHostHeaderMatchList list;
      for (const auto& e : cat_json["cath"]) {
        CatHeaderMatch entry;
        if (e.contains("name") && e["name"].is_string()) {
          entry.name = e["name"].get<std::string>();
        }
        if (e.contains("match") && e["match"].is_object()) {
          entry.match = component_match_from_json(e["match"]);
        }
        list.entries.push_back(std::move(entry));
      }
      token.cat.cath = std::move(list);
    }
    if (cat_json.contains("catgeoiso3166") &&
        cat_json["catgeoiso3166"].is_array()) {
      token.cat.catgeoiso3166 =
          cat_json["catgeoiso3166"].get<std::vector<std::string>>();
    }
    if (cat_json.contains("cattpk_b64") && cat_json["cattpk_b64"].is_string()) {
      token.cat.cattpk = b64_to_bytes(cat_json["cattpk_b64"].get<std::string>());
    }
  }

  // Parse informational claims
  if (j.contains("informational") && j["informational"].is_object()) {
    const auto& info_json = j["informational"];
    if (info_json.contains("sub") && info_json["sub"].is_string()) {
      token.informational.sub = info_json["sub"].get<std::string>();
    }
    if (info_json.contains("iat") && info_json["iat"].is_number()) {
      token.informational.iat = info_json["iat"].get<int64_t>();
    }
    if (info_json.contains("catifdata")) {
      const auto& d = info_json["catifdata"];
      if (d.is_string()) {
        token.informational.catifdata = CatIfData(d.get<std::string>());
      } else if (d.is_array()) {
        token.informational.catifdata =
            CatIfData(d.get<std::vector<std::string>>());
      }
    }
  }

  // Parse DPoP claims
  if (j.contains("dpop") && j["dpop"].is_object()) {
    const auto& dpop_json = j["dpop"];
    if (dpop_json.contains("cnf") && dpop_json["cnf"].is_object()) {
      const auto& c = dpop_json["cnf"];
      CatConfirmation cnf;
      if (c.contains("jkt_b64") && c["jkt_b64"].is_string()) {
        cnf.jkt = b64_to_bytes(c["jkt_b64"].get<std::string>());
      }
      if (c.contains("kid") && c["kid"].is_string()) {
        cnf.kid = c["kid"].get<std::string>();
      }
      if (c.contains("raw_b64") && c["raw_b64"].is_string()) {
        cnf.raw = b64_to_bytes(c["raw_b64"].get<std::string>());
      }
      token.dpop.cnf = std::move(cnf);
    }
    if (dpop_json.contains("catdpop") && dpop_json["catdpop"].is_object()) {
      const auto& d = dpop_json["catdpop"];
      CatDpopSettings dp;
      if (d.contains("critical") && d["critical"].is_array()) {
        dp.critical = d["critical"].get<std::vector<int64_t>>();
      }
      if (d.contains("proof_lifetime_seconds") &&
          d["proof_lifetime_seconds"].is_number()) {
        dp.proof_lifetime_seconds =
            d["proof_lifetime_seconds"].get<int64_t>();
      }
      if (d.contains("jti_challenge_b64") &&
          d["jti_challenge_b64"].is_string()) {
        dp.jti_challenge =
            b64_to_bytes(d["jti_challenge_b64"].get<std::string>());
      }
      if (d.contains("raw_b64") && d["raw_b64"].is_string()) {
        dp.raw = b64_to_bytes(d["raw_b64"].get<std::string>());
      }
      token.dpop.catdpop = std::move(dp);
    }
  }

  // Parse request claims
  if (j.contains("request") && j["request"].is_object()) {
    const auto& request_json = j["request"];
    if (request_json.contains("catif") && request_json["catif"].is_object()) {
      const auto& c = request_json["catif"];
      CatRequestDirective d;
      if (c.contains("raw_b64") && c["raw_b64"].is_string()) {
        d.raw = b64_to_bytes(c["raw_b64"].get<std::string>());
      }
      token.request.catif = std::move(d);
    }
    if (request_json.contains("catr") && request_json["catr"].is_object()) {
      const auto& c = request_json["catr"];
      CatRequestDirective d;
      if (c.contains("raw_b64") && c["raw_b64"].is_string()) {
        d.raw = b64_to_bytes(c["raw_b64"].get<std::string>());
      }
      token.request.catr = std::move(d);
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
  std::string json_str =
      pretty ? to_pretty_json(token, indent) : to_compact_json(token);
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
    throw std::invalid_argument("Failed to decode base64: " +
                                std::string(e.what()));
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

}  // namespace base64_utils

}  // namespace json_serialization
}  // namespace catapult
