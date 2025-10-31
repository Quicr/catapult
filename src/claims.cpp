#include <algorithm>
#include <memory>
#include <ranges>
#include <utility>

#include "catapult/composite.hpp"
#include "catapult/moqt_claims.hpp"
#include "catapult/token.hpp"

namespace catapult {

// CatToken builder methods
CatToken& CatToken::withIssuer(const std::string& issuer) {
  core.iss = issuer;
  return *this;
}

CatToken& CatToken::withAudience(const std::vector<std::string>& audience) {
  core.aud = audience;
  return *this;
}

CatToken& CatToken::withExpiration(
    const std::chrono::system_clock::time_point& exp) {
  auto time_t = std::chrono::system_clock::to_time_t(exp);
  core.exp = static_cast<int64_t>(time_t);
  return *this;
}

CatToken& CatToken::withNotBefore(
    const std::chrono::system_clock::time_point& nbf) {
  auto time_t = std::chrono::system_clock::to_time_t(nbf);
  core.nbf = static_cast<int64_t>(time_t);
  return *this;
}

CatToken& CatToken::withCwtId(const std::string& cti) {
  core.cti = cti;
  return *this;
}

CatToken& CatToken::withVersion(const std::string& version) {
  cat.catv = version;
  return *this;
}

CatToken& CatToken::withUsageLimit(uint32_t limit) {
  cat.catu = limit;
  return *this;
}

CatToken& CatToken::withReplayProtection(const std::string& nonce) {
  cat.catreplay = nonce;
  return *this;
}

CatToken& CatToken::withProofOfPossession(bool enabled) {
  cat.catpor = enabled;
  return *this;
}

CatToken& CatToken::withGeoCoordinate(double lat, double lon,
                                      std::optional<double> accuracy) {
  cat.catgeocoord = GeoCoordinate(lat, lon, accuracy);
  return *this;
}

CatToken& CatToken::withGeohash(const std::string& geohash) {
  cat.geohash = geohash;
  return *this;
}

CatToken& CatToken::withGeoAltitude(int32_t altitude) {
  cat.catgeoalt = altitude;
  return *this;
}

CatToken& CatToken::withNetworkInterfaces(
    const std::vector<std::string>& nips) {
  cat.catnip = nips;
  return *this;
}

CatToken& CatToken::withMethods(const std::string& methods) {
  cat.catm = methods;
  return *this;
}

CatToken& CatToken::withAlpnProtocols(
    const std::vector<std::string>& protocols) {
  cat.catalpn = protocols;
  return *this;
}

CatToken& CatToken::withHosts(const std::vector<std::string>& hosts) {
  cat.cath = hosts;
  return *this;
}

CatToken& CatToken::withCountries(const std::vector<std::string>& countries) {
  cat.catgeoiso3166 = countries;
  return *this;
}

CatToken& CatToken::withTokenPublicKeyThumbprint(
    const std::string& thumbprint) {
  cat.cattpk = thumbprint;
  return *this;
}

CatToken& CatToken::withSubject(const std::string& subject) {
  informational.sub = subject;
  return *this;
}

CatToken& CatToken::withIssuedAt(
    const std::chrono::system_clock::time_point& iat) {
  auto time_t = std::chrono::system_clock::to_time_t(iat);
  informational.iat = static_cast<int64_t>(time_t);
  return *this;
}

CatToken& CatToken::withInterfaceData(const std::string& data) {
  informational.catifdata = data;
  return *this;
}

CatToken& CatToken::withConfirmation(const std::string& cnf) {
  dpop.cnf = cnf;
  return *this;
}

CatToken& CatToken::withDpopClaim(const std::string& dpop_claim) {
  dpop.catdpop = dpop_claim;
  return *this;
}

CatToken& CatToken::withInterfaceClaim(const std::string& interface) {
  request.catif = interface;
  return *this;
}

CatToken& CatToken::withRequestClaim(const std::string& request_claim) {
  request.catr = request_claim;
  return *this;
}

CatToken& CatToken::withUriPatterns(const std::vector<std::string>& patterns) {
  cat.cath = patterns;
  return *this;
}

// CatToken composite claim builder methods
CatToken& CatToken::withOrComposite(std::unique_ptr<OrClaim> orClaim) {
  composite.orClaim = std::move(orClaim);
  return *this;
}

CatToken& CatToken::withNorComposite(std::unique_ptr<NorClaim> norClaim) {
  composite.norClaim = std::move(norClaim);
  return *this;
}

CatToken& CatToken::withAndComposite(std::unique_ptr<AndClaim> andClaim) {
  composite.andClaim = std::move(andClaim);
  return *this;
}

// MOQT claim builder method implementations

// CatToken MOQT methods
CatToken& CatToken::withMoqtClaims(MoqtClaims claims) {
  extended.setMoqtClaims(std::move(claims));
  return *this;
}

CatToken& CatToken::withMoqtRevalidationInterval(
    std::chrono::seconds interval) {
  auto& moqt_claims = extended.getMoqtClaims();
  moqt_claims.setRevalidationInterval(interval);
  return *this;
}

}  // namespace catapult