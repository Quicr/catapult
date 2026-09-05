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

CatToken& CatToken::withCwtId(std::vector<uint8_t> cti) {
  core.cti = std::move(cti);
  return *this;
}

CatToken& CatToken::withCwtIdString(std::string_view cti) {
  core.setCwtIdFromString(cti);
  return *this;
}

CatToken& CatToken::withVersion(uint32_t version) {
  cat.catv = version;
  return *this;
}

CatToken& CatToken::withUriMatch(CatUriMatchMap catu) {
  cat.catu = std::move(catu);
  return *this;
}

CatToken& CatToken::withReplayProtection(CatReplayMode mode) {
  cat.catreplay = mode;
  return *this;
}

CatToken& CatToken::withProofOfPossession(CatProofOfPossession por) {
  cat.catpor = std::move(por);
  return *this;
}

CatToken& CatToken::withGeoCoordinate(double lat, double lon,
                                      std::optional<double> radius) {
  cat.catgeocoord = GeoCoordinate(lat, lon, radius);
  return *this;
}

CatToken& CatToken::withGeohash(GeohashClaimValue geohash) {
  cat.geohash = std::move(geohash);
  return *this;
}

CatToken& CatToken::withGeoAltitude(GeoAltitude altitude) {
  cat.catgeoalt = altitude;
  return *this;
}

CatToken& CatToken::withNetworkInterfaces(std::vector<CatNipEntry> nips) {
  cat.catnip = std::move(nips);
  return *this;
}

CatToken& CatToken::withMethods(std::vector<std::string> methods) {
  cat.catm = std::move(methods);
  return *this;
}

CatToken& CatToken::withAlpnProtocols(
    std::vector<std::vector<uint8_t>> protocols) {
  cat.catalpn = std::move(protocols);
  return *this;
}

CatToken& CatToken::withHeaderMatches(CatHostHeaderMatchList cath) {
  cat.cath = std::move(cath);
  return *this;
}

CatToken& CatToken::withCountries(const std::vector<std::string>& countries) {
  cat.catgeoiso3166 = countries;
  return *this;
}

CatToken& CatToken::withTokenPublicKeyThumbprint(
    std::vector<uint8_t> thumbprint) {
  cat.cattpk = std::move(thumbprint);
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

CatToken& CatToken::withInterfaceData(CatIfData data) {
  informational.catifdata = std::move(data);
  return *this;
}

CatToken& CatToken::withConfirmation(CatConfirmation cnf) {
  dpop.cnf = std::move(cnf);
  return *this;
}

CatToken& CatToken::withDpopClaim(CatDpopSettings dpop_claim) {
  dpop.catdpop = std::move(dpop_claim);
  return *this;
}

CatToken& CatToken::withInterfaceClaim(CatRequestDirective interface_claim) {
  request.catif = std::move(interface_claim);
  return *this;
}

CatToken& CatToken::withRequestClaim(CatRequestDirective request_claim) {
  request.catr = std::move(request_claim);
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
