/**
 * @file cat_token.hpp
 * @brief CAT token class
 */

#pragma once

#include <chrono>
#include <concepts>
#include <memory>
#include <stdexcept>
#include <unordered_map>

#include "claims.hpp"
#include "composite.hpp"
#include "internal/memory_pool.hpp"
#include "moqt_claims.hpp"

namespace catapult {

// Forward declarations for MOQT Claims
struct ExtendedCatClaims;

/**
 * @brief Main CAT token class containing all claim groups
 *
 * Usage patterns:
 * 1. Direct modification of existing tokens:
 *    token.withIssuer("example.com").withAudience({"client1", "client2"});
 *
 * 2. Factory methods for new tokens:
 *    auto tokenPtr = CatToken::createValidated(core_claims, cat_claims);
 */
// Forward declaration
class CatTokenBuilder;

/**
 * @brief Main CAT token class containing all claim groups
 *
 * Usage patterns:
 * 1. Builder pattern (recommended):
 *    auto token = CatToken::builder()
 *        .issuer("example.com")
 *        .audience("client")
 *        .expiresIn(std::chrono::hours{1})
 *        .build();
 *
 * 2. Direct modification:
 *    token.withIssuer("example.com").withAudience({"client1", "client2"});
 *
 * 3. Factory methods:
 *    auto tokenPtr = CatToken::createValidated(core_claims, cat_claims);
 */
class CatToken {
 public:
  CoreClaims core{};                    ///< Core CWT claims
  CatClaims cat{};                      ///< CAT-specific claims
  InformationalClaims informational{};  ///< Informational claims
  DpopClaims dpop{};                    ///< DPoP claims
  RequestClaims request{};              ///< Request claims
  CompositeClaims composite{};          ///< Composite claims
  ExtendedCatClaims extended{};         ///< Extended claims including MOQT
  std::unordered_map<int64_t, std::string> custom{};  ///< Custom claims

  CatToken() = default;
  virtual ~CatToken() = default;

  /**
   * @brief Create a builder for fluent token construction
   */
  [[nodiscard]] static CatTokenBuilder builder();

  /**
   * @brief Constructor for runtime initialization with validation
   */
  CatToken(CoreClaims core_claims, CatClaims cat_claims = {},
           InformationalClaims info_claims = {}, DpopClaims dpop_claims = {},
           RequestClaims req_claims = {}, CompositeClaims comp_claims = {})
      : core(std::move(core_claims)),
        cat(std::move(cat_claims)),
        informational(std::move(info_claims)),
        dpop(std::move(dpop_claims)),
        request(std::move(req_claims)),
        composite(std::move(comp_claims)) {
    validateTokenStructure();
  }

  /**
   * @brief Factory method for creating validated tokens with memory pool
   * optimization
   */
  template <
      typename CoreClaims_T = CoreClaims, typename CatClaims_T = CatClaims,
      typename InfoClaims_T = InformationalClaims,
      typename DpopClaims_T = DpopClaims, typename ReqClaims_T = RequestClaims,
      typename CompClaims_T = CompositeClaims>
  static auto createValidated(CoreClaims_T&& core_claims,
                              CatClaims_T&& cat_claims = {},
                              InfoClaims_T&& info_claims = {},
                              DpopClaims_T&& dpop_claims = {},
                              ReqClaims_T&& req_claims = {},
                              CompClaims_T&& comp_claims = {})
    requires std::constructible_from<CoreClaims, CoreClaims_T> &&
             std::constructible_from<CatClaims, CatClaims_T> &&
             std::constructible_from<InformationalClaims, InfoClaims_T> &&
             std::constructible_from<DpopClaims, DpopClaims_T> &&
             std::constructible_from<RequestClaims, ReqClaims_T> &&
             std::constructible_from<CompositeClaims, CompClaims_T>
  {
    static thread_local ThreadLocalMemoryPool<CatToken, 256> pool;
    auto tokenPtr = pool.make();
    tokenPtr->core = std::forward<CoreClaims_T>(core_claims);
    tokenPtr->cat = std::forward<CatClaims_T>(cat_claims);
    tokenPtr->informational = std::forward<InfoClaims_T>(info_claims);
    tokenPtr->dpop = std::forward<DpopClaims_T>(dpop_claims);
    tokenPtr->request = std::forward<ReqClaims_T>(req_claims);
    tokenPtr->composite = std::forward<CompClaims_T>(comp_claims);
    tokenPtr->validateTokenStructure();
    return tokenPtr;
  }

  /**
   * @brief Factory method for creating validated tokens without memory pool
   * (for stack allocation)
   */
  template <
      typename CoreClaims_T = CoreClaims, typename CatClaims_T = CatClaims,
      typename InfoClaims_T = InformationalClaims,
      typename DpopClaims_T = DpopClaims, typename ReqClaims_T = RequestClaims,
      typename CompClaims_T = CompositeClaims>
  static CatToken createValidatedStack(CoreClaims_T&& core_claims,
                                       CatClaims_T&& cat_claims = {},
                                       InfoClaims_T&& info_claims = {},
                                       DpopClaims_T&& dpop_claims = {},
                                       ReqClaims_T&& req_claims = {},
                                       CompClaims_T&& comp_claims = {})
    requires std::constructible_from<CoreClaims, CoreClaims_T> &&
             std::constructible_from<CatClaims, CatClaims_T> &&
             std::constructible_from<InformationalClaims, InfoClaims_T> &&
             std::constructible_from<DpopClaims, DpopClaims_T> &&
             std::constructible_from<RequestClaims, ReqClaims_T> &&
             std::constructible_from<CompositeClaims, CompClaims_T>
  {
    CatToken token;
    token.core = std::forward<CoreClaims_T>(core_claims);
    token.cat = std::forward<CatClaims_T>(cat_claims);
    token.informational = std::forward<InfoClaims_T>(info_claims);
    token.dpop = std::forward<DpopClaims_T>(dpop_claims);
    token.request = std::forward<ReqClaims_T>(req_claims);
    token.composite = std::forward<CompClaims_T>(comp_claims);
    token.validateTokenStructure();
    return token;
  }

  /**
   * @brief Validate token structure at runtime with enhanced bounds checking
   */
  void validateTokenStructure() const {
    // Validate that essential claims are present and valid
    // Note: Time relationship validation (EXP vs NBF) is handled by
    // CatTokenValidator during validation, not during construction

    // Additional bounds checking for time values
    // TODO: Revisit these limits based on real-world usage
    constexpr int64_t MAX_TIMESTAMP =
        32503680000;  // Year 3000 (more generous for testing)
    constexpr int64_t MIN_TIMESTAMP = 946684800;  // Year 2000

    if (core.exp.has_value()) {
      if (core.exp.value() > MAX_TIMESTAMP ||
          core.exp.value() < MIN_TIMESTAMP) {
        throw InvalidClaimValueError(
            "Expiration time is outside reasonable bounds");
      }
    }

    if (core.nbf.has_value()) {
      if (core.nbf.value() > MAX_TIMESTAMP ||
          core.nbf.value() < MIN_TIMESTAMP) {
        throw InvalidClaimValueError(
            "Not-before time is outside reasonable bounds");
      }
    }

    // `catu` used to carry a single uint usage-limit. In CTA-5007-B it is a
    // URI-component match map; the bounds check moved to the validator.

    // Validate string lengths to prevent DoS attacks
    if (core.iss.has_value() && core.iss->length() > 256) {
      throw InvalidClaimValueError("Issuer string too long");
    }

    // Validate audience list size
    if (core.aud.has_value() && core.aud->size() > 100) {
      throw InvalidClaimValueError("Too many audiences specified");
    }
  }

  /**
   * @brief Fluent interface methods for building CAT tokens
   * @{
   */
  CatToken& withIssuer(const std::string& issuer);
  CatToken& withAudience(const std::vector<std::string>& audience);
  CatToken& withExpiration(const std::chrono::system_clock::time_point& exp);
  CatToken& withNotBefore(const std::chrono::system_clock::time_point& nbf);
  CatToken& withCwtId(std::vector<uint8_t> cti);
  CatToken& withCwtIdString(std::string_view cti);
  CatToken& withVersion(uint32_t version);
  CatToken& withUriMatch(CatUriMatchMap catu);
  CatToken& withReplayProtection(CatReplayMode mode);
  CatToken& withProofOfPossession(CatProofOfPossession por);
  CatToken& withGeoCoordinate(double lat, double lon,
                              std::optional<double> radius = std::nullopt);
  CatToken& withGeohash(GeohashClaimValue geohash);
  CatToken& withGeoAltitude(GeoAltitude altitude);
  CatToken& withNetworkInterfaces(std::vector<CatNipEntry> nips);
  CatToken& withMethods(std::vector<std::string> methods);
  CatToken& withAlpnProtocols(std::vector<std::vector<uint8_t>> protocols);
  CatToken& withHeaderMatches(CatHostHeaderMatchList cath);
  CatToken& withCountries(const std::vector<std::string>& countries);
  CatToken& withTokenPublicKeyThumbprint(std::vector<uint8_t> thumbprint);

  // New claim methods
  CatToken& withSubject(const std::string& subject);
  CatToken& withIssuedAt(const std::chrono::system_clock::time_point& iat);
  CatToken& withInterfaceData(CatIfData data);
  CatToken& withConfirmation(CatConfirmation cnf);
  CatToken& withDpopClaim(CatDpopSettings dpop);
  CatToken& withInterfaceClaim(CatRequestDirective interface_claim);
  CatToken& withRequestClaim(CatRequestDirective request_claim);

  // Composite claim builder methods
  CatToken& withOrComposite(std::unique_ptr<OrClaim> orClaim);
  CatToken& withNorComposite(std::unique_ptr<NorClaim> norClaim);
  CatToken& withAndComposite(std::unique_ptr<AndClaim> andClaim);

  // MOQT claim builder methods

  /**
   * @brief Set pre-built MOQT claims directly
   *
   * Use when you have already constructed a MoqtClaims object with multiple
   * scopes configured.
   */
  CatToken& withMoqtClaims(MoqtClaims claims);

  /**
   * @brief Add a MOQT scope with runtime-determined actions
   *
   * Preferred when: actions come from configuration, user input, or are
   * determined at runtime (e.g., loaded from a database or policy file).
   *
   * @param actions  Range of action integers (validated at runtime)
   * @param namespace_match  Single match condition for namespace
   * @param track_match  Single match condition for track
   */
  template <std::ranges::range ActionRange>
  CatToken& withMoqtActionsDynamic(const ActionRange& actions,
                                   MoqtBinaryMatch namespace_match,
                                   MoqtBinaryMatch track_match);

  /**
   * @brief Add a MOQT scope with runtime actions and compound matches
   *
   * Preferred when: actions are runtime-determined AND you need multiple
   * AND-ed match conditions per dimension.
   *
   * @param actions  Range of action integers (validated at runtime)
   * @param namespace_match  Compound match (AND of conditions) for namespace
   * @param track_match  Compound match (AND of conditions) for track
   */
  template <std::ranges::range ActionRange>
  CatToken& withMoqtActionsDynamic(const ActionRange& actions,
                                   MoqtCompoundMatch namespace_match,
                                   MoqtCompoundMatch track_match);

  /**
   * @brief Add a MOQT scope with compile-time validated actions
   *
   * Preferred when: the set of actions is known at compile time (e.g., a
   * publisher always gets PUBLISH + ANNOUNCE). Actions are validated via
   * static_assert — invalid actions produce a compile error, not a runtime
   * exception.
   *
   * @tparam Actions  MOQT action constants (compile-time validated)
   * @param namespace_match  Single match condition for namespace
   * @param track_match  Single match condition for track
   */
  template <int... Actions>
  CatToken& withMoqtActions(MoqtBinaryMatch namespace_match,
                            MoqtBinaryMatch track_match);

  /**
   * @brief Add a MOQT scope with compile-time actions and compound matches
   *
   * Preferred when: actions are compile-time constants AND you need multiple
   * AND-ed match conditions per dimension.
   *
   * @tparam Actions  MOQT action constants (compile-time validated)
   * @param namespace_match  Compound match (AND of conditions) for namespace
   * @param track_match  Compound match (AND of conditions) for track
   */
  template <int... Actions>
  CatToken& withMoqtActions(MoqtCompoundMatch namespace_match,
                            MoqtCompoundMatch track_match);

  CatToken& withMoqtRevalidationInterval(std::chrono::seconds interval);

  /** @} */  // end of BuilderMethods group
};

/**
 * @brief Compile-time claim validation utilities
 */
namespace claim_validation {
/**
 * @brief Validate claim at compile time
 */
template <int64_t ClaimId>
consteval bool validate_claim_id() noexcept {
  return composite_constants::is_valid_claim_id(ClaimId);
}

/**
 * @brief Type-safe claim identifier wrapper
 */
template <int64_t Id>
struct ClaimIdentifier {
  static constexpr int64_t value = Id;
  static_assert(validate_claim_id<Id>(), "Invalid claim identifier");
};

// Pre-defined claim identifiers with compile-time validation

// Core CWT claims
using IssuerClaim = ClaimIdentifier<CLAIM_ISS>;
using AudienceClaim = ClaimIdentifier<CLAIM_AUD>;
using SubjectClaim = ClaimIdentifier<CLAIM_SUB>;
using ExpirationClaim = ClaimIdentifier<CLAIM_EXP>;
using NotBeforeClaim = ClaimIdentifier<CLAIM_NBF>;
using IssuedAtClaim = ClaimIdentifier<CLAIM_IAT>;
using CwtIdClaim = ClaimIdentifier<CLAIM_CTI>;
using ConfirmationClaim = ClaimIdentifier<CLAIM_CNF>;

// CAT claims
using CatReplayClaim = ClaimIdentifier<CLAIM_CATREPLAY>;
using CatProofClaim = ClaimIdentifier<CLAIM_CATPOR>;
using CatVersionClaim = ClaimIdentifier<CLAIM_CATV>;
using CatNetworkInterfacesClaim = ClaimIdentifier<CLAIM_CATNIP>;
using CatUsageClaim = ClaimIdentifier<CLAIM_CATU>;
using CatMethodsClaim = ClaimIdentifier<CLAIM_CATM>;
using CatAlpnClaim = ClaimIdentifier<CLAIM_CATALPN>;
using CatHostsClaim = ClaimIdentifier<CLAIM_CATH>;
using CatGeoIsoClaim = ClaimIdentifier<CLAIM_CATGEOISO3166>;
using CatGeoCoordClaim = ClaimIdentifier<CLAIM_CATGEOCOORD>;
using GeohashClaim = ClaimIdentifier<CLAIM_GEOHASH>;
using CatGeoAltitudeClaim = ClaimIdentifier<CLAIM_CATGEOALT>;
using CatTokenPublicKeyClaim = ClaimIdentifier<CLAIM_CATTPK>;
using CatInterfaceDataClaim = ClaimIdentifier<CLAIM_CATIFDATA>;
using CatDpopClaim = ClaimIdentifier<CLAIM_CATDPOP>;
using CatInterfaceClaim = ClaimIdentifier<CLAIM_CATIF>;
using CatRequestClaim = ClaimIdentifier<CLAIM_CATR>;

// Composite claims
using OrClaim = ClaimIdentifier<CLAIM_OR>;
using NorClaim = ClaimIdentifier<CLAIM_NOR>;
using AndClaim = ClaimIdentifier<CLAIM_AND>;

// MOQT claims
using MoqtClaim = ClaimIdentifier<CLAIM_MOQT>;
using MoqtRevalidationClaim = ClaimIdentifier<CLAIM_MOQT_REVAL>;

/**
 * @brief Compile-time claim registry for validation and introspection
 */
template <typename... ClaimTypes>
struct ClaimRegistry {
  static constexpr size_t count = sizeof...(ClaimTypes);
  static constexpr std::array<int64_t, count> ids = {ClaimTypes::value...};

  template <int64_t Id>
  static constexpr bool contains() {
    return ((ClaimTypes::value == Id) || ...);
  }

  static constexpr bool is_valid_id(int64_t id) {
    return ((ClaimTypes::value == id) || ...);
  }
};

/**
 * @brief Registry of all standard claims for validation
 */
using StandardClaimRegistry = ClaimRegistry<
    IssuerClaim, AudienceClaim, SubjectClaim, ExpirationClaim, NotBeforeClaim,
    IssuedAtClaim, CwtIdClaim, ConfirmationClaim, CatReplayClaim, CatProofClaim,
    CatVersionClaim, CatNetworkInterfacesClaim, CatUsageClaim, CatMethodsClaim,
    CatAlpnClaim, CatHostsClaim, CatGeoIsoClaim, CatGeoCoordClaim, GeohashClaim,
    CatGeoAltitudeClaim, CatTokenPublicKeyClaim, CatInterfaceDataClaim,
    CatDpopClaim, CatInterfaceClaim, CatRequestClaim, OrClaim, NorClaim,
    AndClaim, MoqtClaim, MoqtRevalidationClaim>;
}  // namespace claim_validation

//
// Implementations for MOQT functionality
//

template <std::ranges::range ActionRange>
CatToken& CatToken::withMoqtActionsDynamic(const ActionRange& actions,
                                           MoqtBinaryMatch namespace_match,
                                           MoqtBinaryMatch track_match) {
  auto& moqt_claims = extended.getMoqtClaims();
  moqt_claims.addScope(actions, std::move(namespace_match),
                       std::move(track_match));
  return *this;
}

template <std::ranges::range ActionRange>
CatToken& CatToken::withMoqtActionsDynamic(const ActionRange& actions,
                                           MoqtCompoundMatch namespace_match,
                                           MoqtCompoundMatch track_match) {
  auto& moqt_claims = extended.getMoqtClaims();
  moqt_claims.addScope(actions, std::move(namespace_match),
                       std::move(track_match));
  return *this;
}

template <int... Actions>
CatToken& CatToken::withMoqtActions(MoqtBinaryMatch namespace_match,
                                    MoqtBinaryMatch track_match) {
  auto& moqt_claims = extended.getMoqtClaims();
  moqt_claims.template addCompileTimeScope<Actions...>(
      std::move(namespace_match), std::move(track_match));
  return *this;
}

template <int... Actions>
CatToken& CatToken::withMoqtActions(MoqtCompoundMatch namespace_match,
                                    MoqtCompoundMatch track_match) {
  auto& moqt_claims = extended.getMoqtClaims();
  moqt_claims.template addCompileTimeScope<Actions...>(
      std::move(namespace_match), std::move(track_match));
  return *this;
}

/**
 * @brief Runtime token factory functions
 */
namespace token_factory {

/**
 * @brief Create a token with geographic restrictions (runtime version)
 */
inline CatToken create_geo_token(const std::string& issuer,
                                 const std::string& audience, double lat,
                                 double lon) {
  if (lat < -90.0 || lat > 90.0 || lon < -180.0 || lon > 180.0) {
    throw std::invalid_argument("Invalid geographic coordinates");
  }

  CatToken token;
  token.core.iss = issuer;
  token.core.aud = std::vector<std::string>{audience};

  auto coord = GeoCoordinate::createSafe(lat, lon);
  if (!coord.has_value()) {
    throw std::invalid_argument("Failed to create valid geographic coordinate");
  }
  token.cat.catgeocoord = coord.value();

  return token;
}

/**
 * @brief Create a token with geographic restrictions (compile-time version)
 * @tparam LatInt Latitude as integer (lat * 10000)
 * @tparam LonInt Longitude as integer (lon * 10000)
 */
template <int LatInt, int LonInt>
CatToken create_geo_token_fixed(const std::string& issuer,
                                const std::string& audience) {
  constexpr double lat = static_cast<double>(LatInt) / 10000.0;
  constexpr double lon = static_cast<double>(LonInt) / 10000.0;

  static_assert(composite_constants::is_valid_latitude(lat),
                "Invalid latitude at compile time");
  static_assert(composite_constants::is_valid_longitude(lon),
                "Invalid longitude at compile time");

  CatToken token;
  token.core.iss = issuer;
  token.core.aud = std::vector<std::string>{audience};

  GeoCoordinate coord;
  coord.lat = lat;
  coord.lon = lon;
  token.cat.catgeocoord = coord;

  return token;
}
}  // namespace token_factory

/**
 * @brief Literal operators for common claim values
 */
namespace literals {
inline std::string operator""_catv(const char* str, size_t len) {
  return std::string(str, len);
}

inline std::string operator""_iss(const char* str, size_t len) {
  return std::string(str, len);
}
}  // namespace literals

/**
 * @brief Builder class for fluent CatToken construction
 */
class CatTokenBuilder {
 private:
  CatToken token_;

 public:
  CatTokenBuilder() = default;

  CatTokenBuilder& issuer(const std::string& iss);
  CatTokenBuilder& audience(const std::string& aud);
  CatTokenBuilder& audience(const std::vector<std::string>& auds);
  CatTokenBuilder& expiresAt(int64_t exp);
  CatTokenBuilder& expiresIn(std::chrono::seconds duration);
  CatTokenBuilder& notBefore(int64_t nbf);
  CatTokenBuilder& tokenId(std::vector<uint8_t> cti);
  CatTokenBuilder& tokenIdFromString(std::string_view cti);
  CatTokenBuilder& version(uint32_t v);
  CatTokenBuilder& uriMatch(CatUriMatchMap catu);
  CatTokenBuilder& replayMode(CatReplayMode mode);
  CatTokenBuilder& proofOfPossession(CatProofOfPossession por);
  CatTokenBuilder& subject(const std::string& sub);
  CatTokenBuilder& geoCoordinate(double lat, double lon,
                                 std::optional<double> radius = std::nullopt);
  CatTokenBuilder& geohash(GeohashClaimValue hash);
  CatTokenBuilder& altitude(GeoAltitude alt);
  CatTokenBuilder& networkInterfaces(std::vector<CatNipEntry> nips);
  CatTokenBuilder& methods(std::vector<std::string> m);
  CatTokenBuilder& alpn(std::vector<std::vector<uint8_t>> protocols);
  CatTokenBuilder& headerMatches(CatHostHeaderMatchList h);
  CatTokenBuilder& countries(const std::vector<std::string>& iso3166);
  CatTokenBuilder& dpopThumbprint(std::vector<uint8_t> jkt);
  [[nodiscard]] CatToken build();
};

inline CatTokenBuilder CatToken::builder() { return CatTokenBuilder{}; }

// CatTokenBuilder inline implementations
inline CatTokenBuilder& CatTokenBuilder::issuer(const std::string& iss) {
  token_.core.iss = iss;
  return *this;
}

inline CatTokenBuilder& CatTokenBuilder::audience(const std::string& aud) {
  token_.core.aud = std::vector<std::string>{aud};
  return *this;
}

inline CatTokenBuilder& CatTokenBuilder::audience(
    const std::vector<std::string>& auds) {
  token_.core.aud = auds;
  return *this;
}

inline CatTokenBuilder& CatTokenBuilder::expiresAt(int64_t exp) {
  token_.core.exp = exp;
  return *this;
}

inline CatTokenBuilder& CatTokenBuilder::expiresIn(
    std::chrono::seconds duration) {
  token_.core.exp = std::chrono::system_clock::to_time_t(
      std::chrono::system_clock::now() + duration);
  return *this;
}

inline CatTokenBuilder& CatTokenBuilder::notBefore(int64_t nbf) {
  token_.core.nbf = nbf;
  return *this;
}

inline CatTokenBuilder& CatTokenBuilder::tokenId(std::vector<uint8_t> cti) {
  token_.core.cti = std::move(cti);
  return *this;
}

inline CatTokenBuilder& CatTokenBuilder::tokenIdFromString(
    std::string_view cti) {
  token_.core.cti = std::vector<uint8_t>(cti.begin(), cti.end());
  return *this;
}

inline CatTokenBuilder& CatTokenBuilder::version(uint32_t v) {
  token_.cat.catv = v;
  return *this;
}

inline CatTokenBuilder& CatTokenBuilder::uriMatch(CatUriMatchMap catu) {
  token_.cat.catu = std::move(catu);
  return *this;
}

inline CatTokenBuilder& CatTokenBuilder::replayMode(CatReplayMode mode) {
  token_.cat.catreplay = mode;
  return *this;
}

inline CatTokenBuilder& CatTokenBuilder::proofOfPossession(
    CatProofOfPossession por) {
  token_.cat.catpor = std::move(por);
  return *this;
}

inline CatTokenBuilder& CatTokenBuilder::subject(const std::string& sub) {
  token_.informational.sub = sub;
  return *this;
}

inline CatTokenBuilder& CatTokenBuilder::geoCoordinate(
    double lat, double lon, std::optional<double> radius) {
  auto coord = GeoCoordinate::createSafe(lat, lon, radius);
  if (coord.has_value()) {
    token_.cat.catgeocoord = coord.value();
  }
  return *this;
}

inline CatTokenBuilder& CatTokenBuilder::geohash(GeohashClaimValue hash) {
  token_.cat.geohash = std::move(hash);
  return *this;
}

inline CatTokenBuilder& CatTokenBuilder::altitude(GeoAltitude alt) {
  token_.cat.catgeoalt = alt;
  return *this;
}

inline CatTokenBuilder& CatTokenBuilder::networkInterfaces(
    std::vector<CatNipEntry> nips) {
  token_.cat.catnip = std::move(nips);
  return *this;
}

inline CatTokenBuilder& CatTokenBuilder::methods(std::vector<std::string> m) {
  token_.cat.catm = std::move(m);
  return *this;
}

inline CatTokenBuilder& CatTokenBuilder::alpn(
    std::vector<std::vector<uint8_t>> protocols) {
  token_.cat.catalpn = std::move(protocols);
  return *this;
}

inline CatTokenBuilder& CatTokenBuilder::headerMatches(
    CatHostHeaderMatchList h) {
  token_.cat.cath = std::move(h);
  return *this;
}

inline CatTokenBuilder& CatTokenBuilder::countries(
    const std::vector<std::string>& iso3166) {
  token_.cat.catgeoiso3166 = iso3166;
  return *this;
}

inline CatTokenBuilder& CatTokenBuilder::dpopThumbprint(
    std::vector<uint8_t> jkt) {
  CatConfirmation cnf;
  cnf.jkt = std::move(jkt);
  token_.dpop.cnf = std::move(cnf);
  return *this;
}

inline CatToken CatTokenBuilder::build() {
  token_.validateTokenStructure();
  return std::move(token_);
}

}  // namespace catapult