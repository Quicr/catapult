/**
 * @file cat_token.hpp
 * @brief CAT token class
 */

#pragma once

#include <chrono>
#include <concepts>
#include <memory>
#include <unordered_map>

#include "claims.hpp"
#include "composite.hpp"
#include "memory_pool.hpp"
#include "moqt_claims.hpp"

namespace catapult {

// Forward declarations for MOQT Claims
class ExtendedCatClaims;

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

    // Enhanced usage limit validation
    if (cat.catu.has_value()) {
      if (cat.catu.value() == 0) {
        throw InvalidClaimValueError("Usage limit must be greater than zero");
      }
      constexpr uint32_t MAX_USAGE_LIMIT = 1000000;  // Reasonable upper bound
      if (cat.catu.value() > MAX_USAGE_LIMIT) {
        throw InvalidClaimValueError(
            "Usage limit exceeds maximum allowed value");
      }
    }

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
  CatToken& withCwtId(const std::string& cti);
  CatToken& withVersion(const std::string& version);
  CatToken& withUsageLimit(uint32_t limit);
  CatToken& withReplayProtection(const std::string& nonce);
  CatToken& withProofOfPossession(bool enabled);
  CatToken& withGeoCoordinate(double lat, double lon,
                              std::optional<double> accuracy = std::nullopt);
  CatToken& withGeohash(const std::string& geohash);
  CatToken& withGeoAltitude(int32_t altitude);
  CatToken& withNetworkInterfaces(const std::vector<std::string>& nips);
  CatToken& withMethods(const std::string& methods);
  CatToken& withAlpnProtocols(const std::vector<std::string>& protocols);
  CatToken& withHosts(const std::vector<std::string>& hosts);
  CatToken& withCountries(const std::vector<std::string>& countries);
  CatToken& withTokenPublicKeyThumbprint(const std::string& thumbprint);

  // New claim methods
  CatToken& withSubject(const std::string& subject);
  CatToken& withIssuedAt(const std::chrono::system_clock::time_point& iat);
  CatToken& withInterfaceData(const std::string& data);
  CatToken& withConfirmation(const std::string& cnf);
  CatToken& withDpopClaim(const std::string& dpop);
  CatToken& withInterfaceClaim(const std::string& interface);
  CatToken& withRequestClaim(const std::string& request);
  CatToken& withUriPatterns(const std::vector<std::string>& patterns);

  // Composite claim builder methods
  CatToken& withOrComposite(std::unique_ptr<OrClaim> orClaim);
  CatToken& withNorComposite(std::unique_ptr<NorClaim> norClaim);
  CatToken& withAndComposite(std::unique_ptr<AndClaim> andClaim);

  // MOQT claim builder methods
  CatToken& withMoqtClaims(MoqtClaims claims);

  template <std::ranges::range ActionRange>
  CatToken& withMoqtActionsDynamic(const ActionRange& actions,
                                   MoqtBinaryMatch namespace_match,
                                   MoqtBinaryMatch track_match);

  template <int... Actions>
  CatToken& withMoqtActions(MoqtBinaryMatch namespace_match,
                            MoqtBinaryMatch track_match);

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

template <int... Actions>
CatToken& CatToken::withMoqtActions(MoqtBinaryMatch namespace_match,
                                    MoqtBinaryMatch track_match) {
  auto& moqt_claims = extended.getMoqtClaims();
  moqt_claims.template addCompileTimeScope<Actions...>(
      std::move(namespace_match), std::move(track_match));
  return *this;
}

}  // namespace catapult