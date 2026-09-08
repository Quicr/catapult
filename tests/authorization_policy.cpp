/**
 * @file authorization_policy.cpp
 * @brief Tests for the AuthorizationPolicyHook enforcement contract.
 *
 * The library-side rule: any token carrying `catpor`, `catdpop`, `catif`,
 * `catr`, `catgeoiso3166`, `geohash`, or `catgeoalt` MUST be rejected
 * unless an operator-supplied policy has explicitly accepted the claim.
 * Silently admitting would let a misconfigured relay believe it was
 * enforcing the claim when it was not.
 */

#include <doctest/doctest.h>

#include <chrono>
#include <string>
#include <string_view>
#include <vector>

#include "catapult/authorization_policy.hpp"
#include "catapult/claims.hpp"
#include "catapult/token.hpp"
#include "catapult/validator.hpp"

using namespace catapult;
using namespace std::chrono_literals;

namespace {
CatToken baseToken() {
  auto now = std::chrono::system_clock::now();
  return CatToken()
      .withIssuer("https://trusted-issuer.com")
      .withAudience({"https://my-service.com"})
      .withExpiration(now + 1h)
      .withCwtIdString("policy-test-token");
}

// Recording policy: reports which accept*() methods were consulted and
// returns a configurable verdict. Used to prove both that the validator
// reaches the hook and that a `false` verdict is honoured per-claim.
class RecordingPolicy final : public AuthorizationPolicyHook {
 public:
  bool por_seen = false;
  bool dpop_seen = false;
  bool if_seen = false;
  bool r_seen = false;
  bool iso_seen = false;
  bool geohash_seen = false;
  bool geoalt_seen = false;

  bool accept_por = true;
  bool accept_dpop = true;
  bool accept_if = true;
  bool accept_r = true;
  bool accept_iso = true;
  bool accept_geohash = true;
  bool accept_geoalt = true;

  bool acceptProofOfPossession(const CatProofOfPossession&) override {
    por_seen = true;
    return accept_por;
  }
  bool acceptDpopBinding(const CatDpopSettings&) override {
    dpop_seen = true;
    return accept_dpop;
  }
  bool acceptRequestDirective(std::string_view claim,
                              const CatRequestDirective&) override {
    if (claim == "catif") {
      if_seen = true;
      return accept_if;
    }
    r_seen = true;
    return accept_r;
  }
  bool acceptGeoIso3166(const std::vector<std::string>&) override {
    iso_seen = true;
    return accept_iso;
  }
  bool acceptGeohash(const GeohashClaimValue&) override {
    geohash_seen = true;
    return accept_geohash;
  }
  bool acceptGeoAltitude(const GeoAltitude&) override {
    geoalt_seen = true;
    return accept_geoalt;
  }
};
}  // namespace

TEST_SUITE("AuthorizationPolicyHook — validator wiring") {
  TEST_CASE("Token without any semantic claim validates with no hook") {
    // Baseline: a token that carries none of the claims that require
    // operator context must validate cleanly without any policy hook
    // installed. Otherwise the fail-closed check would over-reach and
    // reject perfectly ordinary tokens.
    auto token = baseToken();
    CatTokenValidator validator;
    CHECK_NOTHROW(validator.validate(token));
  }

  TEST_CASE("catpor without a hook is rejected") {
    auto token = baseToken();
    CatProofOfPossession por;
    por.probability = 1.0;
    por.identifier = {0x01, 0x02, 0x03};
    token.cat.catpor = por;

    CatTokenValidator validator;
    CHECK_THROWS_AS(validator.validate(token), MissingRequiredClaimError);
  }

  TEST_CASE("catpor with an accepting hook validates") {
    auto token = baseToken();
    CatProofOfPossession por;
    por.probability = 1.0;
    por.identifier = {0x01, 0x02, 0x03};
    token.cat.catpor = por;

    RecordingPolicy policy;
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&policy);
    CHECK_NOTHROW(validator.validate(token));
    CHECK(policy.por_seen);
  }

  TEST_CASE("catpor with a rejecting hook fails as invalid claim") {
    auto token = baseToken();
    CatProofOfPossession por;
    por.probability = 0.5;
    por.identifier = {0xaa};
    token.cat.catpor = por;

    RecordingPolicy policy;
    policy.accept_por = false;
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&policy);
    CHECK_THROWS_AS(validator.validate(token), InvalidClaimValueError);
    CHECK(policy.por_seen);
  }

  TEST_CASE("catdpop is gated by the hook") {
    auto token = baseToken();
    CatDpopSettings settings;
    settings.window_seconds = 60;
    settings.honor_jti = true;
    token.dpop.catdpop = settings;

    // No hook: fail closed.
    CatTokenValidator no_hook;
    CHECK_THROWS_AS(no_hook.validate(token), MissingRequiredClaimError);

    // Rejecting hook: invalid-claim error, hook was consulted.
    RecordingPolicy policy;
    policy.accept_dpop = false;
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&policy);
    CHECK_THROWS_AS(validator.validate(token), InvalidClaimValueError);
    CHECK(policy.dpop_seen);
  }

  TEST_CASE("catif and catr are dispatched by claim name") {
    auto token = baseToken();
    CatRequestDirective d;
    d.raw = {0xa0};  // empty CBOR map
    token.request.catif = d;
    token.request.catr = d;

    RecordingPolicy policy;
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&policy);
    CHECK_NOTHROW(validator.validate(token));
    CHECK(policy.if_seen);
    CHECK(policy.r_seen);
  }

  TEST_CASE("catif rejected by hook throws InvalidClaimValueError") {
    auto token = baseToken();
    CatRequestDirective d;
    d.raw = {0xa0};
    token.request.catif = d;

    RecordingPolicy policy;
    policy.accept_if = false;
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&policy);
    CHECK_THROWS_AS(validator.validate(token), InvalidClaimValueError);
    CHECK(policy.if_seen);
    // catr is not present so its accept path must not be consulted.
    CHECK_FALSE(policy.r_seen);
  }

  TEST_CASE("catgeoiso3166 without a hook is rejected") {
    auto token = baseToken();
    token.cat.catgeoiso3166 = std::vector<std::string>{"US", "CA"};

    CatTokenValidator validator;
    CHECK_THROWS_AS(validator.validate(token), MissingRequiredClaimError);
  }

  TEST_CASE("catgeoiso3166 rejected by hook throws GeographicValidationError") {
    auto token = baseToken();
    token.cat.catgeoiso3166 = std::vector<std::string>{"US"};

    RecordingPolicy policy;
    policy.accept_iso = false;
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&policy);
    CHECK_THROWS_AS(validator.validate(token), GeographicValidationError);
    CHECK(policy.iso_seen);
  }

  TEST_CASE("geohash without a hook is rejected") {
    auto token = baseToken().withGeohash(
        GeohashClaimValue{std::string{"dr5reg"}});

    CatTokenValidator validator;
    CHECK_THROWS_AS(validator.validate(token), MissingRequiredClaimError);
  }

  TEST_CASE("geohash rejected by hook throws GeographicValidationError") {
    auto token = baseToken().withGeohash(
        GeohashClaimValue{std::string{"dr5reg"}});

    RecordingPolicy policy;
    policy.accept_geohash = false;
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&policy);
    CHECK_THROWS_AS(validator.validate(token), GeographicValidationError);
    CHECK(policy.geohash_seen);
  }

  TEST_CASE("catgeoalt without a hook is rejected") {
    auto token = baseToken();
    token.cat.catgeoalt = GeoAltitude{100};

    CatTokenValidator validator;
    CHECK_THROWS_AS(validator.validate(token), MissingRequiredClaimError);
  }

  TEST_CASE("catgeoalt rejected by hook throws GeographicValidationError") {
    auto token = baseToken();
    token.cat.catgeoalt = GeoAltitude{100};

    RecordingPolicy policy;
    policy.accept_geoalt = false;
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&policy);
    CHECK_THROWS_AS(validator.validate(token), GeographicValidationError);
    CHECK(policy.geoalt_seen);
  }

  TEST_CASE("PermissivePolicy admits every gated claim") {
    // Sanity check: the shipped PermissivePolicy default reaches every
    // accept*() method and returns true, matching its documented "test
    // suite / staged rollout" role.
    auto token = baseToken().withGeohash(
        GeohashClaimValue{std::string{"dr5reg"}});
    CatProofOfPossession por;
    por.probability = 1.0;
    por.identifier = {0x01};
    token.cat.catpor = por;
    token.cat.catgeoiso3166 = std::vector<std::string>{"US"};
    token.cat.catgeoalt = GeoAltitude{100};
    CatDpopSettings settings;
    settings.window_seconds = 30;
    token.dpop.catdpop = settings;
    CatRequestDirective d;
    d.raw = {0xa0};
    token.request.catif = d;
    token.request.catr = d;

    PermissivePolicy permissive;
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&permissive);
    CHECK_NOTHROW(validator.validate(token));
  }

  TEST_CASE("RejectingPolicy denies every gated claim it sees") {
    // First claim encountered wins — catpor is checked before the geo
    // claims in the validator, so RejectingPolicy fails there.
    auto token = baseToken();
    CatProofOfPossession por;
    por.probability = 1.0;
    por.identifier = {0x01};
    token.cat.catpor = por;

    RejectingPolicy reject;
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&reject);
    CHECK_THROWS_AS(validator.validate(token), InvalidClaimValueError);
  }

  TEST_CASE("Absent claim does not consult its hook path") {
    // A hook must not be asked about a claim the token does not carry.
    // This matters because a policy may cache negative decisions and
    // spurious accept calls could poison that cache.
    auto token = baseToken();
    token.cat.catgeoiso3166 = std::vector<std::string>{"US"};

    RecordingPolicy policy;
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&policy);
    CHECK_NOTHROW(validator.validate(token));
    CHECK(policy.iso_seen);
    CHECK_FALSE(policy.por_seen);
    CHECK_FALSE(policy.dpop_seen);
    CHECK_FALSE(policy.if_seen);
    CHECK_FALSE(policy.r_seen);
    CHECK_FALSE(policy.geohash_seen);
    CHECK_FALSE(policy.geoalt_seen);
  }

  TEST_CASE("tryValidate surfaces the policy failure via error code") {
    auto token = baseToken();
    token.cat.catgeoiso3166 = std::vector<std::string>{"US"};

    // No hook installed — tryValidate must return a non-SUCCESS code
    // rather than allow the missing-hook exception to escape.
    CatTokenValidator validator;
    auto code = validator.tryValidate(token);
    CHECK(code != CatErrorCode::SUCCESS);
  }
}
