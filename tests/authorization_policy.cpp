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
#include "catapult/dpop.hpp"
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

  // Populated by acceptProofOfPossession so tests can verify that the
  // request-side PolicyContext reached the hook untouched.
  std::optional<std::string> last_client_id;
  std::optional<std::string> last_client_ip;
  std::optional<int> last_moqt_action;

  bool acceptProofOfPossession(const CatProofOfPossession&,
                               const PolicyContext& ctx) override {
    por_seen = true;
    if (ctx.client_id) last_client_id = std::string{*ctx.client_id};
    if (ctx.client_ip) last_client_ip = std::string{*ctx.client_ip};
    last_moqt_action = ctx.moqt_action;
    return accept_por;
  }
  bool acceptDpopBinding(const CatDpopSettings&,
                         const PolicyContext&) override {
    dpop_seen = true;
    return accept_dpop;
  }
  bool acceptRequestDirective(std::string_view claim,
                              const CatRequestDirective&,
                              const PolicyContext&) override {
    if (claim == "catif") {
      if_seen = true;
      return accept_if;
    }
    r_seen = true;
    return accept_r;
  }
  bool acceptGeoIso3166(const std::vector<std::string>&,
                        const PolicyContext&) override {
    iso_seen = true;
    return accept_iso;
  }
  bool acceptGeohash(const GeohashClaimValue&,
                     const PolicyContext&) override {
    geohash_seen = true;
    return accept_geohash;
  }
  bool acceptGeoAltitude(const GeoAltitude&, const PolicyContext&) override {
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

  TEST_CASE("PolicyContext is forwarded to accept*() unmodified") {
    // A shared validator behind a high-concurrency relay must be able to
    // hand per-request facts (client identity, MOQT action) to the hook
    // without the library reshaping or hiding them. Prove the caller's
    // PolicyContext reaches the callback byte-for-byte.
    auto token = baseToken();
    CatProofOfPossession por;
    por.probability = 1.0;
    por.identifier = {0x01};
    token.cat.catpor = por;

    RecordingPolicy policy;
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&policy);

    PolicyContext ctx;
    std::string client_id = "session-42";
    std::string client_ip = "203.0.113.9";
    ctx.client_id = client_id;
    ctx.client_ip = client_ip;
    ctx.moqt_action = 7;

    CHECK_NOTHROW(validator.validate(token, ctx));
    CHECK(policy.por_seen);
    REQUIRE(policy.last_client_id.has_value());
    CHECK(*policy.last_client_id == client_id);
    REQUIRE(policy.last_client_ip.has_value());
    CHECK(*policy.last_client_ip == client_ip);
    REQUIRE(policy.last_moqt_action.has_value());
    CHECK(*policy.last_moqt_action == 7);
  }

  TEST_CASE("Single-arg validate supplies an empty PolicyContext") {
    // The token-only overload must still work for callers that have no
    // request context yet, delegating with a default-constructed context.
    auto token = baseToken();
    CatProofOfPossession por;
    por.probability = 1.0;
    por.identifier = {0x01};
    token.cat.catpor = por;

    RecordingPolicy policy;
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&policy);
    CHECK_NOTHROW(validator.validate(token));
    CHECK(policy.por_seen);
    CHECK_FALSE(policy.last_client_id.has_value());
    CHECK_FALSE(policy.last_client_ip.has_value());
    CHECK_FALSE(policy.last_moqt_action.has_value());
  }

  TEST_CASE("Required context fields: missing client_ip is rejected") {
    // A deployment that pins allow-lists on client IP must be able to say
    // "the request MUST carry a client_ip" at validator-construction time.
    // The check runs before the hook fires, so a hook that forgets to
    // validate its own inputs cannot silently succeed.
    auto token = baseToken();
    CatProofOfPossession por;
    por.probability = 1.0;
    por.identifier = {0x01};
    token.cat.catpor = por;

    RecordingPolicy policy;
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&policy);
    RequiredPolicyContextFields required;
    required.client_ip = true;
    validator.withRequiredContextFields(required);

    CHECK_THROWS_AS(validator.validate(token), MissingRequiredClaimError);
    // The hook must not have been called: the required-field check runs
    // before dispatch.
    CHECK_FALSE(policy.por_seen);
  }

  TEST_CASE("Required context fields: all populated admits token") {
    auto token = baseToken();
    CatProofOfPossession por;
    por.probability = 1.0;
    por.identifier = {0x01};
    token.cat.catpor = por;

    RecordingPolicy policy;
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&policy);
    validator.withRequiredContextFields(RequiredPolicyContextFields::all());

    PolicyContext ctx;
    std::string client_id = "session-1";
    std::string client_ip = "203.0.113.9";
    std::string ns = "example/live";
    std::string track = "audio";
    std::string session = "conn-42";
    DpopPayload payload{7, "example/live", "audio"};
    // The required-fields check only inspects the pointer for non-null.
    ctx.client_id = client_id;
    ctx.client_ip = client_ip;
    ctx.dpop_proof = &payload;
    ctx.moqt_action = 7;
    ctx.moqt_namespace = ns;
    ctx.moqt_track = track;
    ctx.session_id = session;
    ctx.request_time = std::chrono::system_clock::now();

    CHECK_NOTHROW(validator.validate(token, ctx));
    CHECK(policy.por_seen);
  }

  TEST_CASE(
      "Required context fields: not enforced when no gated claim is present") {
    // Required-field enforcement is scoped to tokens that would actually
    // reach the hook. A plain token with no hook-relevant claims must
    // still validate even when the validator is configured to require
    // every context field.
    auto token = baseToken();
    CatTokenValidator validator;
    validator.withRequiredContextFields(RequiredPolicyContextFields::all());
    CHECK_NOTHROW(validator.validate(token));
  }

  TEST_CASE(
      "Required context fields: missing dpop_proof pointer is rejected") {
    auto token = baseToken();
    CatDpopSettings settings;
    settings.window_seconds = 60;
    token.dpop.catdpop = settings;

    RecordingPolicy policy;
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&policy);
    RequiredPolicyContextFields required;
    required.dpop_proof = true;
    validator.withRequiredContextFields(required);

    PolicyContext ctx;  // dpop_proof stays nullptr
    CHECK_THROWS_AS(validator.validate(token, ctx), MissingRequiredClaimError);
    CHECK_FALSE(policy.dpop_seen);
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
