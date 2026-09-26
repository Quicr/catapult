/**
 * @file reference_policies.cpp
 * @brief Tests for the shipped reference policies (IpAllowlistPolicy,
 *        DpopBindingPolicy, ChainedPolicy).
 */

#include <doctest/doctest.h>

#include <chrono>
#include <stdexcept>
#include <string>
#include <vector>

#include "catapult/authorization_policy.hpp"
#include "catapult/dpop.hpp"
#include "catapult/reference_policies.hpp"
#include "catapult/token.hpp"
#include "catapult/validator.hpp"

using namespace catapult;
using namespace std::chrono_literals;

namespace {

CatToken baseToken() {
  auto now = std::chrono::system_clock::now();
  return CatToken()
      .withIssuer("https://issuer.example")
      .withAudience({"https://relay.example"})
      .withExpiration(now + 1h)
      .withCwtIdString("ref-policy-test");
}

}  // namespace

TEST_SUITE("IpAllowlistPolicy — parsing") {
  TEST_CASE("bare IPv4 address becomes a /32 entry") {
    IpAllowlistPolicy p({"10.0.0.5"});
    CHECK(p.size() == 1);
    CHECK(p.contains("10.0.0.5"));
    CHECK_FALSE(p.contains("10.0.0.6"));
  }

  TEST_CASE("IPv4 /24 matches every host in the subnet") {
    IpAllowlistPolicy p({"10.0.0.0/24"});
    CHECK(p.contains("10.0.0.0"));
    CHECK(p.contains("10.0.0.1"));
    CHECK(p.contains("10.0.0.255"));
    CHECK_FALSE(p.contains("10.0.1.0"));
    CHECK_FALSE(p.contains("9.255.255.255"));
  }

  TEST_CASE("IPv4 non-byte-aligned prefix masks correctly") {
    // 10.0.0.0/28 covers 10.0.0.0..10.0.0.15
    IpAllowlistPolicy p({"10.0.0.0/28"});
    CHECK(p.contains("10.0.0.0"));
    CHECK(p.contains("10.0.0.15"));
    CHECK_FALSE(p.contains("10.0.0.16"));
    CHECK_FALSE(p.contains("10.0.0.17"));
  }

  TEST_CASE("bare IPv6 address becomes a /128 entry") {
    IpAllowlistPolicy p({"2001:db8::1"});
    CHECK(p.contains("2001:db8::1"));
    CHECK_FALSE(p.contains("2001:db8::2"));
  }

  TEST_CASE("IPv6 /32 CIDR matches inside the subnet") {
    IpAllowlistPolicy p({"2001:db8::/32"});
    CHECK(p.contains("2001:db8::1"));
    CHECK(p.contains("2001:db8:cafe::1"));
    CHECK_FALSE(p.contains("2001:db9::1"));
  }

  TEST_CASE("multiple entries are additive") {
    IpAllowlistPolicy p({"10.0.0.0/24", "192.168.1.42", "2001:db8::/32"});
    CHECK(p.contains("10.0.0.7"));
    CHECK(p.contains("192.168.1.42"));
    CHECK(p.contains("2001:db8::beef"));
    CHECK_FALSE(p.contains("192.168.1.43"));
  }

  TEST_CASE("v4 and v6 do not cross-match") {
    IpAllowlistPolicy v4({"10.0.0.0/8"});
    CHECK_FALSE(v4.contains("2001:db8::1"));

    IpAllowlistPolicy v6({"2001:db8::/32"});
    CHECK_FALSE(v6.contains("10.0.0.1"));
  }

  TEST_CASE("malformed entries throw at construction") {
    CHECK_THROWS_AS(IpAllowlistPolicy({"not-an-ip"}), std::invalid_argument);
    CHECK_THROWS_AS(IpAllowlistPolicy({"10.0.0.1/33"}), std::invalid_argument);
    CHECK_THROWS_AS(IpAllowlistPolicy({"2001:db8::/129"}),
                    std::invalid_argument);
    CHECK_THROWS_AS(IpAllowlistPolicy({"10.0.0.1/"}), std::invalid_argument);
  }

  TEST_CASE("garbage in client_ip does not match anything") {
    IpAllowlistPolicy p({"10.0.0.0/8"});
    CHECK_FALSE(p.contains("garbage"));
    CHECK_FALSE(p.contains(""));
  }
}

TEST_SUITE("IpAllowlistPolicy — validator integration") {
  TEST_CASE("in-range IP admits a token carrying a gated claim") {
    auto token = baseToken();
    token.cat.catgeoiso3166 = std::vector<std::string>{"US"};

    IpAllowlistPolicy p({"10.0.0.0/8"});
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&p);

    PolicyContext ctx;
    std::string_view ip{"10.1.2.3"};
    ctx.client_ip = ip;
    CHECK_NOTHROW(validator.validate(token, ctx));
  }

  TEST_CASE("out-of-range IP rejects the same token") {
    auto token = baseToken();
    token.cat.catgeoiso3166 = std::vector<std::string>{"US"};

    IpAllowlistPolicy p({"10.0.0.0/8"});
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&p);

    PolicyContext ctx;
    std::string_view ip{"192.168.1.1"};
    ctx.client_ip = ip;
    CHECK_THROWS_AS(validator.validate(token, ctx), GeographicValidationError);
  }

  TEST_CASE("missing client_ip is a policy failure, not a permissive pass") {
    auto token = baseToken();
    token.cat.catgeoiso3166 = std::vector<std::string>{"US"};

    IpAllowlistPolicy p({"10.0.0.0/8"});
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&p);

    PolicyContext ctx;  // client_ip = nullopt
    CHECK_THROWS_AS(validator.validate(token, ctx), GeographicValidationError);
  }
}

TEST_SUITE("DpopBindingPolicy") {
  TEST_CASE("catdpop with a proof on ctx admits") {
    auto token = baseToken();
    CatDpopSettings s;
    s.window_seconds = 60;
    s.honor_jti = true;
    token.dpop.catdpop = s;

    DpopBindingPolicy p;
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&p);

    DpopPayload proof(0, "", "");
    PolicyContext ctx;
    ctx.dpop_proof = &proof;
    CHECK_NOTHROW(validator.validate(token, ctx));
  }

  TEST_CASE("catdpop without a proof on ctx rejects") {
    auto token = baseToken();
    CatDpopSettings s;
    s.window_seconds = 60;
    token.dpop.catdpop = s;

    DpopBindingPolicy p;
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&p);

    PolicyContext ctx;  // dpop_proof = nullptr
    CHECK_THROWS_AS(validator.validate(token, ctx), InvalidClaimValueError);
  }

  TEST_CASE("overlay tightens window and enables honor_jti") {
    DpopValidationSettings dst(300s);
    dst.set_jti_processing(false);
    CHECK(dst.get_effective_window() == 300s);
    CHECK_FALSE(dst.get_jti_processing());

    DpopBindingPolicy p(&dst);

    auto token = baseToken();
    CatDpopSettings wire;
    wire.window_seconds = 30;   // tightens
    wire.honor_jti = true;      // enables
    token.dpop.catdpop = wire;

    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&p);
    DpopPayload proof(0, "", "");
    PolicyContext ctx;
    ctx.dpop_proof = &proof;
    CHECK_NOTHROW(validator.validate(token, ctx));

    CHECK(dst.get_effective_window() == 30s);
    CHECK(dst.get_jti_processing());
  }

  TEST_CASE("overlay does not widen a shorter window") {
    DpopValidationSettings dst(30s);
    DpopBindingPolicy p(&dst);

    auto token = baseToken();
    CatDpopSettings wire;
    wire.window_seconds = 600;  // wider — must be ignored
    token.dpop.catdpop = wire;

    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&p);
    DpopPayload proof(0, "", "");
    PolicyContext ctx;
    ctx.dpop_proof = &proof;
    CHECK_NOTHROW(validator.validate(token, ctx));

    CHECK(dst.get_effective_window() == 30s);
  }
}

TEST_SUITE("ChainedPolicy") {
  TEST_CASE("all-accepting chain admits") {
    PermissivePolicy a;
    PermissivePolicy b;
    ChainedPolicy chain({&a, &b});

    auto token = baseToken();
    token.cat.catgeoiso3166 = std::vector<std::string>{"US"};

    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&chain);
    PolicyContext ctx;
    CHECK_NOTHROW(validator.validate(token, ctx));
  }

  TEST_CASE("one rejecting policy short-circuits the chain") {
    PermissivePolicy a;
    RejectingPolicy b;
    ChainedPolicy chain({&a, &b});

    auto token = baseToken();
    token.cat.catgeoiso3166 = std::vector<std::string>{"US"};

    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&chain);
    PolicyContext ctx;
    CHECK_THROWS_AS(validator.validate(token, ctx), GeographicValidationError);
  }

  TEST_CASE("compose IpAllowlist + DpopBinding") {
    IpAllowlistPolicy ip({"10.0.0.0/8"});
    DpopBindingPolicy dpop;
    ChainedPolicy chain({&ip, &dpop});

    auto token = baseToken();
    token.cat.catgeoiso3166 = std::vector<std::string>{"US"};
    CatDpopSettings s;
    s.window_seconds = 60;
    token.dpop.catdpop = s;

    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&chain);

    // IP in range + proof present → admit.
    {
      DpopPayload proof(0, "", "");
      PolicyContext ctx;
      std::string_view ip_sv{"10.1.2.3"};
      ctx.client_ip = ip_sv;
      ctx.dpop_proof = &proof;
      CHECK_NOTHROW(validator.validate(token, ctx));
    }
    // IP in range but no proof → reject on DPoP.
    {
      PolicyContext ctx;
      std::string_view ip_sv{"10.1.2.3"};
      ctx.client_ip = ip_sv;
      CHECK_THROWS_AS(validator.validate(token, ctx), InvalidClaimValueError);
    }
    // IP out of range + proof present → reject on geo (IP check fires
    // for the catgeoiso3166 hook).
    {
      DpopPayload proof(0, "", "");
      PolicyContext ctx;
      std::string_view ip_sv{"192.168.1.1"};
      ctx.client_ip = ip_sv;
      ctx.dpop_proof = &proof;
      CHECK_THROWS_AS(validator.validate(token, ctx),
                      GeographicValidationError);
    }
  }
}
