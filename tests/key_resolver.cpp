/**
 * @file key_resolver.cpp
 * @brief Tests for the KeyResolver hook and StaticKeyResolver default.
 */

#include <doctest/doctest.h>

#include <memory>
#include <vector>

#include "catapult/crypto.hpp"
#include "catapult/cwt.hpp"
#include "catapult/key_resolver.hpp"
#include "catapult/token.hpp"

using namespace catapult;

namespace {

std::shared_ptr<const HmacSha256Algorithm> makeHmac(uint8_t seed) {
  std::vector<uint8_t> key(32, seed);
  return std::make_shared<HmacSha256Algorithm>(key);
}

CatToken makeToken() {
  CatToken t;
  t.core.iss = "issuer";
  t.core.aud = std::vector<std::string>{"audience"};
  t.core.exp = 4102444800;  // 2100-01-01
  return t;
}

}  // namespace

TEST_SUITE("StaticKeyResolver") {
  TEST_CASE("Empty resolver rejects every lookup") {
    StaticKeyResolver resolver;
    CHECK_THROWS_AS(resolver.resolve("kid-1", ALG_HMAC256_256),
                    MissingKeyError);
    CHECK(resolver.size() == 0);
  }

  TEST_CASE("Unknown kid throws MissingKeyError") {
    StaticKeyResolver resolver;
    resolver.add("kid-1", ALG_HMAC256_256, makeHmac(0x11));
    CHECK_THROWS_AS(resolver.resolve("kid-unknown", ALG_HMAC256_256),
                    MissingKeyError);
  }

  TEST_CASE("Alg mismatch on a known kid throws MissingKeyError") {
    StaticKeyResolver resolver;
    resolver.add("kid-1", ALG_HMAC256_256, makeHmac(0x11));
    // Same kid, different alg — the resolver treats (kid, alg) as the
    // full lookup key; an attacker who forces an alg swap cannot land
    // on the HMAC key by presenting kid-1 with alg=ES256.
    CHECK_THROWS_AS(resolver.resolve("kid-1", ALG_ES256),
                    MissingKeyError);
  }

  TEST_CASE("Null algorithm on add() is rejected") {
    StaticKeyResolver resolver;
    CHECK_THROWS_AS(
        resolver.add("kid-1", ALG_HMAC256_256,
                     std::shared_ptr<const CryptographicAlgorithm>{}),
        MissingKeyError);
  }

  TEST_CASE("Registered (kid, alg) resolves to the same algorithm") {
    StaticKeyResolver resolver;
    auto hmac = makeHmac(0x22);
    resolver.add("kid-a", ALG_HMAC256_256, hmac);
    const auto& resolved = resolver.resolve("kid-a", ALG_HMAC256_256);
    CHECK(&resolved == hmac.get());
    CHECK(resolver.size() == 1);
  }
}

TEST_SUITE("Cwt::validateCwt with KeyResolver") {
  TEST_CASE("Round-trip through a StaticKeyResolver succeeds") {
    auto hmac = makeHmac(0x33);
    Cwt cwt(ALG_HMAC256_256, makeToken());
    cwt.withKeyId("kid-round-trip");
    auto bytes = cwt.createCwt(CwtMode::MACed, *hmac);

    StaticKeyResolver resolver;
    resolver.add("kid-round-trip", ALG_HMAC256_256, hmac);

    auto validated = Cwt::validateCwt(bytes, resolver);
    // Payload survives round-trip; header.kid on the returned Cwt is a
    // library implementation detail (currently not propagated), but the
    // signature verified against the resolver-provided key, which is the
    // property under test.
    CHECK(validated.payload.core.iss.value_or("") == "issuer");
  }

  TEST_CASE("Resolver miss fails the whole validation") {
    auto hmac = makeHmac(0x44);
    Cwt cwt(ALG_HMAC256_256, makeToken());
    cwt.withKeyId("kid-A");
    auto bytes = cwt.createCwt(CwtMode::MACed, *hmac);

    StaticKeyResolver resolver;
    resolver.add("kid-B", ALG_HMAC256_256, hmac);

    CHECK_THROWS_AS(Cwt::validateCwt(bytes, resolver), MissingKeyError);
  }
}
