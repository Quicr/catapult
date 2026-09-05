#include <doctest/doctest.h>
#include "catapult/token.hpp"
#include <chrono>

using namespace catapult;

TEST_CASE("CatToken basic claims") {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);

    auto token = CatToken()
        .withIssuer("https://example.com")
        .withAudience({"https://api.example.com", "https://service.example.com"})
        .withExpiration(exp)
        .withNotBefore(now)
        .withCwtIdString("test-token-id")
        .withVersion(1);

    CHECK(token.core.iss == "https://example.com");
    REQUIRE(token.core.aud.has_value());
    CHECK(token.core.aud->size() == 2);
    CHECK((*token.core.aud)[0] == "https://api.example.com");
    CHECK((*token.core.aud)[1] == "https://service.example.com");
    REQUIRE(token.core.cti.has_value());
    CHECK(std::string(token.core.cti->begin(), token.core.cti->end()) ==
          "test-token-id");
    CHECK(token.cat.catv == 1u);
}

TEST_CASE("CatToken CAT claims") {
    CatProofOfPossession por;
    por.probability = 1.0;
    por.identifier = {0xAA, 0xBB, 0xCC};

    CatNipEntry nip_a{.tag = 260, .value = {0xC0, 0xA8, 0x01, 0x00}};
    CatNipEntry nip_b{.tag = 261, .value = {0x0A, 0x00, 0x00, 0x00}};

    CatUriMatchMap catu;
    catu.components[1] = UriComponentMatch{UriMatchType::Exact,
                                           {'a', 'p', 'i', '.', 'e', 'x'}};

    CatHostHeaderMatchList cath;
    cath.entries.push_back(
        {"host", UriComponentMatch{UriMatchType::Exact, {'a', 'p', 'i'}}});
    cath.entries.push_back(
        {"origin", UriComponentMatch{UriMatchType::Prefix, {'*'}}});

    auto token = CatToken()
        .withUriMatch(catu)
        .withReplayProtection(CatReplayMode::RejectOnReplay)
        .withProofOfPossession(por)
        .withGeoCoordinate(37.7749, -122.4194, 100.0)
        .withGeohash(GeohashClaimValue{std::string{"9q8yy"}})
        .withGeoAltitude(GeoAltitude{150})
        .withNetworkInterfaces({nip_a, nip_b})
        .withMethods({"GET", "POST"})
        .withAlpnProtocols({{'h', '2'}, {'h', 't', 't', 'p', '/', '1', '.', '1'}})
        .withHeaderMatches(cath)
        .withCountries({"US", "CA", "GB"})
        .withTokenPublicKeyThumbprint({0x01, 0x02, 0x03, 0x04});

    REQUIRE(token.cat.catu.has_value());
    CHECK(token.cat.catu->components.size() == 1);

    REQUIRE(token.cat.catreplay.has_value());
    CHECK(*token.cat.catreplay == CatReplayMode::RejectOnReplay);

    REQUIRE(token.cat.catpor.has_value());
    CHECK(token.cat.catpor->probability == doctest::Approx(1.0));
    CHECK(token.cat.catpor->identifier.size() == 3);

    REQUIRE(token.cat.geohash.has_value());
    CHECK(token.cat.geohash->isString());
    CHECK(token.cat.geohash->asString() == "9q8yy");

    REQUIRE(token.cat.catgeoalt.has_value());
    CHECK(token.cat.catgeoalt->altitude == 150);

    REQUIRE(token.cat.catm.has_value());
    CHECK(token.cat.catm->size() == 2);
    CHECK((*token.cat.catm)[0] == "GET");

    REQUIRE(token.cat.cattpk.has_value());
    CHECK(token.cat.cattpk->size() == 4);

    REQUIRE(token.cat.catgeocoord.has_value());
    CHECK(token.cat.catgeocoord->lat == doctest::Approx(37.7749));
    CHECK(token.cat.catgeocoord->lon == doctest::Approx(-122.4194));
    REQUIRE(token.cat.catgeocoord->radius.has_value());
    CHECK(*token.cat.catgeocoord->radius == doctest::Approx(100.0));

    REQUIRE(token.cat.catnip.has_value());
    CHECK(token.cat.catnip->size() == 2);
    CHECK((*token.cat.catnip)[0].tag == 260);

    REQUIRE(token.cat.catalpn.has_value());
    CHECK(token.cat.catalpn->size() == 2);
    CHECK((*token.cat.catalpn)[0].size() == 2);

    REQUIRE(token.cat.cath.has_value());
    CHECK(token.cat.cath->entries.size() == 2);
    CHECK(token.cat.cath->entries[0].name == "host");

    REQUIRE(token.cat.catgeoiso3166.has_value());
    CHECK(token.cat.catgeoiso3166->size() == 3);
    CHECK((*token.cat.catgeoiso3166)[0] == "US");
}

TEST_CASE("GeoCoordinate create_validated") {
    constexpr auto coord1 = GeoCoordinate::create_validated<407128, -740060>();
    CHECK(coord1.lat == doctest::Approx(40.7128));
    CHECK(coord1.lon == doctest::Approx(-74.0060));
    CHECK_FALSE(coord1.radius.has_value());

    constexpr auto coord_max = GeoCoordinate::create_validated<900000, 1800000>();
    CHECK(coord_max.lat == doctest::Approx(90.0));
    CHECK(coord_max.lon == doctest::Approx(180.0));

    constexpr auto coord_min = GeoCoordinate::create_validated<-900000, -1800000>();
    CHECK(coord_min.lat == doctest::Approx(-90.0));
    CHECK(coord_min.lon == doctest::Approx(-180.0));

    constexpr auto coord_zero = GeoCoordinate::create_validated<0, 0>();
    CHECK(coord_zero.lat == doctest::Approx(0.0));
    CHECK(coord_zero.lon == doctest::Approx(0.0));
}

TEST_CASE("Empty token") {
    CatToken token;

    CHECK_FALSE(token.core.iss.has_value());
    CHECK_FALSE(token.core.aud.has_value());
    CHECK_FALSE(token.core.exp.has_value());
    CHECK_FALSE(token.core.nbf.has_value());
    CHECK_FALSE(token.core.cti.has_value());

    CHECK_FALSE(token.cat.catreplay.has_value());
    CHECK_FALSE(token.cat.catpor.has_value());
    CHECK_FALSE(token.cat.catv.has_value());
    CHECK_FALSE(token.cat.catnip.has_value());
    CHECK_FALSE(token.cat.catu.has_value());
    CHECK_FALSE(token.cat.catm.has_value());
    CHECK_FALSE(token.cat.catalpn.has_value());
    CHECK_FALSE(token.cat.cath.has_value());
    CHECK_FALSE(token.cat.catgeoiso3166.has_value());
    CHECK_FALSE(token.cat.catgeocoord.has_value());
    CHECK_FALSE(token.cat.geohash.has_value());
    CHECK_FALSE(token.cat.catgeoalt.has_value());
    CHECK_FALSE(token.cat.cattpk.has_value());
}
