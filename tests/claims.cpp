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
        .withCwtId("test-token-id")
        .withVersion("1.0");
        
    
    CHECK(token.core.iss == "https://example.com");
    REQUIRE(token.core.aud.has_value());
    CHECK(token.core.aud->size() == 2);
    CHECK((*token.core.aud)[0] == "https://api.example.com");
    CHECK((*token.core.aud)[1] == "https://service.example.com");
    CHECK(token.core.cti == "test-token-id");
    CHECK(token.cat.catv == "1.0");
}

TEST_CASE("CatToken CAT claims") {
    auto token = CatToken()
        .withUsageLimit(100)
        .withReplayProtection("nonce-12345")
        .withProofOfPossession(true)
        .withGeoCoordinate(37.7749, -122.4194, 100.0)
        .withGeohash("9q8yy")
        .withGeoAltitude(150)
        .withNetworkInterfaces({"192.168.1.0/24", "10.0.0.0/8"})
        .withMethods("GET,POST")
        .withAlpnProtocols({"h2", "http/1.1"})
        .withHosts({"api.example.com", "*.example.org"})
        .withCountries({"US", "CA", "GB"})
        .withTokenPublicKeyThumbprint("thumbprint-data");
        
    
    CHECK(token.cat.catu == 100);
    CHECK(token.cat.catreplay == "nonce-12345");
    CHECK(token.cat.catpor == true);
    CHECK(token.cat.geohash == "9q8yy");
    CHECK(token.cat.catgeoalt == 150);
    CHECK(token.cat.catm == "GET,POST");
    CHECK(token.cat.cattpk == "thumbprint-data");
    
    REQUIRE(token.cat.catgeocoord.has_value());
    CHECK(token.cat.catgeocoord->lat == doctest::Approx(37.7749));
    CHECK(token.cat.catgeocoord->lon == doctest::Approx(-122.4194));
    REQUIRE(token.cat.catgeocoord->accuracy.has_value());
    CHECK(*token.cat.catgeocoord->accuracy == doctest::Approx(100.0));
    
    REQUIRE(token.cat.catnip.has_value());
    CHECK(token.cat.catnip->size() == 2);
    CHECK((*token.cat.catnip)[0] == "192.168.1.0/24");
    
    REQUIRE(token.cat.catalpn.has_value());
    CHECK(token.cat.catalpn->size() == 2);
    CHECK((*token.cat.catalpn)[0] == "h2");
    
    REQUIRE(token.cat.cath.has_value());
    CHECK(token.cat.cath->size() == 2);
    CHECK((*token.cat.cath)[0] == "api.example.com");
    
    REQUIRE(token.cat.catgeoiso3166.has_value());
    CHECK(token.cat.catgeoiso3166->size() == 3);
    CHECK((*token.cat.catgeoiso3166)[0] == "US");
}

TEST_CASE("GeoCoordinate create_validated") {
    // Test valid coordinates at compile time (values scaled by 10000)
    constexpr auto coord1 = GeoCoordinate::create_validated<407128, -740060>();
    CHECK(coord1.lat == doctest::Approx(40.7128));
    CHECK(coord1.lon == doctest::Approx(-74.0060));
    CHECK_FALSE(coord1.accuracy.has_value());
    
    // Test boundary values
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
    CHECK_FALSE(token.cat.catgeoalt);
    CHECK_FALSE(token.cat.cattpk.has_value());
}