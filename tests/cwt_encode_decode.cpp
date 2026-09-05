#include <doctest/doctest.h>
#include "catapult/cwt.hpp"
#include "catapult/crypto.hpp"

using namespace catapult;

TEST_SUITE("CWT Encode/Decode Tests") {

    auto createFullTestToken() {
        CatProofOfPossession por;
        por.probability = 0.25;
        por.identifier = {0x01, 0x02, 0x03};

        CatUriMatchMap catu;
        catu.components[3] = UriComponentMatch{UriMatchType::Prefix,
                                               {'/', 't', 'e', 's', 't'}};

        return CatToken()
            .withIssuer("https://test-issuer.com")
            .withAudience({"https://service1.com", "https://service2.com"})
            .withExpiration(std::chrono::system_clock::from_time_t(1234567890))
            .withNotBefore(std::chrono::system_clock::from_time_t(1234567800))
            .withCwtIdString("test-cwt-id-12345")
            .withVersion(1)
            .withUriMatch(catu)
            .withReplayProtection(CatReplayMode::RejectOnReplay)
            .withProofOfPossession(por)
            .withGeoCoordinate(37.7749, -122.4194, 10.5)
            .withGeohash(GeohashClaimValue{std::string{"9q8yy"}});
    }

    auto createMinimalTestToken() {
        return CatToken()
            .withIssuer("minimal-issuer")
            .withAudience({"minimal-audience"});
    }

    TEST_CASE("Encode payload with full token") {
        auto token = createFullTestToken();
        Cwt cwt(ALG_ES256, token);

        auto encoded = cwt.encodePayload();

        CHECK_FALSE(encoded.empty());
        CHECK(encoded.size() > 10);
    }

    TEST_CASE("Encode payload with minimal token") {
        auto token = createMinimalTestToken();
        Cwt cwt(ALG_HMAC256_256, token);

        auto encoded = cwt.encodePayload();

        CHECK_FALSE(encoded.empty());
    }

    TEST_CASE("Encode then decode round trip - full token") {
        auto originalToken = createFullTestToken();
        Cwt cwt(ALG_PS256, originalToken);

        auto encoded = cwt.encodePayload();
        CHECK_FALSE(encoded.empty());

        auto decodedToken = Cwt::decodePayload(encoded);

        // Verify core claims
        CHECK(decodedToken.core.iss == originalToken.core.iss);
        CHECK(decodedToken.core.aud == originalToken.core.aud);
        CHECK(decodedToken.core.exp == originalToken.core.exp);
        CHECK(decodedToken.core.nbf == originalToken.core.nbf);
        CHECK(decodedToken.core.cti == originalToken.core.cti);

        // Verify CAT claims
        CHECK(decodedToken.cat.catv == originalToken.cat.catv);
        CHECK(decodedToken.cat.catreplay == originalToken.cat.catreplay);
        REQUIRE(decodedToken.cat.geohash.has_value());
        REQUIRE(originalToken.cat.geohash.has_value());
        CHECK(decodedToken.cat.geohash->asString() ==
              originalToken.cat.geohash->asString());
    }

    TEST_CASE("Encode then decode round trip - minimal token") {
        auto originalToken = createMinimalTestToken();
        Cwt cwt(ALG_ES256, originalToken);

        auto encoded = cwt.encodePayload();
        CHECK_FALSE(encoded.empty());

        auto decodedToken = Cwt::decodePayload(encoded);

        CHECK(decodedToken.core.iss == originalToken.core.iss);
        CHECK(decodedToken.core.aud == originalToken.core.aud);
    }

    TEST_CASE("Decode empty payload throws error") {
        std::vector<uint8_t> emptyPayload;

        CHECK_THROWS_AS(Cwt::decodePayload(emptyPayload), InvalidCborError);
    }

    TEST_CASE("Decode invalid CBOR data throws error") {
        std::vector<uint8_t> invalidCbor = {0xFF, 0xFE, 0xFD, 0xFC};

        CHECK_THROWS_AS(Cwt::decodePayload(invalidCbor), InvalidCborError);
    }

    TEST_CASE("Decode non-map CBOR throws error") {
        std::vector<uint8_t> cborArray = {0x80};

        CHECK_THROWS_AS(Cwt::decodePayload(cborArray), InvalidTokenFormatError);
    }

    TEST_CASE("Encode token with optional claims") {
        auto token = CatToken()
            .withIssuer("test-issuer")
            .withAudience({"test-aud"})
            .withExpiration(std::chrono::system_clock::from_time_t(2147483647))
            .withVersion(7)
            .withReplayProtection(CatReplayMode::RevokeOnReplay);

        Cwt cwt(ALG_HMAC256_256, token);
        auto encoded = cwt.encodePayload();
        auto decoded = Cwt::decodePayload(encoded);

        CHECK(decoded.core.iss.value() == "test-issuer");
        CHECK(decoded.core.aud.value().size() == 1);
        CHECK(decoded.core.aud.value()[0] == "test-aud");
        CHECK(decoded.core.exp.value() == 2147483647);
        CHECK(decoded.cat.catv.value() == 7u);
        CHECK(decoded.cat.catreplay.value() == CatReplayMode::RevokeOnReplay);
    }

    TEST_CASE("Encode token with geographic data") {
        auto token = CatToken()
            .withIssuer("geo-issuer")
            .withAudience({"geo-service"})
            .withGeoCoordinate(40.7128, -74.0060, 50.0)
            .withGeohash(GeohashClaimValue{std::string{"dr5reg"}});

        Cwt cwt(ALG_ES256, token);
        auto encoded = cwt.encodePayload();
        auto decoded = Cwt::decodePayload(encoded);

        CHECK(decoded.core.iss.value() == "geo-issuer");
        REQUIRE(decoded.cat.geohash.has_value());
        CHECK(decoded.cat.geohash->asString() == "dr5reg");
    }

    TEST_CASE("Encode token with typed CAT claims") {
        CatProofOfPossession porA;
        porA.probability = 1.0;
        porA.identifier = {0xAA};

        CatProofOfPossession porB;
        porB.probability = 0.0;
        porB.identifier = {0xBB};

        auto tokenA = CatToken()
            .withIssuer("bool-issuer")
            .withAudience({"bool-service"})
            .withProofOfPossession(porA);
        auto tokenB = CatToken()
            .withIssuer("bool-issuer")
            .withAudience({"bool-service"})
            .withProofOfPossession(porB);

        Cwt cwtA(ALG_HMAC256_256, tokenA);
        Cwt cwtB(ALG_HMAC256_256, tokenB);

        auto decodedA = Cwt::decodePayload(cwtA.encodePayload());
        auto decodedB = Cwt::decodePayload(cwtB.encodePayload());

        REQUIRE(decodedA.cat.catpor.has_value());
        REQUIRE(decodedB.cat.catpor.has_value());
        CHECK(decodedA.cat.catpor->probability == doctest::Approx(1.0));
        CHECK(decodedB.cat.catpor->probability == doctest::Approx(0.0));
    }

    TEST_CASE("Encode token with numeric claims") {
        CatUriMatchMap catu;
        catu.components[3] =
            UriComponentMatch{UriMatchType::Exact, {'/', 'v', '4', '2'}};

        auto token = CatToken()
            .withIssuer("numeric-issuer")
            .withAudience({"numeric-service"})
            .withUriMatch(catu)
            .withExpiration(std::chrono::system_clock::from_time_t(1700000000))
            .withNotBefore(std::chrono::system_clock::from_time_t(1600000000));

        Cwt cwt(ALG_PS256, token);
        auto encoded = cwt.encodePayload();
        auto decoded = Cwt::decodePayload(encoded);

        REQUIRE(decoded.cat.catu.has_value());
        CHECK(decoded.cat.catu->components.size() == 1);
        CHECK(decoded.core.exp.value() == 1700000000);
        CHECK(decoded.core.nbf.value() == 1600000000);
    }

    TEST_CASE("Oversized encoded CWT is rejected before crypto/CBOR work") {
        std::vector<uint8_t> keyBytes(32, 0x11);
        HmacSha256Algorithm hmac(keyBytes);
        std::string oversize(8192, 'A');
        CHECK_THROWS_AS(Cwt::validateCwtBase64(oversize, hmac),
                        InvalidTokenFormatError);
    }

    TEST_CASE("Decoder rejects malformed 'iss' (int instead of string)") {
        std::vector<uint8_t> cbor = {0xa1, 0x01, 0x18, 0x2a};
        CHECK_THROWS_AS(Cwt::decodePayload(cbor), InvalidClaimValueError);
    }

    TEST_CASE("Decoder rejects malformed 'exp' (negative)") {
        std::vector<uint8_t> cbor = {0xa1, 0x04, 0x20};
        CHECK_THROWS_AS(Cwt::decodePayload(cbor), InvalidClaimValueError);
    }

    TEST_CASE("Decoder rejects non-uint claim key") {
        std::vector<uint8_t> cbor = {0xa1, 0x63, 0x69, 0x73, 0x73, 0x61, 0x78};
        CHECK_THROWS_AS(Cwt::decodePayload(cbor), InvalidTokenFormatError);
    }

    TEST_CASE("Encode large payload") {
        std::vector<std::string> largeAudience;
        for (int i = 0; i < 100; ++i) {
            largeAudience.push_back("audience" + std::to_string(i) +
                                    ".example.com");
        }

        auto token = CatToken()
            .withIssuer("large-payload-issuer")
            .withAudience(largeAudience);

        Cwt cwt(ALG_ES256, token);
        auto encoded = cwt.encodePayload();
        auto decoded = Cwt::decodePayload(encoded);

        CHECK(decoded.core.iss.value() == "large-payload-issuer");
        CHECK(decoded.core.aud.value().size() == 100);
        CHECK(decoded.core.aud.value()[0] == "audience0.example.com");
        CHECK(decoded.core.aud.value()[99] == "audience99.example.com");
    }
}
