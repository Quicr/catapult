#include <doctest/doctest.h>
#include "catapult/cwt.hpp"
#include "catapult/crypto.hpp"

using namespace catapult;

TEST_SUITE("CWT Encode/Decode Tests") {

    auto createFullTestToken() {
        return CatToken()
            .withIssuer("https://test-issuer.com")
            .withAudience({"https://service1.com", "https://service2.com"})
            .withExpiration(std::chrono::system_clock::from_time_t(1234567890))
            .withNotBefore(std::chrono::system_clock::from_time_t(1234567800))
            .withCwtId("test-cwt-id-12345")
            .withVersion("1.2.3")
            .withUsageLimit(100)
            .withReplayProtection("unique-nonce-value")
            .withProofOfPossession(true)
            .withGeoCoordinate(37.7749, -122.4194, 10.5)
            .withGeohash("9q8yy");
            
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
        CHECK(encoded.size() > 10); // Should have substantial content
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
        
        // Encode
        auto encoded = cwt.encodePayload();
        CHECK_FALSE(encoded.empty());
        
        // Decode
        auto decodedToken = Cwt::decodePayload(encoded);
        
        // Verify core claims
        CHECK(decodedToken.core.iss == originalToken.core.iss);
        CHECK(decodedToken.core.aud == originalToken.core.aud);
        CHECK(decodedToken.core.exp == originalToken.core.exp);
        CHECK(decodedToken.core.nbf == originalToken.core.nbf);
        CHECK(decodedToken.core.cti == originalToken.core.cti);
        
        // Verify CAT claims
        CHECK(decodedToken.cat.catv == originalToken.cat.catv);
        CHECK(decodedToken.cat.catu == originalToken.cat.catu);
        CHECK(decodedToken.cat.catreplay == originalToken.cat.catreplay);
        CHECK(decodedToken.cat.catpor == originalToken.cat.catpor);
        CHECK(decodedToken.cat.geohash == originalToken.cat.geohash);
    }

    TEST_CASE("Encode then decode round trip - minimal token") {
        auto originalToken = createMinimalTestToken();
        Cwt cwt(ALG_ES256, originalToken);
        
        // Encode
        auto encoded = cwt.encodePayload();
        CHECK_FALSE(encoded.empty());
        
        // Decode
        auto decodedToken = Cwt::decodePayload(encoded);
        
        // Verify basic claims are preserved
        CHECK(decodedToken.core.iss == originalToken.core.iss);
        CHECK(decodedToken.core.aud == originalToken.core.aud);
    }

    TEST_CASE("Decode empty payload throws error") {
        std::vector<uint8_t> emptyPayload;
        
        CHECK_THROWS_AS(Cwt::decodePayload(emptyPayload), InvalidCborError);
    }

    TEST_CASE("Decode invalid CBOR data throws error") {
        std::vector<uint8_t> invalidCbor = {0xFF, 0xFE, 0xFD, 0xFC}; // Invalid CBOR
        
        CHECK_THROWS_AS(Cwt::decodePayload(invalidCbor), InvalidCborError);
    }

    TEST_CASE("Decode non-map CBOR throws error") {
        // Create a valid CBOR array instead of map
        std::vector<uint8_t> cborArray = {0x80}; // Empty CBOR array
        
        CHECK_THROWS_AS(Cwt::decodePayload(cborArray), InvalidTokenFormatError);
    }

    TEST_CASE("Encode token with optional claims") {
        auto token = CatToken()
            .withIssuer("test-issuer")
            .withAudience({"test-aud"})
            .withExpiration(std::chrono::system_clock::from_time_t(2147483647))
            .withVersion("test-version")
            .withReplayProtection("test-replay");
            
            
        Cwt cwt(ALG_HMAC256_256, token);
        auto encoded = cwt.encodePayload();
        auto decoded = Cwt::decodePayload(encoded);
        
        CHECK(decoded.core.iss.value() == "test-issuer");
        CHECK(decoded.core.aud.value().size() == 1);
        CHECK(decoded.core.aud.value()[0] == "test-aud");
        CHECK(decoded.core.exp.value() == 2147483647);
        CHECK(decoded.cat.catv.value() == "test-version");
        CHECK(decoded.cat.catreplay.value() == "test-replay");
    }

    TEST_CASE("Encode token with geographic data") {
        auto token = CatToken()
            .withIssuer("geo-issuer")
            .withAudience({"geo-service"})
            .withGeoCoordinate(40.7128, -74.0060, 50.0) // NYC with accuracy
            .withGeohash("dr5reg");
            
            
        Cwt cwt(ALG_ES256, token);
        auto encoded = cwt.encodePayload();
        auto decoded = Cwt::decodePayload(encoded);
        
        CHECK(decoded.core.iss.value() == "geo-issuer");
        CHECK(decoded.cat.geohash.value() == "dr5reg");
        // Note: Geographic coordinate decoding would need to be implemented
        // in the actual decodePayload method to fully test this
    }

    TEST_CASE("Encode token with boolean claims") {
        auto tokenTrue = CatToken()
            .withIssuer("bool-issuer")
            .withAudience({"bool-service"})
            .withProofOfPossession(true);
            
            
        auto tokenFalse = CatToken()
            .withIssuer("bool-issuer")
            .withAudience({"bool-service"})
            .withProofOfPossession(false);
            
            
        Cwt cwtTrue(ALG_HMAC256_256, tokenTrue);
        Cwt cwtFalse(ALG_HMAC256_256, tokenFalse);
        
        auto encodedTrue = cwtTrue.encodePayload();
        auto encodedFalse = cwtFalse.encodePayload();
        
        auto decodedTrue = Cwt::decodePayload(encodedTrue);
        auto decodedFalse = Cwt::decodePayload(encodedFalse);
        
        CHECK(decodedTrue.cat.catpor.value() == true);
        CHECK(decodedFalse.cat.catpor.value() == false);
    }

    TEST_CASE("Encode token with numeric claims") {
        auto token = CatToken()
            .withIssuer("numeric-issuer")
            .withAudience({"numeric-service"})
            .withUsageLimit(42)
            .withExpiration(std::chrono::system_clock::from_time_t(1700000000))
            .withNotBefore(std::chrono::system_clock::from_time_t(1600000000));
            
            
        Cwt cwt(ALG_PS256, token);
        auto encoded = cwt.encodePayload();
        auto decoded = Cwt::decodePayload(encoded);
        
        CHECK(decoded.cat.catu.value() == 42);
        CHECK(decoded.core.exp.value() == 1700000000);
        CHECK(decoded.core.nbf.value() == 1600000000);
    }

    TEST_CASE("Encode large payload") {
        std::vector<std::string> largeAudience;
        for (int i = 0; i < 100; ++i) {
            largeAudience.push_back("audience" + std::to_string(i) + ".example.com");
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