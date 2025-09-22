#include <doctest/doctest.h>
#include "catapult/claims.hpp"
#include "catapult/validator.hpp"
#include "catapult/crypto.hpp"
#include "catapult/cwt.hpp"
#include <chrono>

using namespace catapult;

auto createSampleToken() {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    
    CoreClaims core;
    core.iss = "https://example.com";
    core.aud = std::vector<std::string>{"https://api.example.com"};
    core.exp = std::chrono::duration_cast<std::chrono::seconds>(exp.time_since_epoch()).count();
    core.nbf = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    core.cti = "integration-test-token";
    
    CatClaims cat;
    cat.catv = "1.0";
    cat.catu = 100;
    cat.catreplay = "nonce-12345";
    cat.catpor = true;
    cat.catgeocoord = GeoCoordinate{37.7749, -122.4194, 100.0};
    cat.geohash = "9q8yy";
    
    return CatToken::createValidated(std::move(core), std::move(cat));
}

TEST_CASE("CompleteTokenLifecycle") {
    // Create a token
    auto token = createSampleToken();
    
    // Verify token properties
    CHECK(token->core.iss == "https://example.com");
    REQUIRE(token->core.aud.has_value());
    CHECK((*token->core.aud)[0] == "https://api.example.com");
    CHECK(token->core.cti == "integration-test-token");
    CHECK(token->cat.catv == "1.0");
    CHECK(token->cat.catu == 100);
    CHECK(token->cat.catreplay == "nonce-12345");
    CHECK(token->cat.catpor == true);
    CHECK(token->cat.geohash == "9q8yy");
    
    REQUIRE(token->cat.catgeocoord.has_value());
    CHECK(token->cat.catgeocoord->lat == doctest::Approx(37.7749));
    CHECK(token->cat.catgeocoord->lon == doctest::Approx(-122.4194));
    REQUIRE(token->cat.catgeocoord->accuracy.has_value());
    CHECK(*token->cat.catgeocoord->accuracy == doctest::Approx(100.0));
}

TEST_CASE("HmacTokenWorkflow") {
    auto token = createSampleToken();
    auto key = secure_utils::to_regular_vector(HmacSha256Algorithm::generateSecureKey());
    HmacSha256Algorithm algorithm(key);
    
    // This test validates the algorithm interface
    CHECK(algorithm.algorithmId() == ALG_HMAC256_256);
    
    // Test signing
    std::vector<uint8_t> testData = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
    auto signature = algorithm.sign(testData);
    CHECK_FALSE(signature.empty());
    
    // Test verification
    CHECK(algorithm.verify(testData, signature));
    
    // Test verification with wrong data
    std::vector<uint8_t> wrongData = {0x57, 0x6f, 0x72, 0x6c, 0x64}; // "World"
    CHECK_FALSE(algorithm.verify(wrongData, signature));
}

TEST_CASE("CwtEncodingWorkflow") {
    auto token = createSampleToken();
    Cwt cwt(ALG_HMAC256_256, *token);
    
    // Test CWT construction
    CHECK(cwt.header.alg == ALG_HMAC256_256);
    CHECK(cwt.header.typ == "CAT");
    CHECK(cwt.payload.core.iss == token->core.iss);
    
    // Test with key ID
    cwt.withKeyId("test-key-123");
    CHECK(cwt.header.kid == "test-key-123");
    
    // Test payload encoding (basic structure validation)
    REQUIRE_NOTHROW({
        auto encoded = cwt.encodePayload();
        CHECK_FALSE(encoded.empty());
    });
}

TEST_CASE("ValidationWorkflow") {
    auto token = createSampleToken();
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    
    // Test successful validation
    CatTokenValidator validator;
    validator.withExpectedIssuers({"https://example.com"})
            .withExpectedAudiences({"https://api.example.com"})
            .withClockSkewTolerance(60);
    
    REQUIRE_NOTHROW(validator.validate(*token));
    
    // Test validation failure scenarios
    auto invalidToken = CatToken()
        .withIssuer("https://malicious.com")
        .withAudience({"https://api.example.com"})
        .withExpiration(exp)
        .withCwtId("invalid-token");
        
    
    REQUIRE_THROWS_AS(validator.validate(invalidToken), InvalidIssuerError);
}

TEST_CASE("MultiAlgorithmSupport") {
    auto token = createSampleToken();
    
    // Test HMAC256
    auto hmacKey = secure_utils::to_regular_vector(HmacSha256Algorithm::generateSecureKey());
    HmacSha256Algorithm hmacAlg(hmacKey);
    CHECK(hmacAlg.algorithmId() == ALG_HMAC256_256);
    
    // Test ES256
    Es256Algorithm es256Alg;
    CHECK(es256Alg.algorithmId() == ALG_ES256);
    
    // Test PS256
    Ps256Algorithm ps256Alg;
    CHECK(ps256Alg.algorithmId() == ALG_PS256);
    
    // Test key generation
    REQUIRE_NOTHROW({
        auto es256Keys = Es256Algorithm::generateKeyPair();
        CHECK_FALSE(es256Keys.first.empty());
        CHECK_FALSE(es256Keys.second.empty());
    });
    
    REQUIRE_NOTHROW({
        auto ps256Keys = Ps256Algorithm::generateKeyPair();
        CHECK_FALSE(ps256Keys.first.empty());
        CHECK_FALSE(ps256Keys.second.empty());
    });
}

TEST_CASE("ComprehensiveClaimsTest") {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    
    // Test token with all possible claims
    auto comprehensiveToken = CatToken()
        .withIssuer("https://comprehensive-issuer.com")
        .withAudience({"aud1", "aud2", "aud3"})
        .withExpiration(exp)
        .withNotBefore(now)
        .withCwtId("comprehensive-token-id")
        .withVersion("2.1")
        .withNetworkInterfaces({"192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"})
        .withUsageLimit(999)
        .withMethods("GET,POST,PUT,DELETE")
        .withAlpnProtocols({"h2", "http/1.1", "http/1.0"})
        .withHosts({"api.example.com", "*.example.org", "service.example.net"})
        .withCountries({"US", "CA", "GB", "DE", "FR"})
        .withGeoCoordinate(34.0522, -118.2437, 25.5)
        .withGeohash("9q5ct12345")
        .withGeoAltitude(100)
        .withTokenPublicKeyThumbprint("comprehensive-thumbprint-data")
        .withReplayProtection("comprehensive-replay-nonce")
        .withProofOfPossession(true);
        
    
    // Validate all core claims
    CHECK(comprehensiveToken.core.iss == "https://comprehensive-issuer.com");
    REQUIRE(comprehensiveToken.core.aud.has_value());
    CHECK(comprehensiveToken.core.aud->size() == 3);
    CHECK(comprehensiveToken.core.cti == "comprehensive-token-id");
    
    // Validate all CAT claims
    CHECK(comprehensiveToken.cat.catv == "2.1");
    REQUIRE(comprehensiveToken.cat.catnip.has_value());
    CHECK(comprehensiveToken.cat.catnip->size() == 3);
    CHECK(comprehensiveToken.cat.catu == 999);
    CHECK(comprehensiveToken.cat.catm == "GET,POST,PUT,DELETE");
    REQUIRE(comprehensiveToken.cat.catalpn.has_value());
    CHECK(comprehensiveToken.cat.catalpn->size() == 3);
    REQUIRE(comprehensiveToken.cat.cath.has_value());
    CHECK(comprehensiveToken.cat.cath->size() == 3);
    REQUIRE(comprehensiveToken.cat.catgeoiso3166.has_value());
    CHECK(comprehensiveToken.cat.catgeoiso3166->size() == 5);
    CHECK(comprehensiveToken.cat.geohash == "9q5ct12345");
    CHECK(comprehensiveToken.cat.catgeoalt == 100);
    CHECK(comprehensiveToken.cat.cattpk == "comprehensive-thumbprint-data");
    CHECK(comprehensiveToken.cat.catreplay == "comprehensive-replay-nonce");
    CHECK(comprehensiveToken.cat.catpor == true);
    
    // Test geo coordinates
    REQUIRE(comprehensiveToken.cat.catgeocoord.has_value());
    CHECK(comprehensiveToken.cat.catgeocoord->lat == doctest::Approx(34.0522));
    CHECK(comprehensiveToken.cat.catgeocoord->lon == doctest::Approx(-118.2437));
    REQUIRE(comprehensiveToken.cat.catgeocoord->accuracy.has_value());
    CHECK(*comprehensiveToken.cat.catgeocoord->accuracy == doctest::Approx(25.5));
    
    // Test validation with comprehensive token
    CatTokenValidator validator;
    validator.withExpectedIssuers({"https://comprehensive-issuer.com"})
            .withExpectedAudiences({"aud2"}) // Should match one of the audiences
            .withClockSkewTolerance(60);
    
    REQUIRE_NOTHROW(validator.validate(comprehensiveToken));
}

TEST_CASE("ErrorHandlingWorkflow") {
    auto now = std::chrono::system_clock::now();
    
    // Test various error conditions
    
    // Geographic validation errors
    CatTokenValidator validator;
    
    auto tokenWithInvalidCoords = CatToken().withGeoCoordinate(91.0, 0.0);
    REQUIRE_THROWS_AS(validator.validate(tokenWithInvalidCoords), GeographicValidationError);
    
    auto tokenWithInvalidGeohash = CatToken().withGeohash("");
    REQUIRE_THROWS_AS(validator.validate(tokenWithInvalidGeohash), GeographicValidationError);
    
    // Token expiration errors
    auto expiredToken = CatToken()
        .withIssuer("https://example.com")
        .withExpiration(now - std::chrono::hours(1));
        
    
    REQUIRE_THROWS_AS(validator.validate(expiredToken), TokenExpiredError);
    
    // Future token errors
    auto futureToken = CatToken()
        .withIssuer("https://example.com")
        .withNotBefore(now + std::chrono::hours(1))
        .withExpiration(now + std::chrono::hours(2));
        
    
    REQUIRE_THROWS_AS(validator.validate(futureToken), TokenNotYetValidError);
}

TEST_CASE("CryptoUtilityFunctions") {
    // Test base64URL encoding/decoding
    std::vector<uint8_t> testData = {0x4d, 0x61, 0x6e, 0x20, 0x69, 0x73}; // "Man is"
    std::string encoded = base64UrlEncode(testData);
    CHECK_FALSE(encoded.empty());
    
    auto decoded = base64UrlDecode(encoded);
    CHECK(decoded == testData);
    
    // Test SHA256 hashing
    auto hash = hashSha256(testData);
    CHECK(hash.size() == 32); // 256 bits = 32 bytes
    
    // Test signing input creation
    std::vector<uint8_t> header = {0x7b, 0x22, 0x61, 0x6c, 0x67, 0x22, 0x3a, 0x22, 0x48, 0x53, 0x32, 0x35, 0x36, 0x22, 0x7d};
    std::vector<uint8_t> payload = {0x7b, 0x22, 0x73, 0x75, 0x62, 0x22, 0x3a, 0x22, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x22, 0x7d};
    
    auto signingInput = createSigningInput(header, payload);
    CHECK_FALSE(signingInput.empty());
    
    std::string expected = base64UrlEncode(header) + "." + base64UrlEncode(payload);
    std::string actual(signingInput.begin(), signingInput.end());
    CHECK(actual == expected);
}