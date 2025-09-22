#include <doctest/doctest.h>
#include "catapult/claims.hpp"
#include "catapult/validator.hpp"
#include "catapult/crypto.hpp"
#include <chrono>

using namespace catapult;

static CatToken createValidToken() {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    auto nbf = now - std::chrono::minutes(5);
    
    return CatToken()
        .withIssuer("https://trusted-issuer.com")
        .withAudience({"https://my-service.com"})
        .withExpiration(exp)
        .withNotBefore(nbf)
        .withCwtId("valid-token")
        .withVersion("1.0")
        .withGeoCoordinate(40.7128, -74.0060, 50.0)
        .withGeohash("dr5reg");
}

TEST_CASE("ValidatorSuccess") {
    auto token = createValidToken();
    
    CatTokenValidator validator;
    validator.withExpectedIssuers({"https://trusted-issuer.com"})
            .withExpectedAudiences({"https://my-service.com"})
            .withClockSkewTolerance(60);
    
    REQUIRE_NOTHROW(validator.validate(token));
}

TEST_CASE("ValidatorExpiredToken") {
    auto now = std::chrono::system_clock::now();
    auto expiredTime = now - std::chrono::hours(1);
    auto token = CatToken()
        .withIssuer("https://trusted-issuer.com")
        .withAudience({"https://my-service.com"})
        .withExpiration(expiredTime)
        .withCwtId("expired-token");
    
    CatTokenValidator validator;
    validator.withExpectedIssuers({"https://trusted-issuer.com"})
            .withExpectedAudiences({"https://my-service.com"});
    
    REQUIRE_THROWS_AS(validator.validate(token), TokenExpiredError);
}

TEST_CASE("ValidatorNotYetValid") {
    auto now = std::chrono::system_clock::now();
    auto futureTime = now + std::chrono::hours(1);
    auto expTime = now + std::chrono::hours(2);
    auto token = CatToken()
        .withIssuer("https://trusted-issuer.com")
        .withAudience({"https://my-service.com"})
        .withExpiration(expTime)
        .withNotBefore(futureTime)
        .withCwtId("future-token");
    
    CatTokenValidator validator;
    validator.withExpectedIssuers({"https://trusted-issuer.com"})
            .withExpectedAudiences({"https://my-service.com"});
    
    REQUIRE_THROWS_AS(validator.validate(token), TokenNotYetValidError);
}

TEST_CASE("ValidatorInvalidIssuer") {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    auto token = CatToken()
        .withIssuer("https://untrusted-issuer.com")
        .withAudience({"https://my-service.com"})
        .withExpiration(exp)
        .withCwtId("invalid-issuer-token");
    
    CatTokenValidator validator;
    validator.withExpectedIssuers({"https://trusted-issuer.com"})
            .withExpectedAudiences({"https://my-service.com"});
    
    REQUIRE_THROWS_AS(validator.validate(token), InvalidIssuerError);
}

TEST_CASE("ValidatorInvalidAudience") {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    auto token = CatToken()
        .withIssuer("https://trusted-issuer.com")
        .withAudience({"https://other-service.com"})
        .withExpiration(exp)
        .withCwtId("invalid-audience-token");
    
    CatTokenValidator validator;
    validator.withExpectedIssuers({"https://trusted-issuer.com"})
            .withExpectedAudiences({"https://my-service.com"});
    
    REQUIRE_THROWS_AS(validator.validate(token), InvalidAudienceError);
}

TEST_CASE("ValidatorMissingIssuer") {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    auto token = CatToken()
        .withAudience({"https://my-service.com"})
        .withExpiration(exp)
        .withCwtId("no-issuer-token");
        
    
    CatTokenValidator validator;
    validator.withExpectedIssuers({"https://trusted-issuer.com"})
            .withExpectedAudiences({"https://my-service.com"});
    
    REQUIRE_THROWS_AS(validator.validate(token), MissingRequiredClaimError);
}

TEST_CASE("ValidatorMissingAudience") {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    auto token = CatToken()
        .withIssuer("https://trusted-issuer.com")
        .withExpiration(exp)
        .withCwtId("no-audience-token");
        
    
    CatTokenValidator validator;
    validator.withExpectedIssuers({"https://trusted-issuer.com"})
            .withExpectedAudiences({"https://my-service.com"});
    
    REQUIRE_THROWS_AS(validator.validate(token), MissingRequiredClaimError);
}

TEST_CASE("ValidatorGeographicValidation") {
    CatTokenValidator validator;
    
    // Test invalid latitude
    auto token1 = CatToken().withGeoCoordinate(91.0, 0.0); // Invalid latitude
    REQUIRE_THROWS_AS(validator.validate(token1), GeographicValidationError);
    
    // Test invalid longitude
    auto token2 = CatToken().withGeoCoordinate(0.0, 181.0); // Invalid longitude
    REQUIRE_THROWS_AS(validator.validate(token2), GeographicValidationError);
    
    // Test invalid geohash
    auto token3 = CatToken().withGeohash(""); // Empty geohash
    REQUIRE_THROWS_AS(validator.validate(token3), GeographicValidationError);
    
    // Test valid coordinates
    auto token4 = CatToken().withGeoCoordinate(40.7128, -74.0060);
    REQUIRE_NOTHROW(validator.validate(token4));
    
    // Test valid geohash
    auto token5 = CatToken().withGeohash("dr5reg");
    REQUIRE_NOTHROW(validator.validate(token5));
}

TEST_CASE("ValidatorClockSkewTolerance") {
    auto now = std::chrono::system_clock::now();
    // Token expired 30 seconds ago
    auto recentlyExpired = now - std::chrono::seconds(30);
    auto token = CatToken()
        .withIssuer("https://trusted-issuer.com")
        .withAudience({"https://my-service.com"})
        .withExpiration(recentlyExpired)
        .withCwtId("recently-expired-token");
        
    
    // With default tolerance (60 seconds), should pass
    CatTokenValidator validator1;
    validator1.withExpectedIssuers({"https://trusted-issuer.com"})
             .withExpectedAudiences({"https://my-service.com"});
    REQUIRE_NOTHROW(validator1.validate(token));
    
    // With zero tolerance, should fail
    CatTokenValidator validator2;
    validator2.withExpectedIssuers({"https://trusted-issuer.com"})
             .withExpectedAudiences({"https://my-service.com"})
             .withClockSkewTolerance(0);
    REQUIRE_THROWS_AS(validator2.validate(token), TokenExpiredError);
}

TEST_CASE("ValidatorMultipleAudiences") {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    auto token = CatToken()
        .withIssuer("https://trusted-issuer.com")
        .withAudience({"https://service1.com", "https://service2.com", "https://my-service.com"})
        .withExpiration(exp)
        .withCwtId("multi-audience-token");
        
    
    CatTokenValidator validator;
    validator.withExpectedIssuers({"https://trusted-issuer.com"})
            .withExpectedAudiences({"https://my-service.com", "https://another-service.com"});
    
    // Should pass because one audience matches
    REQUIRE_NOTHROW(validator.validate(token));
}

TEST_CASE("ValidatorNoExpectedIssuerOrAudience") {
    auto token = createValidToken();
    
    // Validator without expected issuers or audiences should not validate them
    CatTokenValidator validator;
    REQUIRE_NOTHROW(validator.validate(token));
}

TEST_CASE("MOQT Actions Compile Time") {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    
    auto token = CatToken()
        .withIssuer("https://moqt-server.com")
        .withAudience({"https://moqt-client.com"})
        .withExpiration(exp)
        .withMoqtActions<moqt_actions::SUBSCRIBE, moqt_actions::PUBLISH>(
            MoqtBinaryMatch::prefix("live/"),
            MoqtBinaryMatch::suffix("/video")
        );
        
    
    const auto* moqt_claims = token.extended.getMoqtClaimsReadOnly();
    REQUIRE(moqt_claims != nullptr);
    REQUIRE(moqt_claims->getScopeCount() == 1);
    
    const auto& scopes = moqt_claims->getScopes();
    REQUIRE(scopes[0].contains_action(moqt_actions::SUBSCRIBE));
    REQUIRE(scopes[0].contains_action(moqt_actions::PUBLISH));
    REQUIRE_FALSE(scopes[0].contains_action(moqt_actions::ANNOUNCE));
    
    REQUIRE(moqt_claims->isAuthorized(moqt_actions::SUBSCRIBE, "live/stream1", "track1/video"));
    REQUIRE(moqt_claims->isAuthorized(moqt_actions::PUBLISH, "live/stream2", "audio/video"));
    REQUIRE_FALSE(moqt_claims->isAuthorized(moqt_actions::SUBSCRIBE, "recorded/stream1", "track1/video"));
}

TEST_CASE("MOQT Actions Dynamic") {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    
    std::vector<int> actions = {moqt_actions::SUBSCRIBE, moqt_actions::ANNOUNCE, moqt_actions::FETCH};
    
    auto token = CatToken()
        .withIssuer("https://moqt-server.com")
        .withAudience({"https://moqt-client.com"})
        .withExpiration(exp)
        .withMoqtActionsDynamic(actions,
            MoqtBinaryMatch::contains("chat"),
            MoqtBinaryMatch::exact("messages")
        );
        
    
    const auto* moqt_claims = token.extended.getMoqtClaimsReadOnly();
    REQUIRE(moqt_claims != nullptr);
    REQUIRE(moqt_claims->getScopeCount() == 1);
    
    const auto& scopes = moqt_claims->getScopes();
    REQUIRE(scopes[0].contains_action(moqt_actions::SUBSCRIBE));
    REQUIRE(scopes[0].contains_action(moqt_actions::ANNOUNCE));
    REQUIRE(scopes[0].contains_action(moqt_actions::FETCH));
    REQUIRE_FALSE(scopes[0].contains_action(moqt_actions::PUBLISH));
    
    REQUIRE(moqt_claims->isAuthorized(moqt_actions::SUBSCRIBE, "live/chat/room1", "messages"));
    REQUIRE(moqt_claims->isAuthorized(moqt_actions::ANNOUNCE, "group/chat", "messages"));
    REQUIRE_FALSE(moqt_claims->isAuthorized(moqt_actions::SUBSCRIBE, "live/video", "messages"));
    REQUIRE_FALSE(moqt_claims->isAuthorized(moqt_actions::SUBSCRIBE, "live/chat/room1", "status"));
}

TEST_CASE("MOQT Revalidation Interval") {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    
    auto token = CatToken()
        .withIssuer("https://moqt-server.com")
        .withAudience({"https://moqt-client.com"})
        .withExpiration(exp)
        .withMoqtRevalidationInterval(std::chrono::seconds(300));
        
    
    const auto* moqt_claims = token.extended.getMoqtClaimsReadOnly();
    REQUIRE(moqt_claims != nullptr);
    
    auto interval = moqt_claims->getRevalidationInterval();
    REQUIRE(interval.has_value());
    REQUIRE(interval->count() == 300);
    
    auto interval_seconds = moqt_claims->getRevalidationIntervalSeconds();
    REQUIRE(interval_seconds.has_value());
    REQUIRE(interval_seconds.value() == 300);
}

TEST_CASE("MOQT Multiple Scopes") {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    
    std::vector<int> subscribe_actions = {moqt_actions::SUBSCRIBE};
    std::vector<int> publish_actions = {moqt_actions::PUBLISH, moqt_actions::ANNOUNCE};
    
    auto token = CatToken()
        .withIssuer("https://moqt-server.com")
        .withAudience({"https://moqt-client.com"})
        .withExpiration(exp)
        .withMoqtActionsDynamic(subscribe_actions,
            MoqtBinaryMatch::prefix("public/"),
            MoqtBinaryMatch::exact("feed")
        )
        .withMoqtActionsDynamic(publish_actions,
            MoqtBinaryMatch::prefix("user/"),
            MoqtBinaryMatch::contains("content")
        );
        
    
    const auto* moqt_claims = token.extended.getMoqtClaimsReadOnly();
    REQUIRE(moqt_claims != nullptr);
    REQUIRE(moqt_claims->getScopeCount() == 2);
    
    REQUIRE(moqt_claims->isAuthorized(moqt_actions::SUBSCRIBE, "public/news", "feed"));
    REQUIRE(moqt_claims->isAuthorized(moqt_actions::PUBLISH, "user/alice", "content/video"));
    REQUIRE(moqt_claims->isAuthorized(moqt_actions::ANNOUNCE, "user/bob", "user_content"));
    
    REQUIRE_FALSE(moqt_claims->isAuthorized(moqt_actions::PUBLISH, "public/news", "feed"));
    REQUIRE_FALSE(moqt_claims->isAuthorized(moqt_actions::SUBSCRIBE, "user/alice", "content/video"));
}

TEST_CASE("MOQT Binary Match Types") {
    std::vector<int> actions = {moqt_actions::SUBSCRIBE};
    
    auto exact_token = CatToken()
        .withMoqtActionsDynamic(actions,
            MoqtBinaryMatch::exact("live/stream1"),
            MoqtBinaryMatch::exact("video")
        );
        
    
    auto prefix_token = CatToken()
        .withMoqtActionsDynamic(actions,
            MoqtBinaryMatch::prefix("live/"),
            MoqtBinaryMatch::prefix("vid")
        );
        
    
    auto suffix_token = CatToken()
        .withMoqtActionsDynamic(actions,
            MoqtBinaryMatch::suffix("/stream"),
            MoqtBinaryMatch::suffix("eo")
        );
        
    
    auto contains_token = CatToken()
        .withMoqtActionsDynamic(actions,
            MoqtBinaryMatch::contains("live"),
            MoqtBinaryMatch::contains("vid")
        );
        
    
    const auto* exact_claims = exact_token.extended.getMoqtClaimsReadOnly();
    const auto* prefix_claims = prefix_token.extended.getMoqtClaimsReadOnly();
    const auto* suffix_claims = suffix_token.extended.getMoqtClaimsReadOnly();
    const auto* contains_claims = contains_token.extended.getMoqtClaimsReadOnly();
    
    REQUIRE(exact_claims->isAuthorized(moqt_actions::SUBSCRIBE, "live/stream1", "video"));
    REQUIRE_FALSE(exact_claims->isAuthorized(moqt_actions::SUBSCRIBE, "live/stream2", "video"));
    
    REQUIRE(prefix_claims->isAuthorized(moqt_actions::SUBSCRIBE, "live/stream1", "video"));
    REQUIRE(prefix_claims->isAuthorized(moqt_actions::SUBSCRIBE, "live/stream2", "video"));
    REQUIRE_FALSE(prefix_claims->isAuthorized(moqt_actions::SUBSCRIBE, "recorded/stream1", "video"));
    
    REQUIRE(suffix_claims->isAuthorized(moqt_actions::SUBSCRIBE, "live/stream", "video"));
    REQUIRE_FALSE(suffix_claims->isAuthorized(moqt_actions::SUBSCRIBE, "live/stream1", "video"));
    
    REQUIRE(contains_claims->isAuthorized(moqt_actions::SUBSCRIBE, "live/stream1", "video"));
    REQUIRE(contains_claims->isAuthorized(moqt_actions::SUBSCRIBE, "recorded/live/stream", "video"));
    REQUIRE_FALSE(contains_claims->isAuthorized(moqt_actions::SUBSCRIBE, "recorded/stream", "audio"));
}

// Note: Token encoding/decoding tests would require full CBOR implementation
// These are simplified tests for the current implementation level