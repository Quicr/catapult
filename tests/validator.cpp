#include <doctest/doctest.h>
#include "catapult/authorization_policy.hpp"
#include "catapult/claims.hpp"
#include "catapult/moqt_claims.hpp"
#include "catapult/usage_state.hpp"
#include "catapult/validator.hpp"
#include <chrono>

using namespace catapult;

namespace {
// These tests predate the authorization-policy hook. They construct
// tokens carrying semantic claims (geohash, coordinates) purely to
// exercise structural / temporal / composite checks. Install a
// permissive policy so those tokens continue to reach the code paths
// under test; the enforcement contract itself is covered by dedicated
// tests in authorization_policy.cpp.
PermissivePolicy& sharedPermissivePolicy() {
  static PermissivePolicy policy;
  return policy;
}
}  // namespace

// Baseline "valid" token used by structural / temporal / audience tests.
// Deliberately carries no semantic claims (catgeoiso/geohash/catpor/etc.)
// so it can be validated without an authorization-policy hook — those
// claims are covered by their own dedicated tests.
static auto createValidToken() {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    auto nbf = now - std::chrono::minutes(5);

    return CatToken()
        .withIssuer("https://trusted-issuer.com")
        .withAudience({"https://my-service.com"})
        .withExpiration(exp)
        .withNotBefore(nbf)
        .withCwtIdString("valid-token")
        .withVersion(1)
        .withGeoCoordinate(40.7128, -74.0060, 50.0);
}

TEST_CASE("DefaultValidator") {
    auto validToken = createValidToken();
    CatTokenValidator validator;
    
    // Default validator should accept any valid token without specific issuer/audience checks
    REQUIRE_NOTHROW(validator.validate(validToken));
}

TEST_CASE("ValidatorChaining") {
    auto validToken = createValidToken();
    CatTokenValidator validator;
    
    // Test method chaining
    REQUIRE_NOTHROW({
        validator.withExpectedIssuers({"https://trusted-issuer.com"})
                .withExpectedAudiences({"https://my-service.com"})
                .withClockSkewTolerance(30);
    });
    
    REQUIRE_NOTHROW(validator.validate(validToken));
}

TEST_CASE("ValidatorCopyAndAssign") {
    auto validToken = createValidToken();
    CatTokenValidator validator1;
    validator1.withExpectedIssuers({"https://trusted-issuer.com"})
             .withExpectedAudiences({"https://my-service.com"})
             .withClockSkewTolerance(120);
    
    // Test that validator works
    REQUIRE_NOTHROW(validator1.validate(validToken));
    
    // Test copy constructor (if implemented)
    CatTokenValidator validator2 = validator1;
    REQUIRE_NOTHROW(validator2.validate(validToken));
}

TEST_CASE("MultipleExpectedIssuers") {
    auto validToken = createValidToken();
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);

    // Setup validator with multiple expected issuers
    CatTokenValidator validator;
    validator.withExpectedIssuers({
        "https://issuer1.com",
        "https://trusted-issuer.com", 
        "https://issuer3.com"
    }).withExpectedAudiences({"https://my-service.com"});

    // Should pass with one of the valid issuers
    REQUIRE_NOTHROW(validator.validate(validToken));
    
    // Test with token from different issuer not in list
    auto tokenWithDifferentIssuer = CatToken()
        .withIssuer("https://unknown-issuer.com")
        .withAudience({"https://my-service.com"})
        .withExpiration(exp)
        .withCwtIdString("different-issuer-token");
        

    // Should fail due to invalid issuer
    REQUIRE_THROWS_AS(validator.validate(tokenWithDifferentIssuer), InvalidIssuerError);
}

TEST_CASE("MultipleExpectedAudiences") {
    auto validToken = createValidToken();
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    
    CatTokenValidator validator;
    validator.withExpectedIssuers({"https://trusted-issuer.com"})
            .withExpectedAudiences({
                "https://service1.com",
                "https://my-service.com",
                "https://service3.com"
            });

    // Should pass since one of the audiences matches
    REQUIRE_NOTHROW(validator.validate(validToken));
    
    // Test with token containing multiple audiences, one matching
    auto tokenWithMultipleAudiences = CatToken()
        .withIssuer("https://trusted-issuer.com")
        .withAudience({"https://other-service.com", "https://my-service.com"})
        .withExpiration(exp)
        .withCwtIdString("multi-audience-token");
        

    // Should pass since one audience matches
    REQUIRE_NOTHROW(validator.validate(tokenWithMultipleAudiences));
}

TEST_CASE("ValidatorWithVeryStrictTolerance") {
    auto now = std::chrono::system_clock::now();
    // Create token that expires in 5 seconds
    auto shortExp = now + std::chrono::seconds(5);
    auto shortLivedToken = CatToken()
        .withIssuer("https://trusted-issuer.com")
        .withAudience({"https://my-service.com"})
        .withExpiration(shortExp)
        .withCwtIdString("short-lived-token");
        
    
    CatTokenValidator strictValidator;
    strictValidator.withExpectedIssuers({"https://trusted-issuer.com"})
                  .withExpectedAudiences({"https://my-service.com"})
                  .withClockSkewTolerance(1); // Very strict 1-second tolerance
    
    // Should still pass with strict tolerance since token is not expired
    REQUIRE_NOTHROW(strictValidator.validate(shortLivedToken));
}

TEST_CASE("ValidatorWithPermissiveTolerance") {
    auto now = std::chrono::system_clock::now();

    CatTokenValidator permissiveValidator;
    permissiveValidator.withExpectedIssuers({"https://trusted-issuer.com"})
            .withExpectedAudiences({"https://my-service.com"})
            .withClockSkewTolerance(180); // 3-minute tolerance

    // Create token that expired 2 minutes ago
    auto expiredTime = now - std::chrono::minutes(2);
    auto expiredToken = CatToken()
        .withIssuer("https://trusted-issuer.com")
        .withAudience({"https://my-service.com"})
        .withExpiration(expiredTime)
        .withCwtIdString("expired-token");
        

    // Should pass with permissive tolerance
    REQUIRE_NOTHROW(permissiveValidator.validate(expiredToken));
    
    CatTokenValidator strictValidator;
    strictValidator.withExpectedIssuers({"https://trusted-issuer.com"})
                  .withExpectedAudiences({"https://my-service.com"})
                  .withClockSkewTolerance(60); // 1-minute tolerance
    
    // Should fail with strict tolerance
    REQUIRE_THROWS_AS(strictValidator.validate(expiredToken), TokenExpiredError);
}

TEST_CASE("GeographicValidationEdgeCases") {

    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&sharedPermissivePolicy());

    // Test coordinates at the edge of valid ranges
    auto tokenAtNorthPole = CatToken().withGeoCoordinate(90.0, 0.0);
    REQUIRE_NOTHROW(validator.validate(tokenAtNorthPole));
    
    auto tokenAtSouthPole = CatToken().withGeoCoordinate(-90.0, 0.0);
    REQUIRE_NOTHROW(validator.validate(tokenAtSouthPole));
    
    auto tokenAtDateLine = CatToken().withGeoCoordinate(0.0, 180.0);
    REQUIRE_NOTHROW(validator.validate(tokenAtDateLine));
    
    auto tokenAtAntiMeridian = CatToken().withGeoCoordinate(0.0, -180.0);
    REQUIRE_NOTHROW(validator.validate(tokenAtAntiMeridian));
    
    // Test valid geohash lengths
    auto tokenWithShortGeohash = CatToken().withGeohash(GeohashClaimValue{std::string{"u"}});
    REQUIRE_NOTHROW(validator.validate(tokenWithShortGeohash));
    
    auto tokenWithLongGeohash = CatToken().withGeohash(GeohashClaimValue{std::string{"u4pruydqqvj"}}); // 12 characters
    REQUIRE_NOTHROW(validator.validate(tokenWithLongGeohash));
    
    // Test invalid geohash length
    auto tokenWithTooLongGeohash = CatToken().withGeohash(GeohashClaimValue{std::string{"u4pruydqqvjkl"}}); // 13 characters
    REQUIRE_THROWS_AS(validator.validate(tokenWithTooLongGeohash), GeographicValidationError);
}

// Additional positive tests for CatTokenValidator
TEST_CASE("ValidatorPositiveTests - Basic Functionality") {
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&sharedPermissivePolicy());
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(2);
    auto nbf = now - std::chrono::minutes(10);
    
    SUBCASE("Valid token with all claims") {
        auto token = CatToken()
            .withIssuer("https://test-issuer.com")
            .withAudience({"https://test-service.com"})
            .withExpiration(exp)
            .withNotBefore(nbf)
            .withCwtIdString("test-token-123")
            .withVersion(1)
            .withGeoCoordinate(37.7749, -122.4194, 100.0)
            .withGeohash(GeohashClaimValue{std::string{"9q8yy"}});
            
            
        REQUIRE_NOTHROW(validator.validate(token));
    }
    
    SUBCASE("Token with minimal required claims") {
        auto minimalToken = CatToken()
            .withIssuer("https://minimal-issuer.com")
            .withAudience({"https://minimal-service.com"})
            .withExpiration(exp)
            .withCwtIdString("minimal-token");
            
            
        REQUIRE_NOTHROW(validator.validate(minimalToken));
    }
    
    SUBCASE("Token with multiple audiences") {
        auto multiAudToken = CatToken()
            .withIssuer("https://multi-issuer.com")
            .withAudience({"https://service1.com", "https://service2.com", "https://service3.com"})
            .withExpiration(exp)
            .withCwtIdString("multi-aud-token");
            
            
        REQUIRE_NOTHROW(validator.validate(multiAudToken));
    }
    
    SUBCASE("Token with future not-before time within tolerance") {
        auto futureNbf = now + std::chrono::minutes(1);
        auto futureToken = CatToken()
            .withIssuer("https://future-issuer.com")
            .withAudience({"https://future-service.com"})
            .withExpiration(exp)
            .withNotBefore(futureNbf)
            .withCwtIdString("future-token");
            
            
        validator.withClockSkewTolerance(300); // 5 minutes tolerance
        REQUIRE_NOTHROW(validator.validate(futureToken));
    }
}

TEST_CASE("ValidatorPositiveTests - Geographic Claims") {
    CatTokenValidator validator;
    validator.withAuthorizationPolicy(&sharedPermissivePolicy());
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    
    SUBCASE("Valid coordinates around the world") {
        // Tokyo
        auto tokyoToken = CatToken()
            .withIssuer("https://geo-issuer.com")
            .withAudience({"https://geo-service.com"})
            .withExpiration(exp)
            .withGeoCoordinate(35.6762, 139.6503, 10.0)
            .withCwtIdString("tokyo-token");
            
        REQUIRE_NOTHROW(validator.validate(tokyoToken));
        
        // London
        auto londonToken = CatToken()
            .withIssuer("https://geo-issuer.com")
            .withAudience({"https://geo-service.com"})
            .withExpiration(exp)
            .withGeoCoordinate(51.5074, -0.1278, 25.0)
            .withCwtIdString("london-token");
            
        REQUIRE_NOTHROW(validator.validate(londonToken));
        
        // Sydney
        auto sydneyToken = CatToken()
            .withIssuer("https://geo-issuer.com")
            .withAudience({"https://geo-service.com"})
            .withExpiration(exp)
            .withGeoCoordinate(-33.8688, 151.2093, 50.0)
            .withCwtIdString("sydney-token");
            
        REQUIRE_NOTHROW(validator.validate(sydneyToken));
    }
    
    SUBCASE("Valid geohash variations") {
        std::vector<std::string> validHashes = {"9", "dr", "9q8", "dr5r", "9q8yy", "dr5reg", "9q8yywe"};
        
        for (const auto& hash : validHashes) {
            auto token = CatToken()
                .withIssuer("https://hash-issuer.com")
                .withAudience({"https://hash-service.com"})
                .withExpiration(exp)
                .withGeohash(GeohashClaimValue{hash})
                .withCwtIdString(std::string("hash-token-") + hash);
                
            REQUIRE_NOTHROW(validator.validate(token));
        }
    }
    
    SUBCASE("Token with both coordinates and geohash") {
        auto geoToken = CatToken()
            .withIssuer("https://geo-combo-issuer.com")
            .withAudience({"https://geo-combo-service.com"})
            .withExpiration(exp)
            .withGeoCoordinate(40.7128, -74.0060, 30.0)
            .withGeohash(GeohashClaimValue{std::string{"dr5reg"}})
            .withCwtIdString("geo-combo-token");
            
        REQUIRE_NOTHROW(validator.validate(geoToken));
    }
}

TEST_CASE("ValidatorPositiveTests - Flexible Configuration") {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    
    SUBCASE("Validator with wildcard issuer acceptance") {
        auto token = CatToken()
            .withIssuer("https://any-issuer.com")
            .withAudience({"https://test-service.com"})
            .withExpiration(exp)
            .withCwtIdString("wildcard-issuer-token");
            
            
        CatTokenValidator permissiveValidator;
        // No expected issuers set - should accept any issuer
        permissiveValidator.withExpectedAudiences({"https://test-service.com"});
        REQUIRE_NOTHROW(permissiveValidator.validate(token));
    }
    
    SUBCASE("Validator with wildcard audience acceptance") {
        auto token = CatToken()
            .withIssuer("https://test-issuer.com")
            .withAudience({"https://any-service.com"})
            .withExpiration(exp)
            .withCwtIdString("wildcard-audience-token");
            
            
        CatTokenValidator permissiveValidator;
        // No expected audiences set - should accept any audience
        permissiveValidator.withExpectedIssuers({"https://test-issuer.com"});
        REQUIRE_NOTHROW(permissiveValidator.validate(token));
    }
    
    SUBCASE("Large clock skew tolerance") {
        auto expiredToken = CatToken()
            .withIssuer("https://expired-issuer.com")
            .withAudience({"https://expired-service.com"})
            .withExpiration(now - std::chrono::minutes(30)) // Expired 30 minutes ago
            .withCwtIdString("expired-but-tolerated-token");
            
            
        CatTokenValidator tolerantValidator;
        tolerantValidator.withExpectedIssuers({"https://expired-issuer.com"})
                        .withExpectedAudiences({"https://expired-service.com"})
                        .withClockSkewTolerance(3600); // 1 hour tolerance
        REQUIRE_NOTHROW(tolerantValidator.validate(expiredToken));
    }
    
    SUBCASE("Complex issuer and audience lists") {
        auto token = CatToken()
            .withIssuer("https://complex-issuer-3.com")
            .withAudience({"https://complex-service-2.com", "https://complex-service-5.com"})
            .withExpiration(exp)
            .withCwtIdString("complex-lists-token");
            
            
        CatTokenValidator complexValidator;
        complexValidator.withExpectedIssuers({
                          "https://complex-issuer-1.com",
                          "https://complex-issuer-2.com", 
                          "https://complex-issuer-3.com",
                          "https://complex-issuer-4.com"
                      })
                      .withExpectedAudiences({
                          "https://complex-service-1.com",
                          "https://complex-service-2.com",
                          "https://complex-service-3.com",
                          "https://complex-service-4.com",
                          "https://complex-service-5.com"
                      });
        REQUIRE_NOTHROW(complexValidator.validate(token));
    }
}

// Comprehensive negative tests for CatTokenValidator
TEST_CASE("ValidatorNegativeTests - Invalid Issuers and Audiences") {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    
    SUBCASE("Token with invalid issuer") {
        auto token = CatToken()
            .withIssuer("https://untrusted-issuer.com")
            .withAudience({"https://test-service.com"})
            .withExpiration(exp)
            .withCwtIdString("invalid-issuer-token");
            
            
        CatTokenValidator validator;
        validator.withExpectedIssuers({"https://trusted-issuer.com", "https://another-trusted.com"})
                .withExpectedAudiences({"https://test-service.com"});
        
        REQUIRE_THROWS_AS(validator.validate(token), InvalidIssuerError);
    }
    
    SUBCASE("Token with invalid audience") {
        auto token = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://untrusted-service.com"})
            .withExpiration(exp)
            .withCwtIdString("invalid-audience-token");
            
            
        CatTokenValidator validator;
        validator.withExpectedIssuers({"https://trusted-issuer.com"})
                .withExpectedAudiences({"https://trusted-service.com", "https://another-trusted-service.com"});
        
        REQUIRE_THROWS_AS(validator.validate(token), InvalidAudienceError);
    }
    
    SUBCASE("Token with no matching audiences") {
        auto token = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://service1.com", "https://service2.com"})
            .withExpiration(exp)
            .withCwtIdString("no-matching-audience-token");
            
            
        CatTokenValidator validator;
        validator.withExpectedIssuers({"https://trusted-issuer.com"})
                .withExpectedAudiences({"https://service3.com", "https://service4.com"});
        
        REQUIRE_THROWS_AS(validator.validate(token), InvalidAudienceError);
    }
    
    SUBCASE("Empty issuer") {
        auto token = CatToken()
            .withIssuer("")
            .withAudience({"https://test-service.com"})
            .withExpiration(exp)
            .withCwtIdString("empty-issuer-token");
            
            
        CatTokenValidator validator;
        validator.withExpectedIssuers({"https://trusted-issuer.com"});
        
        REQUIRE_THROWS_AS(validator.validate(token), InvalidIssuerError);
    }
    
    SUBCASE("Empty audience") {
        auto token = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"", "https://valid-service.com"})
            .withExpiration(exp)
            .withCwtIdString("empty-audience-token");
            
            
        CatTokenValidator validator;
        validator.withExpectedIssuers({"https://trusted-issuer.com"})
                .withExpectedAudiences({"https://valid-service.com"});
        
        // Should still pass since one audience is valid
        REQUIRE_NOTHROW(validator.validate(token));
        
        // Test with token containing only empty audience
        auto emptyAudToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({""})
            .withExpiration(exp)
            .withCwtIdString("only-empty-audience-token");
            
            
        validator.withExpectedAudiences({"https://valid-service.com"});
        REQUIRE_THROWS_AS(validator.validate(emptyAudToken), InvalidAudienceError);
    }
}

TEST_CASE("ValidatorNegativeTests - Time-based Validation") {
    auto now = std::chrono::system_clock::now();
    
    SUBCASE("Expired token beyond tolerance") {
        auto expiredToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(now - std::chrono::hours(2)) // Expired 2 hours ago
            .withCwtIdString("expired-token");
            
            
        CatTokenValidator strictValidator;
        strictValidator.withExpectedIssuers({"https://trusted-issuer.com"})
                      .withExpectedAudiences({"https://trusted-service.com"})
                      .withClockSkewTolerance(60); // 1 minute tolerance
        
        REQUIRE_THROWS_AS(strictValidator.validate(expiredToken), TokenExpiredError);
    }
    
    SUBCASE("Token not yet valid beyond tolerance") {
        auto futureToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(now + std::chrono::hours(2))
            .withNotBefore(now + std::chrono::hours(1)) // Valid 1 hour from now
            .withCwtIdString("future-token");
            
            
        CatTokenValidator strictValidator;
        strictValidator.withExpectedIssuers({"https://trusted-issuer.com"})
                      .withExpectedAudiences({"https://trusted-service.com"})
                      .withClockSkewTolerance(30); // 30 second tolerance
        
        REQUIRE_THROWS_AS(strictValidator.validate(futureToken), TokenNotYetValidError);
    }
    
    SUBCASE("Token with inverted time claims") {
        // A token where nbf > exp is uninhabitable at any instant. The
        // validator now rejects the relationship explicitly, before any
        // individual boundary check runs.
        auto invalidTimeToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(now + std::chrono::minutes(30))
            .withNotBefore(now + std::chrono::hours(1)) // NBF after EXP
            .withCwtIdString("invalid-time-token");

        CatTokenValidator validator;
        validator.withExpectedIssuers({"https://trusted-issuer.com"})
                .withExpectedAudiences({"https://trusted-service.com"});

        REQUIRE_THROWS_AS(validator.validate(invalidTimeToken), InvalidClaimValueError);
    }
}

TEST_CASE("ValidatorNegativeTests - Geographic Validation") {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    
    SUBCASE("Invalid latitude coordinates") {
        // Latitude out of range
        auto invalidLatToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeoCoordinate(95.0, 0.0, 10.0) // Latitude > 90
            .withCwtIdString("invalid-lat-token");
            
            
        CatTokenValidator validator;
        REQUIRE_THROWS_AS(validator.validate(invalidLatToken), GeographicValidationError);
        
        auto invalidLatToken2 = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeoCoordinate(-95.0, 0.0, 10.0) // Latitude < -90
            .withCwtIdString("invalid-lat-token-2");
            
            
        REQUIRE_THROWS_AS(validator.validate(invalidLatToken2), GeographicValidationError);
    }
    
    SUBCASE("Invalid longitude coordinates") {
        // Longitude out of range
        auto invalidLonToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeoCoordinate(0.0, 185.0, 10.0) // Longitude > 180
            .withCwtIdString("invalid-lon-token");
            
            
        CatTokenValidator validator;
        REQUIRE_THROWS_AS(validator.validate(invalidLonToken), GeographicValidationError);
        
        auto invalidLonToken2 = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeoCoordinate(0.0, -185.0, 10.0) // Longitude < -180
            .withCwtIdString("invalid-lon-token-2");
            
            
        REQUIRE_THROWS_AS(validator.validate(invalidLonToken2), GeographicValidationError);
    }
    
    SUBCASE("Invalid radius values") {
        // Third arg to withGeoCoordinate is radius (metres), not altitude.
        // Negative radius is nonsense; the validator now rejects it.
        auto negativeRadiusToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeoCoordinate(0.0, 0.0, -20000.0)
            .withCwtIdString("negative-radius-token");

        CatTokenValidator validator;
        REQUIRE_THROWS_AS(validator.validate(negativeRadiusToken),
                          GeographicValidationError);
    }
    
    SUBCASE("Invalid geohash formats") {
        // Test empty geohash
        auto emptyGeohashToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeohash(GeohashClaimValue{std::string{""}})
            .withCwtIdString("empty-geohash-token");
            
            
        CatTokenValidator validator;
        REQUIRE_THROWS_AS(validator.validate(emptyGeohashToken), GeographicValidationError);
        
        // Test too long geohash (>12 chars)
        auto tooLongGeohashToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeohash(GeohashClaimValue{std::string{"abcdefghijklm"}}) // 13 characters
            .withCwtIdString("too-long-geohash-token");
            
            
        REQUIRE_THROWS_AS(validator.validate(tooLongGeohashToken), GeographicValidationError);
        
        // Validator now validates geohash character set (base32)
        auto invalidCharSetToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeohash(GeohashClaimValue{std::string{"invalid@hash"}}) // Invalid chars
            .withCwtIdString("invalid-chars-token");

        // This now throws because validator checks character set
        REQUIRE_THROWS_AS(validator.validate(invalidCharSetToken), GeographicValidationError);
    }

    SUBCASE("Non-finite coordinate values are rejected") {
        // Range comparisons against NaN always yield false, so a plain
        // `< -90 || > 90` bounds check would silently accept a NaN latitude.
        const double nan_val = std::numeric_limits<double>::quiet_NaN();
        const double inf_val = std::numeric_limits<double>::infinity();

        CatTokenValidator validator;

        auto nanLatToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeoCoordinate(nan_val, 0.0)
            .withCwtIdString("nan-lat-token");
        REQUIRE_THROWS_AS(validator.validate(nanLatToken),
                          GeographicValidationError);

        auto infLonToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeoCoordinate(0.0, inf_val)
            .withCwtIdString("inf-lon-token");
        REQUIRE_THROWS_AS(validator.validate(infLonToken),
                          GeographicValidationError);

        auto nanRadiusToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeoCoordinate(0.0, 0.0, nan_val)
            .withCwtIdString("nan-radius-token");
        REQUIRE_THROWS_AS(validator.validate(nanRadiusToken),
                          GeographicValidationError);
    }

    SUBCASE("Excessive radius is rejected") {
        // A radius > half the Earth's circumference (~2e7 m) is a meaningless
        // "restriction" and typically indicates a producer bug or an attempt
        // to widen the accepted zone beyond the planet.
        auto oversizedRadiusToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeoCoordinate(0.0, 0.0, 3.0e7)
            .withCwtIdString("oversized-radius-token");

        CatTokenValidator validator;
        REQUIRE_THROWS_AS(validator.validate(oversizedRadiusToken),
                          GeographicValidationError);
    }

    SUBCASE("Altitude out of physical range is rejected") {
        CatTokenValidator validator;

        auto tooLowToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeoAltitude(GeoAltitude{-20000})
            .withCwtIdString("altitude-too-low-token");
        REQUIRE_THROWS_AS(validator.validate(tooLowToken),
                          GeographicValidationError);

        auto tooHighToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeoAltitude(GeoAltitude{600000})
            .withCwtIdString("altitude-too-high-token");
        REQUIRE_THROWS_AS(validator.validate(tooHighToken),
                          GeographicValidationError);

        auto negativeDeviationToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeoAltitude(GeoAltitude{0, -1})
            .withCwtIdString("altitude-neg-dev-token");
        REQUIRE_THROWS_AS(validator.validate(negativeDeviationToken),
                          GeographicValidationError);

        auto hugeDeviationToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeoAltitude(GeoAltitude{0, 600000})
            .withCwtIdString("altitude-huge-dev-token");
        REQUIRE_THROWS_AS(validator.validate(hugeDeviationToken),
                          GeographicValidationError);
    }

    SUBCASE("Structured geohash array bounds") {
        CatTokenValidator validator;

        // Empty array wire-forms as a restriction but expresses none —
        // reject rather than silently allow everywhere.
        auto emptyArrayToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeohash(GeohashClaimValue{std::vector<std::string>{}})
            .withCwtIdString("empty-gh-array-token");
        REQUIRE_THROWS_AS(validator.validate(emptyArrayToken),
                          GeographicValidationError);

        // Array larger than the validator's cap of 64 alternatives.
        std::vector<std::string> many(65, "9q8yy");
        auto tooManyToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeohash(GeohashClaimValue{std::move(many)})
            .withCwtIdString("too-many-gh-token");
        REQUIRE_THROWS_AS(validator.validate(tooManyToken),
                          GeographicValidationError);
    }
}

TEST_CASE("ValidatorNegativeTests - Missing Claims") {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    
    SUBCASE("Missing required issuer") {
        auto token = CatToken()
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withCwtIdString("no-issuer-token");
            
            
        CatTokenValidator validator;
        validator.withExpectedIssuers({"https://trusted-issuer.com"});
        
        REQUIRE_THROWS_AS(validator.validate(token), MissingRequiredClaimError);
    }
    
    SUBCASE("Missing required audience") {
        auto token = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withExpiration(exp)
            .withCwtIdString("no-audience-token");
            
            
        CatTokenValidator validator;
        validator.withExpectedAudiences({"https://trusted-service.com"});
        
        REQUIRE_THROWS_AS(validator.validate(token), MissingRequiredClaimError);
    }
    
    SUBCASE("Missing expiration time") {
        auto token = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withCwtIdString("no-exp-token");
            
            
        CatTokenValidator validator;
        // Current implementation only validates expiration if it's present
        REQUIRE_NOTHROW(validator.validate(token));
    }
    
    SUBCASE("Missing CWT ID") {
        auto token = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp);
            
        CatTokenValidator validator;
        // Current implementation doesn't require CWT ID
        REQUIRE_NOTHROW(validator.validate(token));
    }
}

TEST_CASE("ValidatorNegativeTests - Edge Cases and Error Conditions") {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    
    SUBCASE("Negative clock skew tolerance") {
        CatTokenValidator validator;
        // Negative tolerance values are now rejected
        REQUIRE_THROWS_AS(validator.withClockSkewTolerance(-60), InvalidClaimValueError);
    }
    
    SUBCASE("Extremely large clock skew tolerance") {
        auto token = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withCwtIdString("large-skew-token");
            
            
        CatTokenValidator validator;
        // Should handle very large tolerance values gracefully
        REQUIRE_NOTHROW(validator.withClockSkewTolerance(INT64_MAX));
    }
    
    SUBCASE("Malformed URLs in issuer/audience") {
        std::vector<std::string> malformedUrls = {
            "not-a-url",
            "ftp://invalid-scheme.com",
            "https://", // Incomplete URL
            "://missing-scheme.com",
            "https://.invalid.com",
        };
        
        // The current validator treats issuers/audiences as opaque strings
        // It doesn't validate URL format, only does string matching
        for (const auto& url : malformedUrls) {
            auto token = CatToken()
                .withIssuer(url)
                .withAudience({"https://trusted-service.com"})
                .withExpiration(exp)
                .withCwtIdString("malformed-issuer-token");
                
                
            CatTokenValidator validator;
            validator.withExpectedIssuers({url});
            // Should pass because validator just does string matching
            REQUIRE_NOTHROW(validator.validate(token));
        }
    }
    
    SUBCASE("Token with conflicting geographic claims") {
        // Token with coordinates that don't match geohash
        auto conflictingToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeoCoordinate(40.7128, -74.0060, 10.0) // NYC coordinates
            .withGeohash(GeohashClaimValue{std::string{"9q8yy"}}) // San Francisco geohash
            .withCwtIdString("conflicting-geo-token");


        CatTokenValidator validator;
        validator.withAuthorizationPolicy(&sharedPermissivePolicy());
        // Current implementation doesn't validate geohash/coordinate consistency
        REQUIRE_NOTHROW(validator.validate(conflictingToken));
    }
}

TEST_CASE("ValidatedCatToken exposes only-const access") {
    auto validToken = createValidToken();
    CatTokenValidator validator;

    ValidatedCatToken vt = validator.intoValidated(std::move(validToken));

    CHECK(vt.core().iss.has_value());
    CHECK(*vt.core().iss == "https://trusted-issuer.com");
    CHECK(vt.cat().catv.has_value());
    CHECK(*vt.cat().catv == 1u);

    // Compile-time: none of the getters return non-const references. Read
    // access through token() must also be const.
    const CatToken& underlying = vt.token();
    CHECK(underlying.core.iss.has_value());
}

TEST_CASE("ValidatedCatToken cannot be produced for an invalid token") {
    // exp before nbf — validate() must reject this.
    auto now = std::chrono::system_clock::now();
    auto broken = CatToken()
                      .withIssuer("iss")
                      .withAudience({"aud"})
                      .withExpiration(now)
                      .withNotBefore(now + std::chrono::hours(1))
                      .withCwtIdString("broken");
    CatTokenValidator validator;
    CHECK_THROWS_AS(
        (void)validator.intoValidated(std::move(broken)), CatError);
}

TEST_CASE("ValidatedCatToken is move-only") {
    static_assert(!std::is_copy_constructible_v<ValidatedCatToken>,
                  "ValidatedCatToken must not be copyable");
    static_assert(!std::is_copy_assignable_v<ValidatedCatToken>,
                  "ValidatedCatToken must not be copy-assignable");
    static_assert(std::is_move_constructible_v<ValidatedCatToken>,
                  "ValidatedCatToken must be move-constructible");
    static_assert(std::is_move_assignable_v<ValidatedCatToken>,
                  "ValidatedCatToken must be move-assignable");
}

// CAT-4-MOQT (draft-ietf-moq-c4m-01): `moqt-reval` bounds how long a
// relay may cache the authorization decision without re-checking with the
// issuer. The validator must reject a token once `iat + moqt-reval` is in
// the past, must require `iat`, and must fold in the clock-skew tolerance
// consistently with `exp`/`nbf`.
// A MOQT-scoped token requires the request tuple by default. These
// reval-focused tests are not exercising scope enforcement so they
// supply a permissive tuple via `moqtScopeContext()`; the tuple values
// themselves are irrelevant because scopes use `MoqtBinaryMatch::any()`.
namespace {
PolicyContext moqtScopeContext() {
    static const std::string kNs = "ns";
    static const std::string kTrack = "tr";
    PolicyContext ctx;
    ctx.moqt_action = moqt_actions::PUBLISH;
    ctx.moqt_namespace = kNs;
    ctx.moqt_track = kTrack;
    return ctx;
}
}  // namespace

TEST_CASE("MoqtReval - within window accepts token") {
    auto now_tp = std::chrono::system_clock::now();
    CatToken token;
    token.withIssuer("https://issuer.example")
        .withAudience({"https://relay.example"})
        .withExpiration(now_tp + std::chrono::hours(1))
        .withIssuedAt(now_tp - std::chrono::seconds(30));
    MoqtClaims moqt;
    std::vector<int> actions = {moqt_actions::PUBLISH};
    moqt.addScope(actions, MoqtBinaryMatch::any(), MoqtBinaryMatch::any());
    moqt.setRevalidationInterval(std::chrono::seconds(300));
    token.extended.setMoqtClaims(std::move(moqt));

    CatTokenValidator validator;
    REQUIRE_NOTHROW(validator.validate(token, moqtScopeContext()));
}

TEST_CASE("MoqtReval - past deadline rejects with TokenRevalidationRequiredError") {
    auto now_tp = std::chrono::system_clock::now();
    CatToken token;
    token.withIssuer("https://issuer.example")
        .withAudience({"https://relay.example"})
        .withExpiration(now_tp + std::chrono::hours(1))
        .withIssuedAt(now_tp - std::chrono::seconds(600));
    MoqtClaims moqt;
    std::vector<int> actions = {moqt_actions::PUBLISH};
    moqt.addScope(actions, MoqtBinaryMatch::any(), MoqtBinaryMatch::any());
    moqt.setRevalidationInterval(std::chrono::seconds(300));
    token.extended.setMoqtClaims(std::move(moqt));

    CatTokenValidator validator;
    CHECK_THROWS_AS(validator.validate(token, moqtScopeContext()),
                    TokenRevalidationRequiredError);
}

TEST_CASE("MoqtReval - missing iat is rejected as missing required claim") {
    auto now_tp = std::chrono::system_clock::now();
    CatToken token;
    token.withIssuer("https://issuer.example")
        .withAudience({"https://relay.example"})
        .withExpiration(now_tp + std::chrono::hours(1));
    MoqtClaims moqt;
    std::vector<int> actions = {moqt_actions::PUBLISH};
    moqt.addScope(actions, MoqtBinaryMatch::any(), MoqtBinaryMatch::any());
    moqt.setRevalidationInterval(std::chrono::seconds(300));
    token.extended.setMoqtClaims(std::move(moqt));

    CatTokenValidator validator;
    CHECK_THROWS_AS(validator.validate(token, moqtScopeContext()),
                    MissingRequiredClaimError);
}

TEST_CASE("MoqtReval - clock skew tolerance extends the reval window") {
    // Deadline is exactly 60s in the past; a 90s tolerance must rescue it.
    auto now_tp = std::chrono::system_clock::now();
    CatToken token;
    token.withIssuer("https://issuer.example")
        .withAudience({"https://relay.example"})
        .withExpiration(now_tp + std::chrono::hours(1))
        .withIssuedAt(now_tp - std::chrono::seconds(360));
    MoqtClaims moqt;
    std::vector<int> actions = {moqt_actions::PUBLISH};
    moqt.addScope(actions, MoqtBinaryMatch::any(), MoqtBinaryMatch::any());
    moqt.setRevalidationInterval(std::chrono::seconds(300));
    token.extended.setMoqtClaims(std::move(moqt));

    CatTokenValidator strict;
    CHECK_THROWS_AS(strict.validate(token, moqtScopeContext()),
                    TokenRevalidationRequiredError);

    CatTokenValidator lenient;
    lenient.withClockSkewTolerance(90);
    REQUIRE_NOTHROW(lenient.validate(token, moqtScopeContext()));
}

TEST_CASE("MoqtReval - claim absent leaves validation untouched") {
    // Same shape as the passing test but with no reval interval — must
    // not fabricate a deadline out of `iat` alone.
    auto now_tp = std::chrono::system_clock::now();
    CatToken token;
    token.withIssuer("https://issuer.example")
        .withAudience({"https://relay.example"})
        .withExpiration(now_tp + std::chrono::hours(1))
        .withIssuedAt(now_tp - std::chrono::hours(24));
    MoqtClaims moqt;
    std::vector<int> actions = {moqt_actions::PUBLISH};
    moqt.addScope(actions, MoqtBinaryMatch::any(), MoqtBinaryMatch::any());
    token.extended.setMoqtClaims(std::move(moqt));

    CatTokenValidator validator;
    REQUIRE_NOTHROW(validator.validate(token, moqtScopeContext()));
}

TEST_SUITE("tryValidate — non-throwing hot-path surface") {
    TEST_CASE("Returns SUCCESS for a valid token") {
        auto token = createValidToken();
        CatTokenValidator validator;
        CHECK(validator.tryValidate(token) == CatErrorCode::SUCCESS);
    }

    TEST_CASE("Reports TOKEN_EXPIRED without throwing") {
        auto now = std::chrono::system_clock::now();
        auto token = CatToken()
                         .withIssuer("iss")
                         .withAudience({"aud"})
                         .withExpiration(now - std::chrono::hours(1));
        CatTokenValidator validator;
        CHECK(validator.tryValidate(token) == CatErrorCode::TOKEN_EXPIRED);
    }

    TEST_CASE("Reports INVALID_ISSUER without throwing") {
        auto token = createValidToken();
        CatTokenValidator validator;
        validator.withExpectedIssuers({"https://other-issuer.example"});
        CHECK(validator.tryValidate(token) == CatErrorCode::INVALID_ISSUER);
    }

    TEST_CASE("Reports INVALID_AUDIENCE without throwing") {
        auto token = createValidToken();
        CatTokenValidator validator;
        validator.withExpectedAudiences({"https://other-service.example"});
        CHECK(validator.tryValidate(token) == CatErrorCode::INVALID_AUDIENCE);
    }

    TEST_CASE(
        "Reports GEOGRAPHIC_VALIDATION_FAILED for out-of-range coordinates") {
        auto now = std::chrono::system_clock::now();
        auto token = CatToken()
                         .withIssuer("iss")
                         .withAudience({"aud"})
                         .withExpiration(now + std::chrono::hours(1))
                         .withGeoCoordinate(200.0, 0.0);
        CatTokenValidator validator;
        CHECK(validator.tryValidate(token) ==
              CatErrorCode::GEOGRAPHIC_VALIDATION_FAILED);
    }

    TEST_CASE("tryIntoValidated yields ValidatedCatToken on success") {
        auto token = createValidToken();
        CatTokenValidator validator;
        auto result = validator.tryIntoValidated(token);
        REQUIRE(result.isSuccess());
        auto validated = std::move(result).value();
        CHECK(validated.core().iss.value() == "https://trusted-issuer.com");
    }

    TEST_CASE("tryIntoValidated surfaces the same error code on failure") {
        auto now = std::chrono::system_clock::now();
        auto token = CatToken()
                         .withIssuer("iss")
                         .withAudience({"aud"})
                         .withExpiration(now - std::chrono::hours(1));
        CatTokenValidator validator;
        auto result = validator.tryIntoValidated(token);
        REQUIRE(result.isError());
        CHECK(result.error() == CatErrorCode::TOKEN_EXPIRED);
    }

    TEST_CASE("intoValidated with context honours MOQT scope enforcement") {
        // The context-taking overload is the canonical relay entry point:
        // supplying a request tuple lets a shared validator apply
        // request-scoped checks that the context-free overload cannot.
        auto now = std::chrono::system_clock::now();
        auto token = CatToken()
                         .withIssuer("iss")
                         .withAudience({"aud"})
                         .withExpiration(now + std::chrono::hours(1))
                         .withCwtIdString("scoped");
        MoqtClaims moqt;
        std::vector<int> pub{moqt_actions::PUBLISH};
        moqt.addScope(pub, MoqtBinaryMatch::exact("live"),
                      MoqtBinaryMatch::any());
        token.extended.setMoqtClaims(std::move(moqt));

        CatTokenValidator validator;

        PolicyContext ok;
        ok.moqt_action = moqt_actions::PUBLISH;
        std::string live_ns = "live";
        std::string any_track = "audio";
        ok.moqt_namespace = live_ns;
        ok.moqt_track = any_track;
        REQUIRE_NOTHROW(auto v = validator.intoValidated(token, ok));

        PolicyContext bad;
        bad.moqt_action = moqt_actions::SUBSCRIBE;
        bad.moqt_namespace = live_ns;
        bad.moqt_track = any_track;
        CHECK_THROWS_AS((void)validator.intoValidated(token, bad),
                        InvalidClaimValueError);
    }

    TEST_CASE("tryIntoValidated with context surfaces MOQT scope failure") {
        auto now = std::chrono::system_clock::now();
        auto token = CatToken()
                         .withIssuer("iss")
                         .withAudience({"aud"})
                         .withExpiration(now + std::chrono::hours(1))
                         .withCwtIdString("scoped-try");
        MoqtClaims moqt;
        std::vector<int> pub{moqt_actions::PUBLISH};
        moqt.addScope(pub, MoqtBinaryMatch::exact("live"),
                      MoqtBinaryMatch::any());
        token.extended.setMoqtClaims(std::move(moqt));

        CatTokenValidator validator;
        PolicyContext bad;
        bad.moqt_action = moqt_actions::SUBSCRIBE;
        std::string ns = "live";
        std::string tr = "audio";
        bad.moqt_namespace = ns;
        bad.moqt_track = tr;
        auto result = validator.tryIntoValidated(token, bad);
        REQUIRE(result.isError());
        CHECK(result.error() == CatErrorCode::INVALID_CLAIM_VALUE);
    }

    TEST_CASE(
        "intoValidated context-free rejects MOQT-scoped tokens by default") {
        auto now = std::chrono::system_clock::now();
        auto token = CatToken()
                         .withIssuer("iss")
                         .withAudience({"aud"})
                         .withExpiration(now + std::chrono::hours(1))
                         .withCwtIdString("scoped-nocx");
        MoqtClaims moqt;
        std::vector<int> pub{moqt_actions::PUBLISH};
        moqt.addScope(pub, MoqtBinaryMatch::any(), MoqtBinaryMatch::any());
        token.extended.setMoqtClaims(std::move(moqt));

        CatTokenValidator validator;
        CHECK_THROWS_AS((void)validator.intoValidated(token),
                        MissingRequiredClaimError);
    }

    TEST_CASE("catreplay=None passes without a usage-state hook") {
        // Explicitly opting out of replay enforcement must not require a
        // hook — that would break the "issuer says None" contract.
        auto token = createValidToken().withReplayProtection(
            CatReplayMode::None);
        CatTokenValidator validator;
        REQUIRE_NOTHROW(validator.validate(token));
    }

    TEST_CASE("catreplay=RejectOnReplay without a hook fails closed") {
        // Fail-closed contract: a token that opted into replay protection
        // must be rejected when no hook is available, rather than
        // silently downgraded to no enforcement.
        auto token = createValidToken().withReplayProtection(
            CatReplayMode::RejectOnReplay);
        CatTokenValidator validator;
        CHECK_THROWS_AS(validator.validate(token), ReplayAttackError);
    }

    TEST_CASE("catreplay=RejectOnReplay without cti fails as missing claim") {
        // Without a cti there is no stable key to record; enforcement is
        // impossible, and admitting would defeat the whole claim.
        auto token = CatToken()
                         .withIssuer("iss")
                         .withAudience({"aud"})
                         .withExpiration(std::chrono::system_clock::now() +
                                         std::chrono::hours(1))
                         .withReplayProtection(CatReplayMode::RejectOnReplay);
        InMemoryUsageState hook;
        CatTokenValidator validator;
        validator.withUsageStateHook(&hook);
        CHECK_THROWS_AS(validator.validate(token), MissingRequiredClaimError);
    }

    TEST_CASE(
        "catreplay=RejectOnReplay admits once and rejects the second use") {
        auto now = std::chrono::system_clock::now();
        auto token = CatToken()
                         .withIssuer("iss")
                         .withAudience({"aud"})
                         .withExpiration(now + std::chrono::hours(1))
                         .withCwtIdString("cti-reject")
                         .withReplayProtection(CatReplayMode::RejectOnReplay);
        InMemoryUsageState hook;
        CatTokenValidator validator;
        validator.withUsageStateHook(&hook);
        REQUIRE_NOTHROW(validator.validate(token));
        CHECK_THROWS_AS(validator.validate(token), ReplayAttackError);
    }

    TEST_CASE(
        "catreplay=RevokeOnReplay marks the cti and rejects any later "
        "presentation") {
        auto now = std::chrono::system_clock::now();
        auto token = CatToken()
                         .withIssuer("iss")
                         .withAudience({"aud"})
                         .withExpiration(now + std::chrono::hours(1))
                         .withCwtIdString("cti-revoke")
                         .withReplayProtection(CatReplayMode::RevokeOnReplay);
        InMemoryUsageState hook;
        CatTokenValidator validator;
        validator.withUsageStateHook(&hook);
        REQUIRE_NOTHROW(validator.validate(token));
        // Second sighting → Revoked → ReplayAttackError.
        CHECK_THROWS_AS(validator.validate(token), ReplayAttackError);
        // A third presentation is still rejected even after we switch
        // modes on the token, because revocation is sticky in the hook.
        auto rebadged = token;
        rebadged.cat.catreplay = CatReplayMode::RejectOnReplay;
        CHECK_THROWS_AS(validator.validate(rebadged), ReplayAttackError);
    }
}

// Authorization ordering: usage admission is the single write in the
// pipeline and MUST run after every request-scoped check. If it ran
// earlier, a token rejected for a request-side reason (policy hook,
// MOQT scope, revalidation deadline) would still have consumed its
// one-time `cti`, and the client could never retry with a corrected
// request. These cases lock in "reject-before-admit" for each failure
// mode that follows admission in the previous ordering.
TEST_SUITE("Authorization ordering — usage admission is deferred") {
    TEST_CASE("Policy rejection does not consume the cti") {
        auto now = std::chrono::system_clock::now();
        auto token = CatToken()
                         .withIssuer("iss")
                         .withAudience({"aud"})
                         .withExpiration(now + std::chrono::hours(1))
                         .withCwtIdString("cti-order-policy")
                         .withReplayProtection(CatReplayMode::RejectOnReplay);
        // Attach a claim that forces the policy hook to fire.
        CatProofOfPossession por;
        por.probability = 1.0;
        por.identifier = {0x01, 0x02, 0x03};
        token.cat.catpor = por;

        InMemoryUsageState hook;
        RejectingPolicy policy;
        CatTokenValidator validator;
        validator.withUsageStateHook(&hook).withAuthorizationPolicy(&policy);

        // First call: policy rejects, so admission must NOT have written.
        CHECK_THROWS_AS(validator.validate(token), InvalidClaimValueError);
        CHECK(hook.size() == 0);

        // Swap in a permissive policy — the same cti still admits cleanly,
        // proving the earlier rejection did not silently consume it.
        PermissivePolicy permissive;
        validator.withAuthorizationPolicy(&permissive);
        REQUIRE_NOTHROW(validator.validate(token));
        CHECK(hook.size() == 1);
    }

    TEST_CASE("MOQT scope mismatch does not consume the cti") {
        auto now = std::chrono::system_clock::now();
        MoqtClaims moqt;
        std::vector<int> actions = {moqt_actions::PUBLISH};
        moqt.addScope(actions, MoqtBinaryMatch::exact("news"),
                      MoqtBinaryMatch::exact("headlines"));

        auto token = CatToken()
                         .withIssuer("iss")
                         .withAudience({"aud"})
                         .withExpiration(now + std::chrono::hours(1))
                         .withCwtIdString("cti-order-scope")
                         .withReplayProtection(CatReplayMode::RejectOnReplay);
        token.extended.setMoqtClaims(std::move(moqt));

        PolicyContext context;
        context.moqt_action = moqt_actions::PUBLISH;
        std::string bad_ns = "weather";  // not authorised
        std::string good_ns = "news";
        std::string track = "headlines";
        context.moqt_namespace = bad_ns;
        context.moqt_track = track;

        InMemoryUsageState hook;
        CatTokenValidator validator;
        validator.withUsageStateHook(&hook);

        CHECK_THROWS_AS(validator.validate(token, context),
                        InvalidClaimValueError);
        CHECK(hook.size() == 0);

        // Retry with the authorised namespace — the cti is still fresh.
        context.moqt_namespace = good_ns;
        REQUIRE_NOTHROW(validator.validate(token, context));
        CHECK(hook.size() == 1);
    }
}
