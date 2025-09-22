#include <doctest/doctest.h>
#include "catapult/claims.hpp"
#include "catapult/validator.hpp"
#include <chrono>

using namespace catapult;

static auto createValidToken() {
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
        .withCwtId("different-issuer-token");
        

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
        .withCwtId("multi-audience-token");
        

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
        .withCwtId("short-lived-token");
        
    
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
        .withCwtId("expired-token");
        

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
    auto tokenWithShortGeohash = CatToken().withGeohash("u");
    REQUIRE_NOTHROW(validator.validate(tokenWithShortGeohash));
    
    auto tokenWithLongGeohash = CatToken().withGeohash("u4pruydqqvj"); // 12 characters
    REQUIRE_NOTHROW(validator.validate(tokenWithLongGeohash));
    
    // Test invalid geohash length
    auto tokenWithTooLongGeohash = CatToken().withGeohash("u4pruydqqvjkl"); // 13 characters
    REQUIRE_THROWS_AS(validator.validate(tokenWithTooLongGeohash), GeographicValidationError);
}

// Additional positive tests for CatTokenValidator
TEST_CASE("ValidatorPositiveTests - Basic Functionality") {
    CatTokenValidator validator;
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(2);
    auto nbf = now - std::chrono::minutes(10);
    
    SUBCASE("Valid token with all claims") {
        auto token = CatToken()
            .withIssuer("https://test-issuer.com")
            .withAudience({"https://test-service.com"})
            .withExpiration(exp)
            .withNotBefore(nbf)
            .withCwtId("test-token-123")
            .withVersion("2.0")
            .withGeoCoordinate(37.7749, -122.4194, 100.0)
            .withGeohash("9q8yy");
            
            
        REQUIRE_NOTHROW(validator.validate(token));
    }
    
    SUBCASE("Token with minimal required claims") {
        auto minimalToken = CatToken()
            .withIssuer("https://minimal-issuer.com")
            .withAudience({"https://minimal-service.com"})
            .withExpiration(exp)
            .withCwtId("minimal-token");
            
            
        REQUIRE_NOTHROW(validator.validate(minimalToken));
    }
    
    SUBCASE("Token with multiple audiences") {
        auto multiAudToken = CatToken()
            .withIssuer("https://multi-issuer.com")
            .withAudience({"https://service1.com", "https://service2.com", "https://service3.com"})
            .withExpiration(exp)
            .withCwtId("multi-aud-token");
            
            
        REQUIRE_NOTHROW(validator.validate(multiAudToken));
    }
    
    SUBCASE("Token with future not-before time within tolerance") {
        auto futureNbf = now + std::chrono::minutes(1);
        auto futureToken = CatToken()
            .withIssuer("https://future-issuer.com")
            .withAudience({"https://future-service.com"})
            .withExpiration(exp)
            .withNotBefore(futureNbf)
            .withCwtId("future-token");
            
            
        validator.withClockSkewTolerance(300); // 5 minutes tolerance
        REQUIRE_NOTHROW(validator.validate(futureToken));
    }
}

TEST_CASE("ValidatorPositiveTests - Geographic Claims") {
    CatTokenValidator validator;
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    
    SUBCASE("Valid coordinates around the world") {
        // Tokyo
        auto tokyoToken = CatToken()
            .withIssuer("https://geo-issuer.com")
            .withAudience({"https://geo-service.com"})
            .withExpiration(exp)
            .withGeoCoordinate(35.6762, 139.6503, 10.0)
            .withCwtId("tokyo-token");
            
        REQUIRE_NOTHROW(validator.validate(tokyoToken));
        
        // London
        auto londonToken = CatToken()
            .withIssuer("https://geo-issuer.com")
            .withAudience({"https://geo-service.com"})
            .withExpiration(exp)
            .withGeoCoordinate(51.5074, -0.1278, 25.0)
            .withCwtId("london-token");
            
        REQUIRE_NOTHROW(validator.validate(londonToken));
        
        // Sydney
        auto sydneyToken = CatToken()
            .withIssuer("https://geo-issuer.com")
            .withAudience({"https://geo-service.com"})
            .withExpiration(exp)
            .withGeoCoordinate(-33.8688, 151.2093, 50.0)
            .withCwtId("sydney-token");
            
        REQUIRE_NOTHROW(validator.validate(sydneyToken));
    }
    
    SUBCASE("Valid geohash variations") {
        std::vector<std::string> validHashes = {"9", "dr", "9q8", "dr5r", "9q8yy", "dr5reg", "9q8yywe"};
        
        for (const auto& hash : validHashes) {
            auto token = CatToken()
                .withIssuer("https://hash-issuer.com")
                .withAudience({"https://hash-service.com"})
                .withExpiration(exp)
                .withGeohash(hash)
                .withCwtId("hash-token-" + hash);
                
            REQUIRE_NOTHROW(validator.validate(token));
        }
    }
    
    SUBCASE("Token with both coordinates and geohash") {
        auto geoToken = CatToken()
            .withIssuer("https://geo-combo-issuer.com")
            .withAudience({"https://geo-combo-service.com"})
            .withExpiration(exp)
            .withGeoCoordinate(40.7128, -74.0060, 30.0)
            .withGeohash("dr5reg")
            .withCwtId("geo-combo-token");
            
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
            .withCwtId("wildcard-issuer-token");
            
            
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
            .withCwtId("wildcard-audience-token");
            
            
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
            .withCwtId("expired-but-tolerated-token");
            
            
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
            .withCwtId("complex-lists-token");
            
            
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
            .withCwtId("invalid-issuer-token");
            
            
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
            .withCwtId("invalid-audience-token");
            
            
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
            .withCwtId("no-matching-audience-token");
            
            
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
            .withCwtId("empty-issuer-token");
            
            
        CatTokenValidator validator;
        validator.withExpectedIssuers({"https://trusted-issuer.com"});
        
        REQUIRE_THROWS_AS(validator.validate(token), InvalidIssuerError);
    }
    
    SUBCASE("Empty audience") {
        auto token = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"", "https://valid-service.com"})
            .withExpiration(exp)
            .withCwtId("empty-audience-token");
            
            
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
            .withCwtId("only-empty-audience-token");
            
            
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
            .withCwtId("expired-token");
            
            
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
            .withCwtId("future-token");
            
            
        CatTokenValidator strictValidator;
        strictValidator.withExpectedIssuers({"https://trusted-issuer.com"})
                      .withExpectedAudiences({"https://trusted-service.com"})
                      .withClockSkewTolerance(30); // 30 second tolerance
        
        REQUIRE_THROWS_AS(strictValidator.validate(futureToken), TokenNotYetValidError);
    }
    
    SUBCASE("Token with inverted time claims") {
        // Token where not-before is after expiration - validator checks NBF first
        auto invalidTimeToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(now + std::chrono::minutes(30))
            .withNotBefore(now + std::chrono::hours(1)) // NBF after EXP
            .withCwtId("invalid-time-token");
            
            
        CatTokenValidator validator;
        validator.withExpectedIssuers({"https://trusted-issuer.com"})
                .withExpectedAudiences({"https://trusted-service.com"});
        
        // The validator checks NBF before EXP, so this throws TokenNotYetValidError
        REQUIRE_THROWS_AS(validator.validate(invalidTimeToken), TokenNotYetValidError);
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
            .withCwtId("invalid-lat-token");
            
            
        CatTokenValidator validator;
        REQUIRE_THROWS_AS(validator.validate(invalidLatToken), GeographicValidationError);
        
        auto invalidLatToken2 = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeoCoordinate(-95.0, 0.0, 10.0) // Latitude < -90
            .withCwtId("invalid-lat-token-2");
            
            
        REQUIRE_THROWS_AS(validator.validate(invalidLatToken2), GeographicValidationError);
    }
    
    SUBCASE("Invalid longitude coordinates") {
        // Longitude out of range
        auto invalidLonToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeoCoordinate(0.0, 185.0, 10.0) // Longitude > 180
            .withCwtId("invalid-lon-token");
            
            
        CatTokenValidator validator;
        REQUIRE_THROWS_AS(validator.validate(invalidLonToken), GeographicValidationError);
        
        auto invalidLonToken2 = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeoCoordinate(0.0, -185.0, 10.0) // Longitude < -180
            .withCwtId("invalid-lon-token-2");
            
            
        REQUIRE_THROWS_AS(validator.validate(invalidLonToken2), GeographicValidationError);
    }
    
    SUBCASE("Invalid altitude values") {
        // The current validator only checks lat/lon bounds, not altitude
        // This test documents current behavior - altitude validation may be added later
        auto negativeAltToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeoCoordinate(0.0, 0.0, -20000.0) // Extreme negative altitude
            .withCwtId("negative-alt-token");
            
            
        CatTokenValidator validator;
        // Current implementation doesn't validate altitude bounds
        REQUIRE_NOTHROW(validator.validate(negativeAltToken));
    }
    
    SUBCASE("Invalid geohash formats") {
        // Test empty geohash
        auto emptyGeohashToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeohash("")
            .withCwtId("empty-geohash-token");
            
            
        CatTokenValidator validator;
        REQUIRE_THROWS_AS(validator.validate(emptyGeohashToken), GeographicValidationError);
        
        // Test too long geohash (>12 chars)
        auto tooLongGeohashToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeohash("abcdefghijklm") // 13 characters
            .withCwtId("too-long-geohash-token");
            
            
        REQUIRE_THROWS_AS(validator.validate(tooLongGeohashToken), GeographicValidationError);
        
        // Current implementation doesn't validate character sets, only length
        auto validCharSetToken = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withGeohash("invalid@hash") // Invalid chars but length OK
            .withCwtId("invalid-chars-token");
            
            
        // This passes because validator only checks length
        REQUIRE_NOTHROW(validator.validate(validCharSetToken));
    }
}

TEST_CASE("ValidatorNegativeTests - Missing Claims") {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    
    SUBCASE("Missing required issuer") {
        auto token = CatToken()
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withCwtId("no-issuer-token");
            
            
        CatTokenValidator validator;
        validator.withExpectedIssuers({"https://trusted-issuer.com"});
        
        REQUIRE_THROWS_AS(validator.validate(token), MissingRequiredClaimError);
    }
    
    SUBCASE("Missing required audience") {
        auto token = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withExpiration(exp)
            .withCwtId("no-audience-token");
            
            
        CatTokenValidator validator;
        validator.withExpectedAudiences({"https://trusted-service.com"});
        
        REQUIRE_THROWS_AS(validator.validate(token), MissingRequiredClaimError);
    }
    
    SUBCASE("Missing expiration time") {
        auto token = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withCwtId("no-exp-token");
            
            
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
        auto token = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withCwtId("negative-skew-token");
            
            
        CatTokenValidator validator;
        // Current implementation allows negative tolerance values
        REQUIRE_NOTHROW(validator.withClockSkewTolerance(-60));
        
        // However, negative tolerance would make validation stricter
        // Test that it doesn't cause issues with valid tokens
        REQUIRE_NOTHROW(validator.validate(token));
    }
    
    SUBCASE("Extremely large clock skew tolerance") {
        auto token = CatToken()
            .withIssuer("https://trusted-issuer.com")
            .withAudience({"https://trusted-service.com"})
            .withExpiration(exp)
            .withCwtId("large-skew-token");
            
            
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
                .withCwtId("malformed-issuer-token");
                
                
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
            .withGeohash("9q8yy") // San Francisco geohash
            .withCwtId("conflicting-geo-token");
            
            
        CatTokenValidator validator;
        // Current implementation doesn't validate geohash/coordinate consistency
        REQUIRE_NOTHROW(validator.validate(conflictingToken));
    }
}