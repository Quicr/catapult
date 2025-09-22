#include <doctest/doctest.h>
#include "catapult/token_factory.hpp"
#include "catapult/crypto.hpp"
#include "catapult/claims.hpp"

using namespace catapult;

// Helper function for tests
CatToken create_minimal_token(const std::string& issuer, const std::string& audience) {
    CatToken token;
    token.core.iss = issuer;
    token.core.aud = std::vector<std::string>{audience};
    return token;
}

TEST_CASE("TokenFactory_CreateMinimalToken") {
    auto token = create_minimal_token("https://issuer.com", "https://audience.com");
    
    REQUIRE(token.core.iss.has_value());
    CHECK(token.core.iss.value() == "https://issuer.com");
    
    REQUIRE(token.core.aud.has_value());
    REQUIRE(token.core.aud->size() == 1);
    CHECK(token.core.aud->at(0) == "https://audience.com");
}

TEST_CASE("TokenFactory_CreateGeoToken_ValidCoordinates") {
    // Test with San Francisco coordinates  
    auto token = token_factory::create_geo_token(
        "https://geo-issuer.com", 
        "https://geo-service.com",
        37.7749, -122.4194
    );
    
    // Check core claims
    REQUIRE(token.core.iss.has_value());
    CHECK(token.core.iss.value() == "https://geo-issuer.com");
    
    REQUIRE(token.core.aud.has_value());
    REQUIRE(token.core.aud->size() == 1);
    CHECK(token.core.aud->at(0) == "https://geo-service.com");
    
    // Check geographic coordinate claim
    REQUIRE(token.cat.catgeocoord.has_value());
    CHECK(token.cat.catgeocoord->lat == 37.7749);
    CHECK(token.cat.catgeocoord->lon == -122.4194);
    CHECK(token.cat.catgeocoord->is_valid());
}

TEST_CASE("TokenFactory_CreateGeoToken_EdgeCoordinates") {
    // Test with edge coordinates
    auto token = token_factory::create_geo_token(
        "https://polar-issuer.com", 
        "https://polar-service.com",
        90.0, 0.0
    );
    
    REQUIRE(token.cat.catgeocoord.has_value());
    CHECK(token.cat.catgeocoord->lat == 90.0);
    CHECK(token.cat.catgeocoord->lon == 0.0);
    CHECK(token.cat.catgeocoord->is_valid());
}

TEST_CASE("TokenFactory_CreateGeoToken_DateLine") {
    // Test with coordinates near the international date line
    auto token_east = token_factory::create_geo_token(
        "https://dateline-issuer.com", 
        "https://dateline-service.com",
        0.0, 180.0
    );
    
    auto token_west = token_factory::create_geo_token(
        "https://dateline-issuer.com", 
        "https://dateline-service.com",
        0.0, -180.0
    );
    
    REQUIRE(token_east.cat.catgeocoord.has_value());
    CHECK(token_east.cat.catgeocoord->lat == 0.0);
    CHECK(token_east.cat.catgeocoord->lon == 180.0);
    CHECK(token_east.cat.catgeocoord->is_valid());
    
    REQUIRE(token_west.cat.catgeocoord.has_value());
    CHECK(token_west.cat.catgeocoord->lat == 0.0);
    CHECK(token_west.cat.catgeocoord->lon == -180.0);
    CHECK(token_west.cat.catgeocoord->is_valid());
}

TEST_CASE("TokenFactory_CreateGeoToken_CompileTimeVersion") {
    // Test compile-time version with integer-based coordinates
    // San Francisco: 37.7749, -122.4194 -> 377749, -1224194
    auto token = token_factory::create_geo_token_fixed<377749, -1224194>(
        "https://compile-time-issuer.com", 
        "https://compile-time-service.com"
    );
    
    REQUIRE(token.cat.catgeocoord.has_value());
    CHECK(token.cat.catgeocoord->lat == 37.7749);
    CHECK(token.cat.catgeocoord->lon == -122.4194);
    CHECK(token.cat.catgeocoord->is_valid());
}

TEST_CASE("TokenFactory_CreateGeoToken_InvalidCoordinates") {
    // Test runtime validation with invalid coordinates
    CHECK_THROWS_AS(
        token_factory::create_geo_token(
            "https://invalid-issuer.com", 
            "https://invalid-service.com",
            91.0, 0.0  // Invalid latitude > 90
        ),
        std::invalid_argument
    );
    
    CHECK_THROWS_AS(
        token_factory::create_geo_token(
            "https://invalid-issuer.com", 
            "https://invalid-service.com",
            0.0, 181.0  // Invalid longitude > 180
        ),
        std::invalid_argument
    );
}

// Compile-time validation tests (these should not compile if uncommented)
// TEST_CASE("TokenFactory_CreateGeoToken_InvalidLatitudeCompileTime") {
//     // This should cause a compile-time error due to static_assert
//     auto token = token_factory::create_geo_token_fixed<910000, 0>(  // Invalid latitude > 90
//         "https://invalid-issuer.com", 
//         "https://invalid-service.com"
//     );
// }

TEST_CASE("SecureMemory_HmacKeyGeneration") {
    // Test secure HMAC key generation
    auto secure_key = HmacSha256Algorithm::generateSecureKey();
    auto regular_key = secure_utils::to_regular_vector(HmacSha256Algorithm::generateSecureKey());
    
    CHECK(secure_key.size() == crypto_constants::HMAC_KEY_SIZE);
    CHECK(regular_key.size() == crypto_constants::HMAC_KEY_SIZE);
    
    // Keys should be different (extremely unlikely to be the same)
    // Convert to same type for comparison
    auto regular_secure_key = secure_utils::to_regular_vector(secure_key);
    CHECK(regular_secure_key != regular_key);
    
    // Test that both keys work for algorithm construction
    HmacSha256Algorithm secure_algo(secure_key);
    HmacSha256Algorithm regular_algo(regular_key);
    
    CHECK(secure_algo.algorithmId() == ALG_HMAC256_256);
    CHECK(regular_algo.algorithmId() == ALG_HMAC256_256);
}

TEST_CASE("SecureMemory_Es256SecureKeyPair") {
    // Test secure ES256 key pair generation
    auto [secure_private, public_key] = Es256Algorithm::generateSecureKeyPair();
    auto [regular_private, regular_public] = Es256Algorithm::generateKeyPair();
    
    CHECK(secure_private.size() > 0);
    CHECK(public_key.size() > 0);
    CHECK(regular_private.size() > 0);
    CHECK(regular_public.size() > 0);
    
    // Test constructor with secure private key
    Es256Algorithm secure_algo(secure_private, public_key);
    Es256Algorithm regular_algo(regular_private, regular_public);
    
    CHECK(secure_algo.algorithmId() == ALG_ES256);
    CHECK(regular_algo.algorithmId() == ALG_ES256);
}

TEST_CASE("SecureMemory_Ps256SecureKeyPair") {
    // Test secure PS256 key pair generation
    auto [secure_private, public_key] = Ps256Algorithm::generateSecureKeyPair();
    auto [regular_private, regular_public] = Ps256Algorithm::generateKeyPair();
    
    CHECK(secure_private.size() > 0);
    CHECK(public_key.size() > 0);
    CHECK(regular_private.size() > 0);
    CHECK(regular_public.size() > 0);
    
    // Test constructor with secure private key
    Ps256Algorithm secure_algo(secure_private, public_key);
    Ps256Algorithm regular_algo(regular_private, regular_public);
    
    CHECK(secure_algo.algorithmId() == ALG_PS256);
    CHECK(regular_algo.algorithmId() == ALG_PS256);
}

TEST_CASE("SecureMemory_UtilityFunctions") {
    // Test secure_utils conversion functions
    std::vector<uint8_t> regular_vec = {1, 2, 3, 4, 5};
    
    auto secure_vec = secure_utils::to_secure_vector(regular_vec);
    auto converted_back = secure_utils::to_regular_vector(secure_vec);
    
    CHECK(secure_vec.size() == regular_vec.size());
    CHECK(converted_back.size() == regular_vec.size());
    CHECK(converted_back == regular_vec);
    
    // Check that secure vector has the expected allocator
    static_assert(std::is_same_v<decltype(secure_vec)::allocator_type, SecureAllocator<uint8_t>>);
}