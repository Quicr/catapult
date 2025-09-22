#include <doctest/doctest.h>
#include "catapult/crypto.hpp"

using namespace catapult;

TEST_CASE("Base64UrlEncoding") {
    std::vector<uint8_t> data = {0x4d, 0x61, 0x6e}; // "Man"
    std::string encoded = base64UrlEncode(data);
    CHECK(encoded == "TWFu");
    
    auto decoded = base64UrlDecode(encoded);
    CHECK(decoded == data);
}

TEST_CASE("Base64UrlEncodingPadding") {
    std::vector<uint8_t> data = {0x4d, 0x61}; // "Ma"
    std::string encoded = base64UrlEncode(data);
    CHECK(encoded == "TWE"); // No padding in URL-safe base64
    
    auto decoded = base64UrlDecode(encoded);
    CHECK(decoded == data);
}

TEST_CASE("Base64UrlInvalidCharacter") {
    REQUIRE_THROWS_AS(base64UrlDecode("TW@u"), InvalidBase64Error);
}

TEST_CASE("Sha256Hash") {
    std::vector<uint8_t> testData = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64}; // "Hello World"
    auto hash = hashSha256(testData);
    CHECK(hash.size() == 32); // SHA256 produces 32-byte hash
    
    // Test that same input produces same hash
    auto hash2 = hashSha256(testData);
    CHECK(hash == hash2);
    
    // Test that different input produces different hash
    std::vector<uint8_t> differentData = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    auto differentHash = hashSha256(differentData);
    CHECK(hash != differentHash);
}

TEST_CASE("CreateSigningInput") {
    std::vector<uint8_t> header = {0x7b, 0x22, 0x61, 0x6c, 0x67, 0x22, 0x3a, 0x22, 0x48, 0x53, 0x32, 0x35, 0x36, 0x22, 0x7d}; // {"alg":"HS256"}
    std::vector<uint8_t> payload = {0x7b, 0x22, 0x73, 0x75, 0x62, 0x22, 0x3a, 0x22, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x22, 0x7d}; // {"sub":"1234567890"}
    
    auto signingInput = createSigningInput(header, payload);
    
    // Should be base64url(header) + "." + base64url(payload)
    std::string expected = base64UrlEncode(header) + "." + base64UrlEncode(payload);
    std::string actual(signingInput.begin(), signingInput.end());
    
    CHECK(actual == expected);
}

TEST_CASE("HmacSha256GenerateKey") {
    auto key = secure_utils::to_regular_vector(HmacSha256Algorithm::generateSecureKey());
    CHECK(key.size() == 32); // 256 bits = 32 bytes
    
    // Generate another key and verify they're different
    auto key2 = secure_utils::to_regular_vector(HmacSha256Algorithm::generateSecureKey());
    CHECK(key != key2);
}

TEST_CASE("HmacSha256SignAndVerify") {
    std::vector<uint8_t> testData = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64}; // "Hello World"
    auto key = secure_utils::to_regular_vector(HmacSha256Algorithm::generateSecureKey());
    HmacSha256Algorithm algorithm(key);
    
    auto signature = algorithm.sign(testData);
    CHECK_FALSE(signature.empty());
    
    // Verify with correct key
    CHECK(algorithm.verify(testData, signature));
    
    // Verify with different data should fail
    std::vector<uint8_t> differentData = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    CHECK_FALSE(algorithm.verify(differentData, signature));
    
    // Verify with different key should fail
    auto key2 = secure_utils::to_regular_vector(HmacSha256Algorithm::generateSecureKey());
    HmacSha256Algorithm algorithm2(key2);
    CHECK_FALSE(algorithm2.verify(testData, signature));
}

TEST_CASE("HmacSha256AlgorithmId") {
    auto key = secure_utils::to_regular_vector(HmacSha256Algorithm::generateSecureKey());
    HmacSha256Algorithm algorithm(key);
    
    CHECK(algorithm.algorithmId() == ALG_HMAC256_256);
}

TEST_CASE("Es256GenerateKeyPair") {
    auto keyPair = Es256Algorithm::generateKeyPair();
    CHECK_FALSE(keyPair.first.empty());  // Private key
    CHECK_FALSE(keyPair.second.empty()); // Public key
    
    // Generate another key pair and verify they're different
    auto keyPair2 = Es256Algorithm::generateKeyPair();
    CHECK(keyPair.first != keyPair2.first);
    CHECK(keyPair.second != keyPair2.second);
}

TEST_CASE("Es256AlgorithmId") {
    Es256Algorithm algorithm;
    CHECK(algorithm.algorithmId() == ALG_ES256);
}

TEST_CASE("Ps256GenerateKeyPair") {
    auto keyPair = Ps256Algorithm::generateKeyPair();
    CHECK_FALSE(keyPair.first.empty());  // Private key
    CHECK_FALSE(keyPair.second.empty()); // Public key
    
    // Generate another key pair and verify they're different
    auto keyPair2 = Ps256Algorithm::generateKeyPair();
    CHECK(keyPair.first != keyPair2.first);
    CHECK(keyPair.second != keyPair2.second);
}

TEST_CASE("Ps256AlgorithmId") {
    Ps256Algorithm algorithm;
    CHECK(algorithm.algorithmId() == ALG_PS256);
}

// Note: Full Es256 and Ps256 sign/verify tests would require proper key loading
// which is not fully implemented in the simplified version