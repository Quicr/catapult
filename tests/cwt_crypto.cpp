#include <doctest/doctest.h>
#include "catapult/cwt.hpp"
#include "catapult/crypto.hpp"
#include "catapult/base64.hpp"
#include <chrono>

using namespace catapult;

/**
 * @brief Test suite for RFC 8392 Section 7 compliance
 * Tests CWT creation, validation, signing, MACing, and base64url encoding/decoding
 */
TEST_SUITE("RFC 8392 CWT Compliance Tests") {

    auto checkBase64UrlEncoding(const std::string& encoded) {
        CHECK_FALSE(encoded.empty());
        CHECK(encoded.find('+') == std::string::npos);
        CHECK(encoded.find('/') == std::string::npos);
        CHECK(encoded.find('=') == std::string::npos);
    }

    auto createTestToken() {
        return CatToken()
            .withIssuer("https://example-issuer.com")
            .withAudience({"https://service1.example.com", "https://service2.example.com"})
            .withExpiration(std::chrono::system_clock::from_time_t(1735689600)) // Jan 1, 2025
            .withNotBefore(std::chrono::system_clock::from_time_t(1704067200))  // Jan 1, 2024
            .withCwtId("test-cwt-id-12345")
            .withVersion("2.0")
            .withUsageLimit(1000)
            .withReplayProtection("unique-nonce-abcdef")
            .withProofOfPossession(true)
            .withGeoCoordinate(37.7749, -122.4194, 15.5)  // San Francisco with accuracy
            .withGeohash("9q8yy9n");
    }

    TEST_CASE("RFC 8392 Section 7 - Create Signed CWT with ES256") {
        // Create test token
        auto token = createTestToken();
        Cwt cwt(ALG_ES256, token);
        cwt.withKeyId("test-key-es256");
        
        // Generate ES256 key pair
        auto keyPair = Es256Algorithm::generateKeyPair();
        Es256Algorithm es256Alg(keyPair.first, keyPair.second);
        
        // Create signed CWT according to RFC 8392 Section 7
        REQUIRE_NOTHROW({
            std::string signedCwt = cwt.createCwt(CwtMode::Signed, es256Alg);
            
            // Verify the result is base64url encoded
            checkBase64UrlEncoding(signedCwt);
            
            // Should be able to decode from base64url
            auto decoded = base64UrlDecode(signedCwt);
            CHECK_FALSE(decoded.empty());
            
            INFO("Generated CWT: " << signedCwt.substr(0, 50) << "...");
            INFO("CWT length: " << signedCwt.size() << " characters");
            INFO("Decoded length: " << decoded.size() << " bytes");
        });
    }

    TEST_CASE("RFC 8392 Section 7 - Create MACed CWT with HMAC-SHA256") {
        auto token = createTestToken();
        Cwt cwt(ALG_HMAC256_256, token);
        cwt.withKeyId("test-key-hmac256");
        
        // Generate HMAC key
        auto hmacKey = HmacSha256Algorithm::generateSecureKey();
        HmacSha256Algorithm hmacAlg(hmacKey);
        
        // Create MACed CWT according to RFC 8392 Section 7
        REQUIRE_NOTHROW({
            std::string macedCwt = cwt.createCwt(CwtMode::MACed, hmacAlg);
            
            // Verify base64url encoding
            checkBase64UrlEncoding(macedCwt);
            
            INFO("Generated MACed CWT length: " << macedCwt.size());
        });
    }

    TEST_CASE("RFC 8392 Section 7 - Create Signed CWT with PS256") {
        auto token = createTestToken();
        Cwt cwt(ALG_PS256, token);
        cwt.withKeyId("test-key-ps256");
        
        // Generate PS256 key pair
        auto keyPair = Ps256Algorithm::generateKeyPair();
        Ps256Algorithm ps256Alg(keyPair.first, keyPair.second);
        
        // Create signed CWT
        REQUIRE_NOTHROW({
            std::string signedCwt = cwt.createCwt(CwtMode::Signed, ps256Alg);
            
            checkBase64UrlEncoding(signedCwt);
            
            INFO("Generated PS256 CWT length: " << signedCwt.size());
        });
    }

    TEST_CASE("RFC 8392 Section 7 - Full Round Trip: Create and Validate Signed CWT") {
        auto originalToken = createTestToken();
        Cwt originalCwt(ALG_ES256, originalToken);
        originalCwt.withKeyId("roundtrip-test-key");
        
        // Generate key pair for signing/verification
        auto keyPair = Es256Algorithm::generateKeyPair();
        Es256Algorithm signingAlg(keyPair.first, keyPair.second);
        Es256Algorithm verificationAlg(keyPair.second); // Verification-only (public key only)
        
        // Step 1: Create signed CWT according to RFC 8392
        std::string signedCwt = originalCwt.createCwt(CwtMode::Signed, signingAlg);
        
        // Step 2: Validate the CWT according to RFC 8392
        REQUIRE_NOTHROW({
            Cwt validatedCwt = Cwt::validateCwt(signedCwt, verificationAlg);
            
            // Verify payload was correctly recovered
            CHECK(validatedCwt.payload.core.iss == originalToken.core.iss);
            CHECK(validatedCwt.payload.core.aud == originalToken.core.aud);
            CHECK(validatedCwt.payload.core.exp == originalToken.core.exp);
            CHECK(validatedCwt.payload.core.nbf == originalToken.core.nbf);
            CHECK(validatedCwt.payload.core.cti == originalToken.core.cti);
            CHECK(validatedCwt.payload.cat.catv == originalToken.cat.catv);
            CHECK(validatedCwt.payload.cat.catu == originalToken.cat.catu);
            CHECK(validatedCwt.payload.cat.catreplay == originalToken.cat.catreplay);
            CHECK(validatedCwt.payload.cat.catpor == originalToken.cat.catpor);
            CHECK(validatedCwt.payload.cat.geohash == originalToken.cat.geohash);
            
            INFO("Round trip validation successful");
        });
    }

    TEST_CASE("RFC 8392 Section 7 - Full Round Trip: Create and Validate MACed CWT") {
        auto originalToken = createTestToken();
        Cwt originalCwt(ALG_HMAC256_256, originalToken);
        originalCwt.withKeyId("hmac-roundtrip-test");
        
        // Generate shared HMAC key
        auto sharedKey = HmacSha256Algorithm::generateKey();
        HmacSha256Algorithm hmacAlg(sharedKey);
        
        // Step 1: Create MACed CWT
        std::string macedCwt = originalCwt.createCwt(CwtMode::MACed, hmacAlg);
        
        // Step 2: Validate the CWT
        REQUIRE_NOTHROW({
            Cwt validatedCwt = Cwt::validateCwt(macedCwt, hmacAlg);
            
            // Verify payload integrity
            CHECK(validatedCwt.payload.core.iss == originalToken.core.iss);
            CHECK(validatedCwt.payload.core.aud == originalToken.core.aud);
            CHECK(validatedCwt.payload.cat.catv == originalToken.cat.catv);
            
            INFO("HMAC round trip validation successful");
        });
    }

    TEST_CASE("RFC 8392 Section 7 - Validate CWT with Wrong Key Should Fail") {
        auto token = createTestToken();
        Cwt cwt(ALG_ES256, token);
        
        // Generate two different key pairs
        auto correctKeyPair = Es256Algorithm::generateKeyPair();
        auto wrongKeyPair = Es256Algorithm::generateKeyPair();
        
        Es256Algorithm correctAlg(correctKeyPair.first, correctKeyPair.second);
        Es256Algorithm wrongAlg(wrongKeyPair.second); // Wrong public key
        
        // Create CWT with correct key
        std::string signedCwt = cwt.createCwt(CwtMode::Signed, correctAlg);
        
        // Try to validate with wrong key - should fail
        CHECK_THROWS_AS(Cwt::validateCwt(signedCwt, wrongAlg), CryptoError);
    }

    TEST_CASE("RFC 8392 Section 7 - Validate Tampered CWT Should Fail") {
        auto token = createTestToken();
        Cwt cwt(ALG_ES256, token);
        
        auto keyPair = Es256Algorithm::generateKeyPair();
        Es256Algorithm es256Alg(keyPair.first, keyPair.second);
        
        // Create valid CWT
        std::string signedCwt = cwt.createCwt(CwtMode::Signed, es256Alg);
        
        // Tamper with the CWT (change one character)

        std::string tamperedCwt = signedCwt;
        if (!tamperedCwt.empty()) {
            size_t pos = std::min(size_t(10), tamperedCwt.size() - 1);
            tamperedCwt[pos] = (tamperedCwt[pos] == 'A') ? 'B' : 'A';
        }
        
        // Validation should fail
        Es256Algorithm verificationAlg(keyPair.second);
        CHECK_THROWS_AS(Cwt::validateCwt(tamperedCwt, verificationAlg), CryptoError);
    }

    TEST_CASE("RFC 8392 Section 7 - Base64url Encoding Compliance") {
        auto token = createTestToken();
        Cwt cwt(ALG_HMAC256_256, token);
        
        auto hmacKey = HmacSha256Algorithm::generateKey();
        HmacSha256Algorithm hmacAlg(hmacKey);
        
        std::string encodedCwt = cwt.createCwt(CwtMode::MACed, hmacAlg);
        
        // RFC 4648 Section 5 compliance checks
        CHECK_FALSE(encodedCwt.empty());
        
        // Should not contain standard base64 characters
        CHECK(encodedCwt.find('+') == std::string::npos);
        CHECK(encodedCwt.find('/') == std::string::npos);
        
        // Should not have padding
        CHECK(encodedCwt.find('=') == std::string::npos);
        
        // Should only contain base64url characters
        for (char c : encodedCwt) {
            CHECK(((c >= 'A' && c <= 'Z') || 
                   (c >= 'a' && c <= 'z') || 
                   (c >= '0' && c <= '9') || 
                   c == '-' || c == '_'));
        }
        
        // Should be decodable
        REQUIRE_NOTHROW({
            auto decoded = base64UrlDecode(encodedCwt);
            CHECK_FALSE(decoded.empty());
        });
    }

    TEST_CASE("RFC 8392 Section 7 - Invalid Base64url Input Should Fail") {
        Es256Algorithm es256Alg(Es256Algorithm::generateKeyPair().second); // Public key only
        
        // Test various invalid base64url strings
        std::vector<std::string> invalidInputs = {
            "",                           // Empty string
            "invalid+base64/chars=",     // Standard base64 chars
            "invalid characters!",        // Invalid characters
            "ABC",                       // Too short to be valid CBOR
            "###invalid###"              // Invalid characters
        };
        
        for (const auto& invalid : invalidInputs) {
            INFO("Testing invalid input: " << invalid);
            CHECK_THROWS(Cwt::validateCwt(invalid, es256Alg));
        }
    }

    TEST_CASE("RFC 8392 Section 7 - Large Token Support") {
        // Create a token with large amounts of data
        std::vector<std::string> largeAudience;
        for (int i = 0; i < 50; ++i) {
            largeAudience.push_back("audience" + std::to_string(i) + ".example.com");
        }
        
        auto largeToken = CatToken()
            .withIssuer("https://large-token-issuer.example.com/with/very/long/path")
            .withAudience(largeAudience)
            .withCwtId("very-long-cwt-id-with-lots-of-characters-to-test-large-data-handling")
            .withVersion("1.2.3-beta.4+build.567890")
            .withUsageLimit(999999)
            .withReplayProtection("very-long-nonce-with-lots-of-entropy-and-random-data-abcdef123456789");
        
        Cwt largeCwt(ALG_ES256, largeToken);
        largeCwt.withKeyId("large-test-key-identifier");
        
        auto keyPair = Es256Algorithm::generateKeyPair();
        Es256Algorithm es256Alg(keyPair.first, keyPair.second);
        
        REQUIRE_NOTHROW({
            std::string largeCwtString = largeCwt.createCwt(CwtMode::Signed, es256Alg);
            
            INFO("Large CWT size: " << largeCwtString.size() << " characters");
            CHECK_FALSE(largeCwtString.empty());
            CHECK(largeCwtString.size() > 1000);
            
            // Validate round trip
            Es256Algorithm verifyAlg(keyPair.second);
            Cwt validated = Cwt::validateCwt(largeCwtString, verifyAlg);
            CHECK(validated.payload.core.iss == largeToken.core.iss);
            CHECK(validated.payload.core.aud.value().size() == 50);
        });
    }

    TEST_CASE("RFC 8392 Section 7 - Algorithm Mismatch Should Fail") {
        auto token = createTestToken();
        
        // Create CWT with ES256
        Cwt es256Cwt(ALG_ES256, token);
        auto es256KeyPair = Es256Algorithm::generateKeyPair();
        Es256Algorithm es256Alg(es256KeyPair.first, es256KeyPair.second);
        std::string es256Token = es256Cwt.createCwt(CwtMode::Signed, es256Alg);
        
        // Try to validate with HMAC algorithm - should fail
        auto hmacKey = HmacSha256Algorithm::generateKey();
        HmacSha256Algorithm hmacAlg(hmacKey);
        
        CHECK_THROWS(Cwt::validateCwt(es256Token, hmacAlg));
    }

    TEST_CASE("RFC 8392 Section 7 - Create Encrypted CWT with AES-128-GCM") {
        auto token = createTestToken();
        Cwt cwt(ALG_A128GCM, token);
        cwt.withKeyId("test-aes128-key");
        
        // Generate AES-128 key
        auto aesKey = AesGcmAlgorithm::generateSecureKey(crypto_constants::AES128_KEY_SIZE);
        AesGcmAlgorithm aes128Alg(aesKey, ALG_A128GCM);
        
        // Create encrypted CWT according to RFC 8392 Section 7
        REQUIRE_NOTHROW({
            std::string encryptedCwt = cwt.createCwt(CwtMode::Encrypted, aes128Alg);

            // Verify the result is base64url encoded
            checkBase64UrlEncoding(encryptedCwt);

            INFO("Generated AES-128-GCM CWT length: " << encryptedCwt.size());
        });
    }

    TEST_CASE("RFC 8392 Section 7 - Create Encrypted CWT with AES-256-GCM") {
        auto token = createTestToken();
        Cwt cwt(ALG_A256GCM, token);
        cwt.withKeyId("test-aes256-key");
        
        // Generate AES-256 key
        auto aesKey = AesGcmAlgorithm::generateSecureKey(crypto_constants::AES256_KEY_SIZE);
        AesGcmAlgorithm aes256Alg(aesKey, ALG_A256GCM);
        
        REQUIRE_NOTHROW({
            std::string encryptedCwt = cwt.createCwt(CwtMode::Encrypted, aes256Alg);

            checkBase64UrlEncoding(encryptedCwt);

            INFO("Generated AES-256-GCM CWT length: " << encryptedCwt.size());
        });
    }

    TEST_CASE("RFC 8392 Section 7 - Create Encrypted CWT with ChaCha20-Poly1305") {
        auto token = createTestToken();
        Cwt cwt(ALG_ChaCha20_Poly1305, token);
        cwt.withKeyId("test-chacha20-key");
        
        // Generate ChaCha20 key
        auto chachaKey = ChaCha20Poly1305Algorithm::generateSecureKey();
        ChaCha20Poly1305Algorithm chachaAlg(chachaKey);
        
        REQUIRE_NOTHROW({
            std::string encryptedCwt = cwt.createCwt(CwtMode::Encrypted, chachaAlg);
            
            checkBase64UrlEncoding(encryptedCwt);
            
            INFO("Generated ChaCha20-Poly1305 CWT length: " << encryptedCwt.size());
        });
    }

    TEST_CASE("RFC 8392 Section 7 - Full Round Trip: Create and Validate Encrypted CWT (AES-GCM)") {
        auto originalToken = createTestToken();
        Cwt originalCwt(ALG_A256GCM, originalToken);
        originalCwt.withKeyId("aes-roundtrip-test");
        
        // Generate shared AES key
        auto sharedKey = AesGcmAlgorithm::generateSecureKey(crypto_constants::AES256_KEY_SIZE);
        AesGcmAlgorithm aesAlg(sharedKey, ALG_A256GCM);
        
        // Step 1: Create encrypted CWT
        std::string encryptedCwt = originalCwt.createCwt(CwtMode::Encrypted, aesAlg);
        
        // Step 2: Validate the CWT
        REQUIRE_NOTHROW({
            Cwt validatedCwt = Cwt::validateCwt(encryptedCwt, aesAlg);
            
            // Verify payload integrity
            CHECK(validatedCwt.payload.core.iss == originalToken.core.iss);
            CHECK(validatedCwt.payload.core.aud == originalToken.core.aud);
            CHECK(validatedCwt.payload.core.exp == originalToken.core.exp);
            CHECK(validatedCwt.payload.core.nbf == originalToken.core.nbf);
            CHECK(validatedCwt.payload.core.cti == originalToken.core.cti);
            CHECK(validatedCwt.payload.cat.catv == originalToken.cat.catv);
            CHECK(validatedCwt.payload.cat.catu == originalToken.cat.catu);
            CHECK(validatedCwt.payload.cat.catreplay == originalToken.cat.catreplay);
            CHECK(validatedCwt.payload.cat.catpor == originalToken.cat.catpor);
            CHECK(validatedCwt.payload.cat.geohash == originalToken.cat.geohash);
            
            INFO("AES-GCM encrypted round trip validation successful");
        });
    }

    TEST_CASE("RFC 8392 Section 7 - Full Round Trip: Create and Validate Encrypted CWT (ChaCha20)") {
        auto originalToken = createTestToken();
        Cwt originalCwt(ALG_ChaCha20_Poly1305, originalToken);
        originalCwt.withKeyId("chacha-roundtrip-test");
        
        // Generate shared ChaCha20 key
        auto sharedKey = ChaCha20Poly1305Algorithm::generateSecureKey();
        ChaCha20Poly1305Algorithm chachaAlg(sharedKey);
        
        // Step 1: Create encrypted CWT
        std::string encryptedCwt = originalCwt.createCwt(CwtMode::Encrypted, chachaAlg);
        
        // Step 2: Validate the CWT
        REQUIRE_NOTHROW({
            Cwt validatedCwt = Cwt::validateCwt(encryptedCwt, chachaAlg);
            
            // Verify payload integrity
            CHECK(validatedCwt.payload.core.iss == originalToken.core.iss);
            CHECK(validatedCwt.payload.core.aud == originalToken.core.aud);
            CHECK(validatedCwt.payload.cat.catv == originalToken.cat.catv);
            
            INFO("ChaCha20-Poly1305 encrypted round trip validation successful");
        });
    }

    TEST_CASE("RFC 8392 Section 7 - Validate Encrypted CWT with Wrong Key Should Fail") {
        auto token = createTestToken();
        Cwt cwt(ALG_A128GCM, token);
        
        // Generate two different keys
        auto correctKey = AesGcmAlgorithm::generateSecureKey(crypto_constants::AES128_KEY_SIZE);
        auto wrongKey = AesGcmAlgorithm::generateSecureKey(crypto_constants::AES128_KEY_SIZE);
        
        AesGcmAlgorithm correctAlg(correctKey, ALG_A128GCM);
        AesGcmAlgorithm wrongAlg(wrongKey, ALG_A128GCM);
        
        // Create CWT with correct key
        std::string encryptedCwt = cwt.createCwt(CwtMode::Encrypted, correctAlg);
        
        // Try to validate with wrong key - should fail
        CHECK_THROWS_AS(Cwt::validateCwt(encryptedCwt, wrongAlg), CryptoError);
    }

    TEST_CASE("RFC 8392 Section 7 - Validate Tampered Encrypted CWT Should Fail") {
        auto token = createTestToken();
        Cwt cwt(ALG_A256GCM, token);
        
        auto aesKey = AesGcmAlgorithm::generateSecureKey(crypto_constants::AES256_KEY_SIZE);
        AesGcmAlgorithm aesAlg(aesKey, ALG_A256GCM);
        
        // Create valid encrypted CWT
        std::string encryptedCwt = cwt.createCwt(CwtMode::Encrypted, aesAlg);
        
        // First verify the original CWT validates correctly
        REQUIRE_NOTHROW(Cwt::validateCwt(encryptedCwt, aesAlg));
        
        // Decode the CWT to tamper with the actual encrypted data
        auto coseBytes = base64UrlDecode(encryptedCwt);
        
        // Tamper with the encrypted data (flip bits in authentication tag area)
        // This should cause authentication tag verification to fail
        if (coseBytes.size() > 50) {
            coseBytes[coseBytes.size() - 5] ^= 0xFF;  // Tamper near the end (likely auth tag)
            coseBytes[coseBytes.size() - 15] ^= 0x01; // Also tamper in ciphertext area
        }
        
        // Re-encode the tampered data
        std::string tamperedCwt = base64UrlEncode(coseBytes);
        
        // Validation should fail due to authentication tag mismatch
        CHECK_THROWS_AS(Cwt::validateCwt(tamperedCwt, aesAlg), CryptoError);
    }

    TEST_CASE("RFC 8392 Section 7 - Encryption with Non-Encryption Algorithm Should Fail") {
        auto token = createTestToken();
        Cwt cwt(ALG_ES256, token);
        
        auto keyPair = Es256Algorithm::generateKeyPair();
        Es256Algorithm es256Alg(keyPair.first, keyPair.second);
        
        // Encryption mode should throw for signature-only algorithms
        CHECK_THROWS_AS(cwt.createCwt(CwtMode::Encrypted, es256Alg), CryptoError);
    }

    TEST_CASE("RFC 8392 Section 7 - AES-GCM Key Generation and Validation") {
        // Test different AES key sizes
        std::vector<std::pair<size_t, int64_t>> key_configs = {
            {crypto_constants::AES128_KEY_SIZE, ALG_A128GCM},
            {crypto_constants::AES192_KEY_SIZE, ALG_A192GCM},
            {crypto_constants::AES256_KEY_SIZE, ALG_A256GCM}
        };
        
        for (const auto& config : key_configs) {
            size_t keySize = config.first;
            int64_t algId = config.second;
            
            REQUIRE_NOTHROW({
                auto key = AesGcmAlgorithm::generateSecureKey(keySize);
                CHECK(key.size() == keySize);
                
                AesGcmAlgorithm alg(key, algId);
                CHECK(alg.algorithmId() == algId);
                CHECK(alg.supportsEncryption() == true);
                
                // Test IV generation
                auto iv1 = AesGcmAlgorithm::generateIV();
                auto iv2 = AesGcmAlgorithm::generateIV();
                CHECK(iv1.size() == crypto_constants::GCM_IV_SIZE);
                CHECK(iv2.size() == crypto_constants::GCM_IV_SIZE);
                CHECK(iv1 != iv2); // Should be different (very high probability)
            });
        }
    }

    TEST_CASE("RFC 8392 Section 7 - ChaCha20-Poly1305 Key Generation and Validation") {
        REQUIRE_NOTHROW({
            auto key = ChaCha20Poly1305Algorithm::generateSecureKey();
            CHECK(key.size() == crypto_constants::ChaCha20_KEY_SIZE);
            
            ChaCha20Poly1305Algorithm alg(key);
            CHECK(alg.algorithmId() == ALG_ChaCha20_Poly1305);
            CHECK(alg.supportsEncryption() == true);
            
            // Test nonce generation
            auto nonce1 = ChaCha20Poly1305Algorithm::generateNonce();
            auto nonce2 = ChaCha20Poly1305Algorithm::generateNonce();
            CHECK(nonce1.size() == crypto_constants::ChaCha20_NONCE_SIZE);
            CHECK(nonce2.size() == crypto_constants::ChaCha20_NONCE_SIZE);
            CHECK(nonce1 != nonce2); // Should be different (very high probability)
        });
    }

    TEST_CASE("RFC 8392 Section 7 - Direct Encryption/Decryption Test") {
        std::string testData = "Hello, encrypted world!";
        std::vector<uint8_t> data(testData.begin(), testData.end());
        
        // Test AES-GCM
        {
            auto key = AesGcmAlgorithm::generateSecureKey(crypto_constants::AES256_KEY_SIZE);
            AesGcmAlgorithm aesAlg(key, ALG_A256GCM);
            
            auto iv = AesGcmAlgorithm::generateIV();
            auto encrypted = aesAlg.encrypt(data, iv);
            auto decrypted = aesAlg.decrypt(encrypted, iv);
            
            CHECK(encrypted != data); // Should be different after encryption
            CHECK(decrypted == data); // Should match original after round trip
        }
        
        // Test ChaCha20-Poly1305
        {
            auto key = ChaCha20Poly1305Algorithm::generateSecureKey();
            ChaCha20Poly1305Algorithm chachaAlg(key);
            
            auto nonce = ChaCha20Poly1305Algorithm::generateNonce();
            auto encrypted = chachaAlg.encrypt(data, nonce);
            auto decrypted = chachaAlg.decrypt(encrypted, nonce);
            
            CHECK(encrypted != data); // Should be different after encryption
            CHECK(decrypted == data); // Should match original after round trip
        }
    }
}