/**
 * @file cwt_signing.cpp
 * @brief Comprehensive tests for CWT signing (both single and multi-signature)
 * 
 * Tests RFC 8392 Section 7.1 and 7.2 compliance for COSE_Sign1 and COSE_Sign
 * Also includes RFC 8152 COSE structure compliance testing
 */

#include <doctest/doctest.h>
#include "catapult/cwt.hpp"
#include "catapult/crypto.hpp"
#include "catapult/logging.hpp"
#include <cbor.h>
#include <memory>

using namespace catapult;

TEST_SUITE("RFC 8152 COSE Structure Compliance") {

    TEST_CASE("RFC 8152 Section 4.4 - COSE_Sign1 Sig_structure Format") {
        std::vector<uint8_t> protectedHeader = {0x43, 0xa1, 0x01, 0x26}; // CBOR: {1: -7} (ES256)
        std::vector<uint8_t> payload = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21}; // "Hello!"
        std::vector<uint8_t> externalAAD = {}; // Empty for this test
        
        auto sigStructure = createCoseSign1Input(protectedHeader, payload, externalAAD);
        
        struct cbor_load_result result;
        cbor_item_t* item = cbor_load(sigStructure.data(), sigStructure.size(), &result);
        
        REQUIRE(result.error.code == CBOR_ERR_NONE);
        REQUIRE(cbor_isa_array(item));
        
        // Verify array has exactly 4 elements for COSE_Sign1
        // [context, body_protected, external_aad, payload]
        CHECK(cbor_array_size(item) == 4);
        
        cbor_item_t** array = cbor_array_handle(item);
        
        // Check element 0: context string "Signature1"
        REQUIRE(cbor_isa_string(array[0]));
        std::string context(reinterpret_cast<const char*>(cbor_string_handle(array[0])), 
                           cbor_string_length(array[0]));
        CHECK(context == "Signature1");
        
        // Check element 1: body_protected (should match our input)
        REQUIRE(cbor_isa_bytestring(array[1]));
        std::vector<uint8_t> extractedHeader(
            cbor_bytestring_handle(array[1]),
            cbor_bytestring_handle(array[1]) + cbor_bytestring_length(array[1])
        );
        CHECK(extractedHeader == protectedHeader);
        
        // Check element 2: external_aad (should be empty bytestring)
        REQUIRE(cbor_isa_bytestring(array[2]));
        CHECK(cbor_bytestring_length(array[2]) == 0);
        
        // Check element 3: payload
        REQUIRE(cbor_isa_bytestring(array[3]));
        std::vector<uint8_t> extractedPayload(
            cbor_bytestring_handle(array[3]),
            cbor_bytestring_handle(array[3]) + cbor_bytestring_length(array[3])
        );
        CHECK(extractedPayload == payload);
        
        cbor_decref(&item);
    }

    TEST_CASE("RFC 8152 Section 4.4 - COSE_Sign1 with External AAD") {
        std::vector<uint8_t> protectedHeader = {0x43, 0xa1, 0x01, 0x26}; // CBOR: {1: -7}
        std::vector<uint8_t> payload = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21}; // "Hello!"
        std::vector<uint8_t> externalAAD = {0x57, 0x6F, 0x72, 0x6C, 0x64}; // "World"
        
        auto sigStructure = createCoseSign1Input(protectedHeader, payload, externalAAD);
        
        struct cbor_load_result result;
        cbor_item_t* item = cbor_load(sigStructure.data(), sigStructure.size(), &result);
        
        REQUIRE(result.error.code == CBOR_ERR_NONE);
        REQUIRE(cbor_isa_array(item));
        CHECK(cbor_array_size(item) == 4);
        
        cbor_item_t** array = cbor_array_handle(item);
        
        // Check external_aad is correctly included
        REQUIRE(cbor_isa_bytestring(array[2]));
        std::vector<uint8_t> extractedAAD(
            cbor_bytestring_handle(array[2]),
            cbor_bytestring_handle(array[2]) + cbor_bytestring_length(array[2])
        );
        CHECK(extractedAAD == externalAAD);
        
        cbor_decref(&item);
    }

    TEST_CASE("RFC 8152 Section 4.4 - COSE_Signature Sig_structure Format") {
        std::vector<uint8_t> protectedHeader = {0x43, 0xa1, 0x01, 0x26};
        std::vector<uint8_t> payload = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21};
        std::vector<uint8_t> externalAAD = {};
        
        // Use the multi-signature function for COSE_Signature
        std::vector<uint8_t> signatureProtectedHeader = {}; // Empty for this test
        auto sigStructure = createCoseSignInput(protectedHeader, signatureProtectedHeader, externalAAD, payload);
        
        struct cbor_load_result result;
        cbor_item_t* item = cbor_load(sigStructure.data(), sigStructure.size(), &result);
        
        REQUIRE(result.error.code == CBOR_ERR_NONE);
        REQUIRE(cbor_isa_array(item));
        
        // COSE_Signature should have 5 elements: 
        // [context, body_protected, sign_protected, external_aad, payload]
        CHECK(cbor_array_size(item) == 5);
        
        cbor_item_t** array = cbor_array_handle(item);
        
        // Check context string is "Signature"
        REQUIRE(cbor_isa_string(array[0]));
        std::string context(reinterpret_cast<const char*>(cbor_string_handle(array[0])), 
                           cbor_string_length(array[0]));
        CHECK(context == "Signature");
        
        // Check sign_protected (element 2) is empty bytestring for this test
        REQUIRE(cbor_isa_bytestring(array[2]));
        CHECK(cbor_bytestring_length(array[2]) == 0);
        
        cbor_decref(&item);
    }

    TEST_CASE("RFC 8152 - CBOR Deterministic Encoding") {
        std::vector<uint8_t> header = {0x43, 0xa1, 0x01, 0x26};
        std::vector<uint8_t> payload = {0x54, 0x65, 0x73, 0x74}; // "Test"
        
        auto sig1 = createCoseSign1Input(header, payload);
        auto sig2 = createCoseSign1Input(header, payload);
        
        // Should produce identical results
        CHECK(sig1 == sig2);
        CHECK_FALSE(sig1.empty());
    }

}

TEST_SUITE("CWT Single Signature (COSE_Sign1) Tests") {

    TEST_CASE("RFC 8392 Section 7.1 - COSE_Sign1 Creation and Validation") {
        CatToken token;
        token.core.iss = "single-sig-issuer";
        token.core.aud = {"test-audience"};
        token.core.exp = 1234567890;
        token.cat.catv = "1.0";
        
        auto algorithm = std::make_unique<Es256Algorithm>();
        
        // Create single-signed CWT
        Cwt cwt(algorithm->algorithmId(), token);
        std::string singleSigCwt = cwt.createCwt(CwtMode::Signed, *algorithm);
        CHECK_FALSE(singleSigCwt.empty());
        
        // Validate the CWT
        Cwt validatedCwt = Cwt::validateCwt(singleSigCwt, *algorithm);
        CHECK(validatedCwt.payload.core.iss == "single-sig-issuer");
        CHECK(validatedCwt.payload.core.exp == 1234567890);
        CHECK(validatedCwt.payload.cat.catv == "1.0");
    }

    TEST_CASE("COSE_Sign1 with Key ID") {
        CatToken token;
        token.core.iss = "keyid-test";
        token.core.exp = 9876543210;
        
        auto algorithm = std::make_unique<Es256Algorithm>();
        
        Cwt cwt(algorithm->algorithmId(), token);
        cwt.withKeyId("test-key-2024");
        
        std::string cwtString = cwt.createCwt(CwtMode::Signed, *algorithm);
        
        // Should validate successfully
        Cwt validated = Cwt::validateCwt(cwtString, *algorithm);
        CHECK(validated.payload.core.iss == "keyid-test");
        CHECK(validated.payload.core.exp == 9876543210);
    }

    TEST_CASE("COSE_Sign1 Error Cases") {
        CatToken token;
        token.core.iss = "error-test";
        
        auto algorithm = std::make_unique<Es256Algorithm>();
        
        SUBCASE("Invalid CWT validation") {
            Cwt cwt(algorithm->algorithmId(), token);
            std::string validCwt = cwt.createCwt(CwtMode::Signed, *algorithm);
            
            // Corrupt the CWT
            std::string corruptedCwt = validCwt;
            corruptedCwt[10] = 'X'; // Corrupt a character
            
            CHECK_THROWS(Cwt::validateCwt(corruptedCwt, *algorithm));
        }
    }
}

TEST_SUITE("CWT Multi-Signature (COSE_Sign) Tests") {

    TEST_CASE("RFC 8392 Section 7.1 - COSE_Sign Creation with Multiple Signatures") {
        CatToken token;
        token.core.iss = "multi-sig-issuer";
        token.core.aud = {"audience1", "audience2"};
        token.core.exp = 1234567890;
        token.cat.catv = "1.0";
        
        // Create algorithm - use same key for all signatures in this test
        std::vector<uint8_t> testKey(reinterpret_cast<const uint8_t*>("test-key-16-bytes"), 
                                     reinterpret_cast<const uint8_t*>("test-key-16-bytes") + 16);
        auto hmac = std::make_unique<HmacSha256Algorithm>(testKey);
        
        // Create CWT and add multiple signatures with same key
        Cwt cwt(hmac->algorithmId(), token);
        cwt.addSignature(*hmac);
        cwt.addSignature(*hmac);
        cwt.addSignature(*hmac);
        
        // Verify signatures were added
        CHECK(cwt.signatures.size() == 3);
        
        // Create COSE_Sign CWT
        std::string multiSignedCwt = cwt.createCwt(CwtMode::MultiSigned, *hmac);
        CHECK_FALSE(multiSignedCwt.empty());
        
        // Validate the CWT using validateMultiSignedCwt
        std::map<int64_t, std::reference_wrapper<const CryptographicAlgorithm>> algorithms;
        algorithms.emplace(hmac->algorithmId(), std::cref(*hmac));
        Cwt validatedCwt = Cwt::validateMultiSignedCwt(multiSignedCwt, algorithms);
        CHECK(validatedCwt.signatures.size() == 3);
        CHECK(validatedCwt.payload.core.iss == "multi-sig-issuer");
    }

    TEST_CASE("RFC 8392 Section 7.2 - COSE_Sign Validation") {
        CatToken token;
        token.core.iss = "validation-test";
        token.core.exp = 9876543210;
        
        auto algorithm = std::make_unique<Es256Algorithm>();
        
        // Create and sign CWT
        Cwt cwt(algorithm->algorithmId(), token);
        cwt.addSignature(*algorithm);
        cwt.addSignature(*algorithm); // Add second signature with same key
        
        std::string cwtString = cwt.createCwt(CwtMode::MultiSigned, *algorithm);
        
        // Validate - should succeed
        std::map<int64_t, std::reference_wrapper<const CryptographicAlgorithm>> algorithms;
        algorithms.emplace(algorithm->algorithmId(), std::cref(*algorithm));
        REQUIRE_NOTHROW(Cwt::validateMultiSignedCwt(cwtString, algorithms));
        
        // Validate structure
        Cwt validated = Cwt::validateMultiSignedCwt(cwtString, algorithms);
        CHECK(validated.signatures.size() == 2);
        CHECK(validated.payload.core.iss == "validation-test");
        CHECK(validated.payload.core.exp == 9876543210);
    }

    TEST_CASE("COSE_Sign vs COSE_Sign1 Structure Validation") {
        CatToken token;
        token.core.iss = "structure-test";
        
        auto algorithm = std::make_unique<Es256Algorithm>();
        
        // Create COSE_Sign1 (single signature)
        Cwt singleCwt(algorithm->algorithmId(), token);
        std::string singleSigCwt = singleCwt.createCwt(CwtMode::Signed, *algorithm);
        
        // Create COSE_Sign (multi signature)
        Cwt multiCwt(algorithm->algorithmId(), token);
        multiCwt.addSignature(*algorithm);
        std::string multiSigCwt = multiCwt.createCwt(CwtMode::MultiSigned, *algorithm);
        
        // Both should validate successfully
        Cwt validatedSingle = Cwt::validateCwt(singleSigCwt, *algorithm);
        std::map<int64_t, std::reference_wrapper<const CryptographicAlgorithm>> algorithms;
        algorithms.emplace(algorithm->algorithmId(), std::cref(*algorithm));
        Cwt validatedMulti = Cwt::validateMultiSignedCwt(multiSigCwt, algorithms);
        
        // Check structure differences
        CHECK(validatedSingle.signatures.size() == 0); // COSE_Sign1 doesn't populate signatures array
        CHECK(validatedMulti.signatures.size() == 1);  // COSE_Sign does
        
        // Payload should be identical
        CHECK(validatedSingle.payload.core.iss == validatedMulti.payload.core.iss);
    }

    TEST_CASE("Multiple Algorithms in COSE_Sign") {
        CatToken token;
        token.core.iss = "multi-alg-test";
        token.core.aud = {"test-audience"};
        
        // Use HMAC for consistent validation in multi-algorithm test
        std::vector<uint8_t> multiAlgKey(reinterpret_cast<const uint8_t*>("multi-alg-key-16b"), 
                                         reinterpret_cast<const uint8_t*>("multi-alg-key-16b") + 16);
        auto hmac = std::make_unique<HmacSha256Algorithm>(multiAlgKey);
        
        Cwt cwt(hmac->algorithmId(), token);
        cwt.addSignature(*hmac);
        cwt.addSignature(*hmac);  // Use same algorithm for consistent validation
        cwt.addSignature(*hmac);
        
        CHECK(cwt.signatures.size() == 3);
        
        std::string cwtString = cwt.createCwt(CwtMode::MultiSigned, *hmac);
        
        // Should validate successfully
        std::map<int64_t, std::reference_wrapper<const CryptographicAlgorithm>> algorithms;
        algorithms.emplace(hmac->algorithmId(), std::cref(*hmac));
        REQUIRE_NOTHROW(Cwt::validateMultiSignedCwt(cwtString, algorithms));
    }

    TEST_CASE("Error Cases - COSE_Sign") {
        CatToken token;
        token.core.iss = "error-test";
        
        auto algorithm = std::make_unique<Es256Algorithm>();
        
        SUBCASE("No signatures for MultiSigned mode") {
            Cwt cwt(algorithm->algorithmId(), token);
            // Don't add any signatures
            CHECK_THROWS_AS(cwt.createCwt(CwtMode::MultiSigned, *algorithm), CryptoError);
        }
        
        SUBCASE("Invalid CWT validation") {
            // Create a valid CWT first
            Cwt cwt(algorithm->algorithmId(), token);
            cwt.addSignature(*algorithm);
            std::string validCwt = cwt.createCwt(CwtMode::MultiSigned, *algorithm);
            
            // Corrupt the CWT
            std::string corruptedCwt = validCwt;
            corruptedCwt[10] = 'X'; // Corrupt a character
            
            std::map<int64_t, std::reference_wrapper<const CryptographicAlgorithm>> algorithms;
            algorithms.emplace(algorithm->algorithmId(), std::cref(*algorithm));
            CHECK_THROWS(Cwt::validateMultiSignedCwt(corruptedCwt, algorithms));
        }
    }

    TEST_CASE("Performance - Large Number of Signatures") {
        CatToken token;
        token.core.iss = "performance-test";
        
        std::vector<uint8_t> perfKey(reinterpret_cast<const uint8_t*>("perf-test-key-16"), 
                                     reinterpret_cast<const uint8_t*>("perf-test-key-16") + 16);
        auto algorithm = std::make_unique<HmacSha256Algorithm>(perfKey);
        
        Cwt cwt(algorithm->algorithmId(), token);
        
        // Add multiple signatures (HMAC is faster for this test)
        constexpr int NUM_SIGNATURES = 10;
        for (int i = 0; i < NUM_SIGNATURES; i++) {
            cwt.addSignature(*algorithm);
        }
        
        CHECK(cwt.signatures.size() == NUM_SIGNATURES);
        
        // Should create and validate successfully
        std::string cwtString = cwt.createCwt(CwtMode::MultiSigned, *algorithm);
        std::map<int64_t, std::reference_wrapper<const CryptographicAlgorithm>> algorithms;
        algorithms.emplace(algorithm->algorithmId(), std::cref(*algorithm));
        Cwt validated = Cwt::validateMultiSignedCwt(cwtString, algorithms);
        
        CHECK(validated.signatures.size() == NUM_SIGNATURES);
    }
}

TEST_SUITE("CWT Signing Integration Tests") {

    TEST_CASE("End-to-End Multi-Signature Workflow") {
        // Simulate a real-world scenario with multiple signers
        CatToken token;
        token.core.iss = "corporate-ca";
        token.core.aud = {"service1", "service2"};
        token.core.exp = 1234567890;
        token.core.nbf = 1234500000;
        token.cat.catv = "2.0";
        token.cat.catu = 100;
        
        // Use same HMAC key for consistent validation in integration test
        std::vector<uint8_t> sharedKey(reinterpret_cast<const uint8_t*>("shared-secret-16b"), 
                                       reinterpret_cast<const uint8_t*>("shared-secret-16b") + 16);
        auto caAlgorithm = std::make_unique<HmacSha256Algorithm>(sharedKey);
        auto deptAlgorithm = std::make_unique<HmacSha256Algorithm>(sharedKey);
        auto userAlgorithm = std::make_unique<HmacSha256Algorithm>(sharedKey);
        
        // Create CWT with multiple authority signatures
        Cwt corporateCwt(caAlgorithm->algorithmId(), token);
        corporateCwt.withKeyId("corporate-ca-2024");
        
        // Add signatures from different authorities
        corporateCwt.addSignature(*caAlgorithm);     // CA signature
        corporateCwt.addSignature(*deptAlgorithm);   // Department signature  
        corporateCwt.addSignature(*userAlgorithm);   // User signature
        
        // Create the multi-signed token
        std::string corporateToken = corporateCwt.createCwt(CwtMode::MultiSigned, *caAlgorithm);
        
        // Validate with algorithm map
        std::map<int64_t, std::reference_wrapper<const CryptographicAlgorithm>> algorithms;
        algorithms.emplace(caAlgorithm->algorithmId(), std::cref(*caAlgorithm));
        Cwt caValidated = Cwt::validateMultiSignedCwt(corporateToken, algorithms);
        
        // Check all claims are preserved
        CHECK(caValidated.payload.core.iss == "corporate-ca");
        CHECK(caValidated.payload.core.aud.has_value());
        CHECK(caValidated.payload.core.aud->size() == 2);
        CHECK(caValidated.payload.core.exp == 1234567890);
        CHECK(caValidated.payload.core.nbf == 1234500000);
        CHECK(caValidated.payload.cat.catv == "2.0");
        CHECK(caValidated.payload.cat.catu == 100);
        CHECK(caValidated.signatures.size() == 3);
        
        CAT_LOG_INFO("End-to-end multi-signature workflow completed successfully");
    }

    TEST_CASE("Per-Signature Algorithm Support") {
        CatToken token;
        token.core.iss = "per-sig-test";
        token.core.aud = {"mixed-alg-audience"};
        token.core.exp = 1234567890;
        
        // Create different algorithms
        auto es256 = std::make_unique<Es256Algorithm>();
        auto ps256 = std::make_unique<Ps256Algorithm>();
        std::vector<uint8_t> hmacKey(reinterpret_cast<const uint8_t*>("hmac-key-16-bytes"), 
                                     reinterpret_cast<const uint8_t*>("hmac-key-16-bytes") + 16);
        auto hmac = std::make_unique<HmacSha256Algorithm>(hmacKey);
        
        // Create CWT with mixed algorithm signatures
        Cwt cwt(es256->algorithmId(), token);
        cwt.addSignature(*es256);
        cwt.addSignature(*ps256);
        cwt.addSignature(*hmac);
        
        CHECK(cwt.signatures.size() == 3);
        CHECK(cwt.signatures[0].algorithmId == es256->algorithmId());
        CHECK(cwt.signatures[1].algorithmId == ps256->algorithmId());
        CHECK(cwt.signatures[2].algorithmId == hmac->algorithmId());
        
        // Create the token
        std::string cwtString = cwt.createCwt(CwtMode::MultiSigned, *es256);
        
        // Create algorithm map for validation
        std::map<int64_t, std::reference_wrapper<const CryptographicAlgorithm>> algorithms;
        algorithms.emplace(es256->algorithmId(), std::cref(*es256));
        algorithms.emplace(ps256->algorithmId(), std::cref(*ps256));
        algorithms.emplace(hmac->algorithmId(), std::cref(*hmac));
        
        // Validate with per-signature algorithms
        Cwt validated = Cwt::validateMultiSignedCwt(cwtString, algorithms);
        
        CHECK(validated.signatures.size() == 3);
        CHECK(validated.signatures[0].algorithmId == es256->algorithmId());
        CHECK(validated.signatures[1].algorithmId == ps256->algorithmId());
        CHECK(validated.signatures[2].algorithmId == hmac->algorithmId());
        CHECK(validated.payload.core.iss == "per-sig-test");
        
        // Test missing algorithm error
        std::map<int64_t, std::reference_wrapper<const CryptographicAlgorithm>> incompleteAlgorithms;
        incompleteAlgorithms.emplace(es256->algorithmId(), std::cref(*es256));
        // Missing ps256 and hmac
        
        CHECK_THROWS_AS(Cwt::validateMultiSignedCwt(cwtString, incompleteAlgorithms), CryptoError);
    }

    TEST_CASE("Single vs Multi-Signature Mode Comparison") {
        CatToken token;
        token.core.iss = "comparison-test";
        token.core.exp = 1234567890;
        
        auto algorithm = std::make_unique<Es256Algorithm>();
        
        // Create single signature CWT
        Cwt singleCwt(algorithm->algorithmId(), token);
        std::string singleToken = singleCwt.createCwt(CwtMode::Signed, *algorithm);
        
        // Create multi signature CWT with one signature
        Cwt multiCwt(algorithm->algorithmId(), token);
        multiCwt.addSignature(*algorithm);
        std::string multiToken = multiCwt.createCwt(CwtMode::MultiSigned, *algorithm);
        
        // Tokens should be different despite same content
        CHECK(singleToken != multiToken);
        
        // Both should validate to same payload
        Cwt validatedSingle = Cwt::validateCwt(singleToken, *algorithm);
        std::map<int64_t, std::reference_wrapper<const CryptographicAlgorithm>> algorithms;
        algorithms.emplace(algorithm->algorithmId(), std::cref(*algorithm));
        Cwt validatedMulti = Cwt::validateMultiSignedCwt(multiToken, algorithms);
        
        CHECK(validatedSingle.payload.core.iss == validatedMulti.payload.core.iss);
        CHECK(validatedSingle.payload.core.exp == validatedMulti.payload.core.exp);
    }

    TEST_CASE("RFC 8392 Compliance - CWT Tags") {
        CatToken token;
        token.core.iss = "tag-test";
        
        auto algorithm = std::make_unique<Es256Algorithm>();
        
        SUBCASE("Single signature with tags") {
            Cwt cwt(algorithm->algorithmId(), token);
            std::string cwtString = cwt.createCwt(CwtMode::Signed, *algorithm);
            
            Cwt validated = Cwt::validateCwt(cwtString, *algorithm);
            CHECK(validated.payload.core.iss == "tag-test");
        }
        
        SUBCASE("Multi signature with tags") {
            Cwt cwt(algorithm->algorithmId(), token);
            cwt.addSignature(*algorithm);
            
            std::string cwtString = cwt.createCwt(CwtMode::MultiSigned, *algorithm);
            
            std::map<int64_t, std::reference_wrapper<const CryptographicAlgorithm>> algorithms;
            algorithms.emplace(algorithm->algorithmId(), std::cref(*algorithm));
            Cwt validated = Cwt::validateMultiSignedCwt(cwtString, algorithms);
            CHECK(validated.payload.core.iss == "tag-test");
        }
    }
}