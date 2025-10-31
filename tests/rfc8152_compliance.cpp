/**
 * @file rfc8152_section4_1_compliance.cpp
 * @brief RFC 8152 Section 4.1 compliance verification tests
 * 
 * Tests that our COSE implementation strictly adheres to RFC 8152 Section 4.1
 * requirements for COSE_Sign and COSE_Sign1 structures.
 */

#include <doctest/doctest.h>
#include "catapult/cwt.hpp"
#include "catapult/crypto.hpp"
#include <cbor.h>

using namespace catapult;

TEST_SUITE("RFC 8152 Section 4.1 Compliance Tests") {

    TEST_CASE("COSE_Sign Structure Compliance - Four Mandatory Fields") {
        // RFC 8152 Section 4.1: COSE_Sign must have exactly 4 fields:
        // [protected, unprotected, payload, signatures]
        
        CatToken token;
        token.core.iss = "rfc8152-test";
        
        std::vector<uint8_t> hmacKey(reinterpret_cast<const uint8_t*>("test-key-16-bytes"), 
                                     reinterpret_cast<const uint8_t*>("test-key-16-bytes") + 16);
        auto hmac = std::make_unique<HmacSha256Algorithm>(hmacKey);
        
        Cwt cwt(hmac->algorithmId(), token);
        cwt.addSignature(*hmac);
        
        std::string cwtString = cwt.createCwt(CwtMode::MultiSigned, *hmac);
        auto coseBytes = base64UrlDecode(cwtString);
        
        // Parse COSE structure
        struct cbor_load_result result;
        cbor_item_t* coseItem = cbor_load(coseBytes.data(), coseBytes.size(), &result);
        
        REQUIRE(result.error.code == CBOR_ERR_NONE);
        REQUIRE(cbor_isa_array(coseItem));
        
        // Must have exactly 4 elements
        CHECK(cbor_array_size(coseItem) == 4);
        
        cbor_item_t** array = cbor_array_handle(coseItem);
        
        // Element 0: protected headers (byte string)
        CHECK(cbor_isa_bytestring(array[0]));
        
        // Element 1: unprotected headers (map)
        CHECK(cbor_isa_map(array[1]));
        
        // Element 2: payload (byte string)  
        CHECK(cbor_isa_bytestring(array[2]));
        
        // Element 3: signatures array
        CHECK(cbor_isa_array(array[3]));
        CHECK(cbor_array_size(array[3]) >= 1); // Must have at least one signature
        
        cbor_decref(&coseItem);
    }

    TEST_CASE("COSE_Sign1 Structure Compliance - Four Mandatory Fields") {
        // RFC 8152 Section 4.1: COSE_Sign1 must have exactly 4 fields:
        // [protected, unprotected, payload, signature]
        
        CatToken token;
        token.core.iss = "rfc8152-sign1-test";
        
        std::vector<uint8_t> hmacKey(reinterpret_cast<const uint8_t*>("sign1-key-16-byte"), 
                                     reinterpret_cast<const uint8_t*>("sign1-key-16-byte") + 16);
        auto hmac = std::make_unique<HmacSha256Algorithm>(hmacKey);
        
        Cwt cwt(hmac->algorithmId(), token);
        std::string cwtString = cwt.createCwt(CwtMode::Signed, *hmac);
        auto coseBytes = base64UrlDecode(cwtString);
        
        // Parse COSE structure
        struct cbor_load_result result;
        cbor_item_t* coseItem = cbor_load(coseBytes.data(), coseBytes.size(), &result);
        
        REQUIRE(result.error.code == CBOR_ERR_NONE);
        REQUIRE(cbor_isa_array(coseItem));
        
        // Must have exactly 4 elements
        CHECK(cbor_array_size(coseItem) == 4);
        
        cbor_item_t** array = cbor_array_handle(coseItem);
        
        // Element 0: protected headers (byte string)
        CHECK(cbor_isa_bytestring(array[0]));
        
        // Element 1: unprotected headers (map)
        CHECK(cbor_isa_map(array[1]));
        
        // Element 2: payload (byte string)
        CHECK(cbor_isa_bytestring(array[2]));
        
        // Element 3: signature (byte string, not array)
        CHECK(cbor_isa_bytestring(array[3]));
        CHECK_FALSE(cbor_isa_array(array[3])); // Must not be array
        
        cbor_decref(&coseItem);
    }

    TEST_CASE("COSE_Sign Signatures Array Structure") {
        // RFC 8152 Section 4.1: Each signature in COSE_Sign must be:
        // [protected, unprotected, signature]
        
        CatToken token;
        token.core.iss = "sig-array-test";
        
        std::vector<uint8_t> hmacKey(reinterpret_cast<const uint8_t*>("sig-array-key-16b"), 
                                     reinterpret_cast<const uint8_t*>("sig-array-key-16b") + 16);
        auto hmac = std::make_unique<HmacSha256Algorithm>(hmacKey);
        
        Cwt cwt(hmac->algorithmId(), token);
        cwt.addSignature(*hmac);
        cwt.addSignature(*hmac);
        
        std::string cwtString = cwt.createCwt(CwtMode::MultiSigned, *hmac);
        auto coseBytes = base64UrlDecode(cwtString);
        
        struct cbor_load_result result;
        cbor_item_t* coseItem = cbor_load(coseBytes.data(), coseBytes.size(), &result);
        
        REQUIRE(result.error.code == CBOR_ERR_NONE);
        
        cbor_item_t** mainArray = cbor_array_handle(coseItem);
        cbor_item_t** signaturesArray = cbor_array_handle(mainArray[3]);
        size_t sigCount = cbor_array_size(mainArray[3]);
        
        CHECK(sigCount == 2);
        
        // Check each signature structure
        for (size_t i = 0; i < sigCount; i++) {
            CHECK(cbor_isa_array(signaturesArray[i]));
            CHECK(cbor_array_size(signaturesArray[i]) == 3);
            
            cbor_item_t** sigStructure = cbor_array_handle(signaturesArray[i]);
            
            // Element 0: signature protected headers (byte string)
            CHECK(cbor_isa_bytestring(sigStructure[0]));
            
            // Element 1: signature unprotected headers (map)
            CHECK(cbor_isa_map(sigStructure[1]));
            
            // Element 2: signature (byte string)
            CHECK(cbor_isa_bytestring(sigStructure[2]));
        }
        
        cbor_decref(&coseItem);
    }

    TEST_CASE("Protected Headers Must Be Byte String") {
        // RFC 8152 Section 4.1: Protected headers must be encoded as byte string
        
        CatToken token;
        token.core.iss = "protected-header-test";
        
        std::vector<uint8_t> hmacKey(reinterpret_cast<const uint8_t*>("protected-hdr-16b"), 
                                     reinterpret_cast<const uint8_t*>("protected-hdr-16b") + 16);
        auto hmac = std::make_unique<HmacSha256Algorithm>(hmacKey);
        
        Cwt cwt(hmac->algorithmId(), token);
        cwt.withKeyId("test-key-id");
        
        // Test COSE_Sign1
        std::string sign1Cwt = cwt.createCwt(CwtMode::Signed, *hmac);
        auto sign1Bytes = base64UrlDecode(sign1Cwt);
        
        struct cbor_load_result result;
        cbor_item_t* coseItem = cbor_load(sign1Bytes.data(), sign1Bytes.size(), &result);
        
        REQUIRE(result.error.code == CBOR_ERR_NONE);
        
        cbor_item_t** array = cbor_array_handle(coseItem);
        
        // Protected header must be byte string
        CHECK(cbor_isa_bytestring(array[0]));
        
        // Parse the protected header content
        auto headerBytes = std::vector<uint8_t>(
            cbor_bytestring_handle(array[0]),
            cbor_bytestring_handle(array[0]) + cbor_bytestring_length(array[0])
        );
        
        // The protected header content should be valid CBOR map
        struct cbor_load_result headerResult;
        cbor_item_t* headerMap = cbor_load(headerBytes.data(), headerBytes.size(), &headerResult);
        
        CHECK(headerResult.error.code == CBOR_ERR_NONE);
        CHECK(cbor_isa_map(headerMap));
        
        cbor_decref(&headerMap);
        cbor_decref(&coseItem);
    }

    TEST_CASE("Unprotected Headers Must Be Map") {
        // RFC 8152 Section 4.1: Unprotected headers must be a map
        
        CatToken token;
        token.core.iss = "unprotected-test";
        
        std::vector<uint8_t> hmacKey(reinterpret_cast<const uint8_t*>("unprotected-key16"), 
                                     reinterpret_cast<const uint8_t*>("unprotected-key16") + 16);
        auto hmac = std::make_unique<HmacSha256Algorithm>(hmacKey);
        
        Cwt cwt(hmac->algorithmId(), token);
        std::string cwtString = cwt.createCwt(CwtMode::Signed, *hmac);
        auto coseBytes = base64UrlDecode(cwtString);
        
        struct cbor_load_result result;
        cbor_item_t* coseItem = cbor_load(coseBytes.data(), coseBytes.size(), &result);
        
        REQUIRE(result.error.code == CBOR_ERR_NONE);
        
        cbor_item_t** array = cbor_array_handle(coseItem);
        
        // Unprotected header must be map
        CHECK(cbor_isa_map(array[1]));
        
        cbor_decref(&coseItem);
    }

    TEST_CASE("Payload Encoding Compliance") {
        // RFC 8152 Section 4.1: Payload must be wrapped in byte string or nil if detached
        
        CatToken token;
        token.core.iss = "payload-test";
        token.core.aud = {"audience1"};
        
        std::vector<uint8_t> hmacKey(reinterpret_cast<const uint8_t*>("payload-test-16b"), 
                                     reinterpret_cast<const uint8_t*>("payload-test-16b") + 16);
        auto hmac = std::make_unique<HmacSha256Algorithm>(hmacKey);
        
        Cwt cwt(hmac->algorithmId(), token);
        std::string cwtString = cwt.createCwt(CwtMode::Signed, *hmac);
        auto coseBytes = base64UrlDecode(cwtString);
        
        struct cbor_load_result result;
        cbor_item_t* coseItem = cbor_load(coseBytes.data(), coseBytes.size(), &result);
        
        REQUIRE(result.error.code == CBOR_ERR_NONE);
        
        cbor_item_t** array = cbor_array_handle(coseItem);
        
        // Payload must be byte string (we don't support detached payloads)
        CHECK(cbor_isa_bytestring(array[2]));
        CHECK(cbor_bytestring_length(array[2]) > 0); // Must not be empty
        
        cbor_decref(&coseItem);
    }

    TEST_CASE("Structure Identification Prevention") {
        // RFC 8152 Section 4.1: "signature computation includes a parameter 
        // identifying which structure is being used"
        
        CatToken token;
        token.core.iss = "structure-id-test";
        
        std::vector<uint8_t> hmacKey(reinterpret_cast<const uint8_t*>("struct-id-key-16"), 
                                     reinterpret_cast<const uint8_t*>("struct-id-key-16") + 16);
        auto hmac = std::make_unique<HmacSha256Algorithm>(hmacKey);
        
        // Create COSE_Sign1
        Cwt sign1Cwt(hmac->algorithmId(), token);
        std::string sign1Token = sign1Cwt.createCwt(CwtMode::Signed, *hmac);
        
        // Create COSE_Sign with same payload
        Cwt signCwt(hmac->algorithmId(), token);
        signCwt.addSignature(*hmac);
        std::string signToken = signCwt.createCwt(CwtMode::MultiSigned, *hmac);
        
        // Tokens should be different even with same algorithm and payload
        CHECK(sign1Token != signToken);
        
        // COSE_Sign1 validation should fail on COSE_Sign token
        CHECK_THROWS(Cwt::validateCwt(signToken, *hmac));
        
        // COSE_Sign validation should succeed on COSE_Sign token
        std::map<int64_t, std::reference_wrapper<const CryptographicAlgorithm>> algorithms;
        algorithms.emplace(hmac->algorithmId(), std::cref(*hmac));
        REQUIRE_NOTHROW(Cwt::validateMultiSignedCwt(signToken, algorithms));
    }
}