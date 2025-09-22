#include <doctest/doctest.h>
#include "catapult/cwt.hpp"
#include "catapult/crypto.hpp"
#include <cbor.h>

using namespace catapult;

auto createTestToken() {
    return CatToken()
        .withIssuer("https://example.com")
        .withAudience({"https://api.example.com"})
        .withCwtId("test-payload")
        .withVersion("1.0")
        .withUsageLimit(50)
        .withReplayProtection("test-nonce")
        .withProofOfPossession(false)
        .withGeoCoordinate(51.5074, -0.1278)
        .withGeohash("gcpvj");
        
}

TEST_CASE("CwtConstruction") {
    auto token = createTestToken();
    Cwt cwt(ALG_ES256, token);
    
    CHECK(cwt.header.alg == ALG_ES256);
    CHECK(cwt.header.typ == "CAT");
    CHECK_FALSE(cwt.header.kid.has_value());
    CHECK(cwt.payload.core.iss == token.core.iss);
    CHECK(cwt.payload.cat.catv == token.cat.catv);
}

TEST_CASE("CwtWithKeyId") {
    auto token = createTestToken();
    Cwt cwt(ALG_HMAC256_256, token);
    cwt.withKeyId("test-key-id");
    
    CHECK(cwt.header.kid == "test-key-id");
}

TEST_CASE("CwtHeaderTypes") {
    CwtHeader header1(ALG_HMAC256_256);
    CHECK(header1.alg == ALG_HMAC256_256);
    CHECK(header1.typ == "CAT");
    CHECK_FALSE(header1.kid.has_value());
    
    CwtHeader header2(ALG_ES256);
    CHECK(header2.alg == ALG_ES256);
    CHECK(header2.typ == "CAT");
}

TEST_CASE("PayloadEncoding") {
    auto token = createTestToken();
    Cwt cwt(ALG_HMAC256_256, token);
    
    REQUIRE_NOTHROW({
        auto encoded = cwt.encodePayload();
        CHECK_FALSE(encoded.empty());
    });
    
    CatToken emptyToken;
    Cwt emptyCwt(ALG_ES256, emptyToken);
    REQUIRE_NOTHROW({
        auto emptyEncoded = emptyCwt.encodePayload();
        CHECK_FALSE(emptyEncoded.empty());
    });
}

TEST_CASE("PayloadDecoding") {
    auto token = createTestToken();
    Cwt cwt(ALG_HMAC256_256, token);
    
    auto encoded = cwt.encodePayload();
    auto decoded = Cwt::decodePayload(encoded);
    
    CHECK(decoded.core.iss == token.core.iss);
    CHECK(decoded.core.aud == token.core.aud);
    CHECK(decoded.core.cti == token.core.cti);
    CHECK(decoded.cat.catv == token.cat.catv);
    CHECK(decoded.cat.catu == token.cat.catu);
    CHECK(decoded.cat.catreplay == token.cat.catreplay);
    CHECK(decoded.cat.catpor == token.cat.catpor);
    CHECK(decoded.cat.geohash == token.cat.geohash);
    
    CatToken emptyToken;
    Cwt emptyCwt(ALG_ES256, emptyToken);
    auto emptyEncoded = emptyCwt.encodePayload();
    auto emptyDecoded = Cwt::decodePayload(emptyEncoded);
    
    CHECK_FALSE(emptyDecoded.core.iss.has_value());
    CHECK_FALSE(emptyDecoded.core.aud.has_value());
    CHECK_FALSE(emptyDecoded.core.cti.has_value());
    CHECK_FALSE(emptyDecoded.cat.catv.has_value());
}

TEST_CASE("PayloadDecodingInvalidCbor") {
    std::vector<uint8_t> invalidData = {0xFF, 0xFF, 0xFF};
    CHECK_THROWS_AS(Cwt::decodePayload(invalidData), InvalidCborError);
}

TEST_CASE("PayloadDecodingNonMapCbor") {
    std::vector<uint8_t> arrayData = {0x83, 0x01, 0x02, 0x03};
    CHECK_THROWS_AS(Cwt::decodePayload(arrayData), InvalidTokenFormatError);
}

TEST_CASE("RoundtripEncodingDecoding") {
    auto originalToken = CatToken()
        .withIssuer("https://test.com")
        .withAudience({"api1", "api2"})
        .withCwtId("test-id-123")
        .withVersion("1.5")
        .withUsageLimit(42)
        .withGeoCoordinate(40.7128, -74.0060)
        .withGeohash("dr5reg")
        .withReplayProtection("nonce-456")
        .withProofOfPossession(false);
        
    
    Cwt cwt(ALG_ES256, originalToken);
    
    auto encoded1 = cwt.encodePayload();
    auto decoded1 = Cwt::decodePayload(encoded1);
    
    Cwt cwt2(ALG_ES256, decoded1);
    auto encoded2 = cwt2.encodePayload();
    auto decoded2 = Cwt::decodePayload(encoded2);
    
    CHECK(decoded1.core.iss == decoded2.core.iss);
    CHECK(decoded1.core.aud == decoded2.core.aud);
    CHECK(decoded1.core.cti == decoded2.core.cti);
    CHECK(decoded1.cat.catv == decoded2.cat.catv);
    CHECK(decoded1.cat.catu == decoded2.cat.catu);
    CHECK(decoded1.cat.catreplay == decoded2.cat.catreplay);
    CHECK(decoded1.cat.catpor == decoded2.cat.catpor);
    CHECK(decoded1.cat.geohash == decoded2.cat.geohash);
}

TEST_CASE("PayloadValidation") {
    auto token = createTestToken();
    Cwt cwt(ALG_HMAC256_256, token);
    auto encoded = cwt.encodePayload();
    
    struct cbor_load_result result;
    cbor_item_t* item = cbor_load(encoded.data(), encoded.size(), &result);
    
    REQUIRE(result.error.code == CBOR_ERR_NONE);
    REQUIRE(cbor_isa_map(item));
    
    struct cbor_pair* pairs = cbor_map_handle(item);
    size_t map_size = cbor_map_size(item);
    bool found_iss = false, found_aud = false, found_cti = false;
    
    for (size_t i = 0; i < map_size; i++) {
        if (cbor_isa_uint(pairs[i].key)) {
            uint64_t claim_id = cbor_get_uint64(pairs[i].key);
            cbor_item_t* value = pairs[i].value;
            
            switch (claim_id) {
                case CLAIM_ISS:
                    found_iss = cbor_isa_string(value);
                    break;
                case CLAIM_AUD:
                    found_aud = cbor_isa_array(value);
                    if (cbor_isa_array(value)) {
                        size_t aud_size = cbor_array_size(value);
                        cbor_item_t** aud_items = cbor_array_handle(value);
                        for (size_t j = 0; j < aud_size; j++) {
                            CHECK(cbor_isa_string(aud_items[j]));
                        }
                    }
                    break;
                case CLAIM_CTI:
                    found_cti = cbor_isa_string(value) || cbor_isa_bytestring(value);
                    break;
                case CLAIM_CATREPLAY:
                case CLAIM_CATV:
                case CLAIM_GEOHASH:
                    CHECK(cbor_isa_string(value));
                    break;
                case CLAIM_CATU:
                    CHECK(cbor_isa_uint(value));
                    break;
                case CLAIM_CATPOR:
                    CHECK(cbor_is_bool(value));
                    break;
                case CLAIM_CATGEOCOORD:
                    CHECK(cbor_isa_map(value));
                    if (cbor_isa_map(value)) {
                        CHECK(cbor_map_size(value) >= 2);
                        CHECK(cbor_map_size(value) <= 3);
                    }
                    break;
            }
        }
    }
    
    CHECK(found_iss);
    CHECK(found_aud);
    CHECK(found_cti);
    
    cbor_decref(&item);
}