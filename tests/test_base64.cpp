#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "catapult/cat_base64.hpp"
#include <array>
#include <numeric>

using namespace catapult;

TEST_CASE("Base64UrlEncode - Empty input") {
    std::vector<uint8_t> empty;
    std::string encoded = base64UrlEncode(empty);
    CHECK(encoded.empty());
}

TEST_CASE("Base64UrlEncode - Single byte") {
    std::vector<uint8_t> data = {0x4d}; // "M"
    std::string encoded = base64UrlEncode(data);
    CHECK(encoded == "TQ");
}


TEST_CASE("Base64UrlEncode - Four bytes") {
    std::vector<uint8_t> data = {0x4d, 0x61, 0x6e, 0x79}; // "Many"
    std::string encoded = base64UrlEncode(data);
    CHECK(encoded == "TWFueQ");
}

TEST_CASE("Base64UrlEncode - Binary data") {
    std::vector<uint8_t> data = {0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd};
    std::string encoded = base64UrlEncode(data);
    CHECK(encoded == "AAECA__-_Q");
}

TEST_CASE("Base64UrlEncode - URL-safe characters") {
    std::vector<uint8_t> data = {0x3e, 0x3f}; // Should produce '+' and '/' in standard base64, but '-' and '_' in URL-safe
    std::string encoded = base64UrlEncode(data);
    CHECK(encoded == "Pj8");
    
    std::vector<uint8_t> data2 = {0xfb, 0xff}; // Should produce URL-safe characters
    std::string encoded2 = base64UrlEncode(data2);
    CHECK(encoded2 == "-_8");
}

TEST_CASE("Base64UrlDecode - Empty input") {
    auto decoded = base64UrlDecode("");
    CHECK(decoded.empty());
}

TEST_CASE("Base64UrlDecode - Single byte") {
    auto decoded = base64UrlDecode("TQ");
    std::vector<uint8_t> expected = {0x4d};
    CHECK(decoded == expected);
}


TEST_CASE("Base64UrlDecode - URL-safe characters") {
    auto decoded = base64UrlDecode("-_8");
    std::vector<uint8_t> expected = {0xfb, 0xff};
    CHECK(decoded == expected);
}

TEST_CASE("Base64UrlDecode - Invalid characters") {
    CHECK_THROWS_AS(base64UrlDecode("TW@u"), InvalidBase64Error);
    CHECK_THROWS_AS(base64UrlDecode("TW+u"), InvalidBase64Error); // Standard base64 chars not allowed
    CHECK_THROWS_AS(base64UrlDecode("TW/u"), InvalidBase64Error); // Standard base64 chars not allowed
    CHECK_THROWS_AS(base64UrlDecode("TW u"), InvalidBase64Error); // Space not allowed
    CHECK_THROWS_AS(base64UrlDecode("TW\tu"), InvalidBase64Error); // Tab not allowed
    CHECK_THROWS_AS(base64UrlDecode("TW\nu"), InvalidBase64Error); // Newline not allowed
}

TEST_CASE("Base64UrlDecode - Padding handling") {
    // URL-safe base64 typically omits padding, but should handle it if present
    auto decoded1 = base64UrlDecode("TWE=");
    std::vector<uint8_t> expected1 = {0x4d, 0x61};
    CHECK(decoded1 == expected1);
    
    auto decoded2 = base64UrlDecode("TQ==");
    std::vector<uint8_t> expected2 = {0x4d};
    CHECK(decoded2 == expected2);
}

TEST_CASE("Base64UrlEncode/Decode - Round trip test") {
    std::vector<uint8_t> original = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0xff
    };
    
    std::string encoded = base64UrlEncode(original);
    auto decoded = base64UrlDecode(encoded);
    CHECK(decoded == original);
}

TEST_CASE("Base64UrlEncode - Use std::aray") {
    // Test with std::array
    std::array<uint8_t, 3> arr = {0x4d, 0x61, 0x6e};
    std::string encoded = base64UrlEncode(arr);
    CHECK(encoded == "TWFu");
    
    // Test with vector (should also work with concept)
    std::vector<uint8_t> vec = {0x4d, 0x61, 0x6e};
    std::string encoded2 = base64UrlEncode(vec);
    CHECK(encoded2 == "TWFu");
}
