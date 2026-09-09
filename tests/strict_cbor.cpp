#include <doctest/doctest.h>

#include <cbor.h>

#include <cstring>
#include <span>
#include <vector>

#include "catapult/error.hpp"
#include "catapult/internal/strict_cbor.hpp"

using catapult::InvalidCborError;
using catapult::internal::loadStrict;
using catapult::internal::loadStrictCoseEnvelope;
using catapult::internal::StrictCborOptions;

namespace {

std::vector<uint8_t> asBytes(std::initializer_list<int> ints) {
  std::vector<uint8_t> out;
  out.reserve(ints.size());
  for (int b : ints) out.push_back(static_cast<uint8_t>(b));
  return out;
}

}  // namespace

TEST_CASE("strict CBOR accepts a canonical integer") {
  auto bytes = asBytes({0x01});  // unsigned 1
  auto item = loadStrict(std::span<const uint8_t>(bytes));
  REQUIRE(item);
  CHECK(cbor_typeof(item.get()) == CBOR_TYPE_UINT);
}

TEST_CASE("strict CBOR accepts a small definite map") {
  // { 1: 2, 3: 4 }
  auto bytes = asBytes({0xa2, 0x01, 0x02, 0x03, 0x04});
  auto item = loadStrict(std::span<const uint8_t>(bytes));
  REQUIRE(item);
  CHECK(cbor_typeof(item.get()) == CBOR_TYPE_MAP);
  CHECK(cbor_map_size(item.get()) == 2);
}

TEST_CASE("strict CBOR rejects empty input") {
  std::vector<uint8_t> bytes;
  CHECK_THROWS_AS(loadStrict(std::span<const uint8_t>(bytes)),
                  InvalidCborError);
}

TEST_CASE("strict CBOR rejects trailing bytes after root") {
  auto bytes = asBytes({0x01, 0x02});  // two independent items concatenated
  CHECK_THROWS_AS(loadStrict(std::span<const uint8_t>(bytes)),
                  InvalidCborError);
}

TEST_CASE("strict CBOR rejects indefinite-length array") {
  // 0x9f = indefinite array, one uint 1, then break
  auto bytes = asBytes({0x9f, 0x01, 0xff});
  CHECK_THROWS_AS(loadStrict(std::span<const uint8_t>(bytes)),
                  InvalidCborError);
}

TEST_CASE("strict CBOR rejects indefinite-length map") {
  // 0xbf = indefinite map, 1:2, break
  auto bytes = asBytes({0xbf, 0x01, 0x02, 0xff});
  CHECK_THROWS_AS(loadStrict(std::span<const uint8_t>(bytes)),
                  InvalidCborError);
}

TEST_CASE("strict CBOR rejects indefinite-length bytestring") {
  // 0x5f = indefinite bytestring, one chunk 0x41 0xAA, then break
  auto bytes = asBytes({0x5f, 0x41, 0xaa, 0xff});
  CHECK_THROWS_AS(loadStrict(std::span<const uint8_t>(bytes)),
                  InvalidCborError);
}

TEST_CASE("strict CBOR rejects indefinite-length text string") {
  // 0x7f = indefinite text string, one chunk 0x61 'a', then break
  auto bytes = asBytes({0x7f, 0x61, 0x61, 0xff});
  CHECK_THROWS_AS(loadStrict(std::span<const uint8_t>(bytes)),
                  InvalidCborError);
}

TEST_CASE("strict CBOR rejects duplicate map keys") {
  // { 1: 2, 1: 3 } — same key encoded twice
  auto bytes = asBytes({0xa2, 0x01, 0x02, 0x01, 0x03});
  CHECK_THROWS_AS(loadStrict(std::span<const uint8_t>(bytes)),
                  InvalidCborError);
}

TEST_CASE("strict CBOR rejects unrecognized tags") {
  // Tag 0 (RFC 3339 date/time string) wrapping the text "hi"
  auto bytes = asBytes({0xc0, 0x62, 0x68, 0x69});
  CHECK_THROWS_AS(loadStrict(std::span<const uint8_t>(bytes)),
                  InvalidCborError);
}

TEST_CASE("strict CBOR rejects NaN floats") {
  // 0xfa = single-precision float, IEEE 754 quiet NaN 0x7fc00000
  auto bytes = asBytes({0xfa, 0x7f, 0xc0, 0x00, 0x00});
  CHECK_THROWS_AS(loadStrict(std::span<const uint8_t>(bytes)),
                  InvalidCborError);
}

TEST_CASE("strict CBOR rejects negative zero float") {
  // 0xfa = single-precision float, -0.0 = 0x80000000
  auto bytes = asBytes({0xfa, 0x80, 0x00, 0x00, 0x00});
  CHECK_THROWS_AS(loadStrict(std::span<const uint8_t>(bytes)),
                  InvalidCborError);
}

TEST_CASE("strict CBOR rejects excessive nesting depth") {
  // Build 20 nested single-element arrays: 0x81 repeated + terminal 0x01.
  std::vector<uint8_t> bytes(20, 0x81);
  bytes.push_back(0x01);
  StrictCborOptions opts;
  opts.max_depth = 16;
  CHECK_THROWS_AS(loadStrict(std::span<const uint8_t>(bytes), opts),
                  InvalidCborError);
}

TEST_CASE("strict CBOR allows nesting within depth limit") {
  // 4 nested arrays containing 1 — well under default 16 limit.
  std::vector<uint8_t> bytes(4, 0x81);
  bytes.push_back(0x01);
  auto item = loadStrict(std::span<const uint8_t>(bytes));
  REQUIRE(item);
  CHECK(cbor_typeof(item.get()) == CBOR_TYPE_ARRAY);
}

TEST_CASE("strict CBOR pre-scan rejects oversized array header") {
  // 0x9a followed by a 4-byte length ~2^30 with no payload. libcbor
  // pre-allocates array storage from this header; without the pre-scan
  // this input would attempt a multi-GB allocation.
  auto bytes = asBytes({0x9a, 0x40, 0x00, 0x00, 0x00});
  CHECK_THROWS_AS(loadStrict(std::span<const uint8_t>(bytes)),
                  InvalidCborError);
}

TEST_CASE("strict CBOR pre-scan rejects oversized map header") {
  // 0xba (map, 4-byte length) with count 2^20 but only 5 bytes of input.
  auto bytes = asBytes({0xba, 0x00, 0x10, 0x00, 0x00});
  CHECK_THROWS_AS(loadStrict(std::span<const uint8_t>(bytes)),
                  InvalidCborError);
}

TEST_CASE("strict CBOR pre-scan rejects oversized bytestring header") {
  // 0x5a (bytestring, 4-byte length) claiming ~1 GiB with 0 payload bytes.
  auto bytes = asBytes({0x5a, 0x40, 0x00, 0x00, 0x00});
  CHECK_THROWS_AS(loadStrict(std::span<const uint8_t>(bytes)),
                  InvalidCborError);
}

TEST_CASE("strict CBOR pre-scan rejects truncated head length") {
  // 0x1a (uint32) with only 2 length bytes present.
  auto bytes = asBytes({0x1a, 0x01, 0x02});
  CHECK_THROWS_AS(loadStrict(std::span<const uint8_t>(bytes)),
                  InvalidCborError);
}

TEST_CASE("strict CBOR rejects payloads exceeding size cap") {
  // Craft a "definite bytestring" header claiming a huge length so we do
  // not have to allocate a huge buffer; the length check should trip
  // before parsing.
  std::vector<uint8_t> bytes(catapult::internal::kMaxDecodedCborBytes + 1,
                             0x00);
  CHECK_THROWS_AS(loadStrict(std::span<const uint8_t>(bytes)),
                  InvalidCborError);
}

TEST_CASE("strict CBOR rejects non-shortest integer (2-byte encoding of 1)") {
  // 0x19 0x00 0x01 = uint16 with value 1. Canonical form is 0x01.
  auto bytes = asBytes({0x19, 0x00, 0x01});
  CHECK_THROWS_AS(loadStrict(std::span<const uint8_t>(bytes)),
                  InvalidCborError);
}

TEST_CASE("strict CBOR rejects non-shortest integer (8-byte encoding of 5)") {
  // 0x1b 00 00 00 00 00 00 00 05 = uint64 with value 5.
  auto bytes = asBytes({0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05});
  CHECK_THROWS_AS(loadStrict(std::span<const uint8_t>(bytes)),
                  InvalidCborError);
}

TEST_CASE("strict CBOR rejects non-shortest negint") {
  // 0x39 0x00 0x00 = negint16 with value -1. Canonical is 0x20.
  auto bytes = asBytes({0x39, 0x00, 0x00});
  CHECK_THROWS_AS(loadStrict(std::span<const uint8_t>(bytes)),
                  InvalidCborError);
}

TEST_CASE("strict CBOR rejects non-canonical map key order") {
  // { 100: 1, 1: 2 }
  //  - key 100 serializes to 3 bytes: 0x18 0x64
  //  - key 1 serializes to 1 byte: 0x01
  // Length-first ordering requires the 1-byte key first, so this input is
  // out of canonical order.
  auto bytes = asBytes({0xa2, 0x18, 0x64, 0x01, 0x01, 0x02});
  CHECK_THROWS_AS(loadStrict(std::span<const uint8_t>(bytes)),
                  InvalidCborError);
}

TEST_CASE("strict CBOR accepts canonical length-first map order") {
  // { 1: 2, 100: 3 } — 1-byte key precedes 2-byte key.
  auto bytes = asBytes({0xa2, 0x01, 0x02, 0x18, 0x64, 0x03});
  auto item = loadStrict(std::span<const uint8_t>(bytes));
  REQUIRE(item);
  CHECK(cbor_typeof(item.get()) == CBOR_TYPE_MAP);
}

TEST_CASE("strict CBOR accepts a whitelisted tag (context-aware policy)") {
  // Tag 52 wrapping bytestring 0x00 — a shape catnip test vectors carry.
  // Under the default policy this is rejected; with the tag in the allow-
  // list the loader must accept and recurse into the wrapped bytestring.
  auto bytes = asBytes({0xd8, 0x34, 0x40});
  StrictCborOptions opts;
  opts.allowed_tags = {52};
  auto item = loadStrict(std::span<const uint8_t>(bytes), opts);
  REQUIRE(item);
  CHECK(cbor_typeof(item.get()) == CBOR_TYPE_TAG);
  CHECK(cbor_tag_value(item.get()) == 52);
}

TEST_CASE("strict CBOR still rejects non-whitelisted tags under narrow policy") {
  // Tag 52 is whitelisted, but tag 100 is not — the loader must reject.
  auto bytes = asBytes({0xd8, 0x64, 0x40});
  StrictCborOptions opts;
  opts.allowed_tags = {52};
  CHECK_THROWS_AS(loadStrict(std::span<const uint8_t>(bytes), opts),
                  InvalidCborError);
}

TEST_CASE(
    "strict COSE envelope peels a whitelisted outer tag and returns it") {
  // Tag 18 (COSE_Sign1) wrapping a 4-element array of definite bytestrings.
  // Inner array: [h'', {}, h'', h''] serialises to 0x84 0x40 0xa0 0x40 0x40.
  auto bytes = asBytes({0xd2, 0x84, 0x40, 0xa0, 0x40, 0x40});
  auto env = loadStrictCoseEnvelope(std::span<const uint8_t>(bytes), {18});
  REQUIRE(env.item);
  REQUIRE(env.tag.has_value());
  CHECK(*env.tag == 18);
  CHECK(cbor_typeof(env.item.get()) == CBOR_TYPE_ARRAY);
  CHECK(cbor_array_size(env.item.get()) == 4);
}

TEST_CASE("strict COSE envelope rejects wrong outer tag") {
  // Tag 17 (COSE_Mac0) — Sign1-only whitelist must reject before parsing
  // the body. This is exactly the tag-confusion guard L-04 codifies.
  auto bytes = asBytes({0xd1, 0x84, 0x40, 0xa0, 0x40, 0x40});
  CHECK_THROWS_AS(
      loadStrictCoseEnvelope(std::span<const uint8_t>(bytes), {18}),
      InvalidCborError);
}

TEST_CASE("strict COSE envelope accepts untagged COSE array") {
  // Same inner array, no outer tag: env.tag is unset, item is the array.
  auto bytes = asBytes({0x84, 0x40, 0xa0, 0x40, 0x40});
  auto env = loadStrictCoseEnvelope(std::span<const uint8_t>(bytes), {18});
  REQUIRE(env.item);
  CHECK_FALSE(env.tag.has_value());
  CHECK(cbor_typeof(env.item.get()) == CBOR_TYPE_ARRAY);
}
