#include <doctest/doctest.h>

#include <cbor.h>

#include <cstring>
#include <span>
#include <vector>

#include "catapult/error.hpp"
#include "catapult/internal/strict_cbor.hpp"

using catapult::InvalidCborError;
using catapult::internal::loadStrict;
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

TEST_CASE("strict CBOR rejects payloads exceeding size cap") {
  // Craft a "definite bytestring" header claiming a huge length so we do
  // not have to allocate a huge buffer; the length check should trip
  // before parsing.
  std::vector<uint8_t> bytes(catapult::internal::kMaxDecodedCborBytes + 1,
                             0x00);
  CHECK_THROWS_AS(loadStrict(std::span<const uint8_t>(bytes)),
                  InvalidCborError);
}
