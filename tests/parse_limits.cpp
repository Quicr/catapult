/**
 * @file parse_limits.cpp
 * @brief End-to-end coverage for CTA-5007-B parse-boundary hardening.
 *
 * strict_cbor.cpp exercises loadStrict directly. These cases pin the
 * higher-level effect: the CWT and DPoP decoders reject the same classes
 * of malformed input (trailing bytes, duplicate keys, indefinite-length
 * forms, unrecognised tags in the protected header).
 */

#include <cbor.h>
#include <doctest/doctest.h>

#include <memory>
#include <span>
#include <vector>

#include "catapult/base64.hpp"
#include "catapult/crypto.hpp"
#include "catapult/cwt.hpp"
#include "catapult/dpop.hpp"
#include "catapult/error.hpp"
#include "catapult/internal/parse_limits.hpp"
#include "catapult/parse_limits.hpp"
#include "catapult/uri.hpp"

using namespace catapult;

namespace {

std::vector<uint8_t> buildTaggedCoseSign1(std::vector<uint8_t> protHdr,
                                          std::vector<uint8_t> payload,
                                          std::vector<uint8_t> signature) {
  std::vector<uint8_t> out;
  // Tag 18 (COSE_Sign1)
  out.push_back(0xd8);
  out.push_back(0x12);
  // 4-element array
  out.push_back(0x84);

  auto pushBstr = [&](const std::vector<uint8_t>& b) {
    if (b.size() <= 23) {
      out.push_back(static_cast<uint8_t>(0x40 | b.size()));
    } else {
      out.push_back(0x58);
      out.push_back(static_cast<uint8_t>(b.size()));
    }
    out.insert(out.end(), b.begin(), b.end());
  };

  pushBstr(protHdr);
  out.push_back(0xa0);  // empty unprotected map
  pushBstr(payload);
  pushBstr(signature);
  return out;
}

}  // namespace

TEST_SUITE("CTA-5007-B parse boundary hardening") {
  TEST_CASE("Cwt::decodeHeader rejects trailing bytes on the COSE root") {
    // Minimal untagged Sign1: [h'', {}, h'', h'']  → 0x84 0x40 0xa0 0x40 0x40
    std::vector<uint8_t> good = {0x84, 0x40, 0xa0, 0x40, 0x40};
    // Append a spurious second CBOR item to trigger the trailing-byte
    // rejection path.
    std::vector<uint8_t> withTrailer = good;
    withTrailer.push_back(0x01);
    CHECK_THROWS_AS(Cwt::decodeHeader(std::span<const uint8_t>(withTrailer)),
                    InvalidCborError);
  }

  TEST_CASE("Cwt::decodeHeader rejects a COSE input exceeding the size cap") {
    std::vector<uint8_t> oversized(
        catapult::internal::kMaxDecodedCborBytes + 1, 0x00);
    CHECK_THROWS_AS(Cwt::decodeHeader(std::span<const uint8_t>(oversized)),
                    InvalidCborError);
  }

  TEST_CASE("Cwt::decodeHeader rejects protected header with duplicate keys") {
    // Protected header map contains alg=ES256 twice: {1: -7, 1: -7}
    std::vector<uint8_t> dupHdr = {0xa2, 0x01, 0x26, 0x01, 0x26};
    auto cose = buildTaggedCoseSign1(dupHdr, /*payload=*/{}, /*sig=*/{});
    CHECK_THROWS_AS(Cwt::decodeHeader(std::span<const uint8_t>(cose)),
                    InvalidTokenFormatError);
  }

  TEST_CASE(
      "Cwt::decodeHeader rejects protected header with indefinite-length map") {
    // 0xbf ... 0xff would be an indefinite-length map; strict parse rejects.
    std::vector<uint8_t> indefHdr = {0xbf, 0x01, 0x26, 0xff};
    auto cose = buildTaggedCoseSign1(indefHdr, {}, {});
    CHECK_THROWS_AS(Cwt::decodeHeader(std::span<const uint8_t>(cose)),
                    InvalidTokenFormatError);
  }

  TEST_CASE("UriMatcher surfaces regex compile failures instead of silently"
            " accepting the claim") {
    UriMatcher matcher;
    UriPattern bad{UriPatternType::Regex, "([unclosed"};
    CHECK_THROWS_AS(matcher.addPattern(bad), InvalidClaimValueError);
  }

  TEST_CASE("UriMatcher rejects oversized regex patterns") {
    UriMatcher matcher;
    UriPattern huge{
        UriPatternType::Regex,
        std::string(catapult::internal::kMaxRegexPatternLength + 1, 'a')};
    CHECK_THROWS_AS(matcher.addPattern(huge), InvalidClaimValueError);
  }
}

TEST_SUITE("Public ParseLimits configuration") {
  TEST_CASE("Defaults pass validation") {
    // The shipped defaults are the CTA-5007-B recommendation; they must
    // always be accepted, otherwise every caller who does not override
    // would be blocked at construction.
    CHECK_NOTHROW(validateParseLimits(ParseLimits::defaults()));
  }

  TEST_CASE("Zero on any field is rejected as disabling the check") {
    ParseLimits limits = ParseLimits::defaults();
    limits.max_encoded_token_bytes = 0;
    CHECK_THROWS_AS(validateParseLimits(limits), InvalidParseLimitsError);
  }

  TEST_CASE("Values above the compiled ceiling are rejected") {
    // Loosening the ceiling is not a supported operation — the ceiling
    // is what the fuzz corpus is anchored against. Callers may only
    // tighten below it.
    ParseLimits limits = ParseLimits::defaults();
    limits.max_encoded_token_bytes = kAbsoluteMaxEncodedTokenBytes + 1;
    CHECK_THROWS_AS(validateParseLimits(limits), InvalidParseLimitsError);
  }

  TEST_CASE("Tightening below the default is accepted") {
    // A relay whose transport layer caps token bytes tighter than 4 KiB
    // can legitimately narrow the parse ceiling. Enforcement propagates
    // through the public CWT overload.
    ParseLimits tight = ParseLimits::defaults();
    tight.max_encoded_token_bytes = 100;
    CHECK_NOTHROW(validateParseLimits(tight));
  }

  TEST_CASE(
      "validateCwtBase64 with a tightened ParseLimits rejects oversized "
      "input the default overload would have accepted") {
    // Build an encoded input larger than the tightened cap but smaller
    // than the default cap. The overload MUST honour the caller.
    ParseLimits tight = ParseLimits::defaults();
    tight.max_encoded_token_bytes = 32;
    // A 40-char base64 string; content does not need to be valid CBOR
    // because the size check fires first.
    std::string oversize(40, 'A');
    HmacSha256Algorithm hmac(std::vector<uint8_t>(32, 0x00));
    CHECK_THROWS_AS(Cwt::validateCwtBase64(oversize, hmac, tight),
                    InvalidTokenFormatError);
  }

  TEST_CASE(
      "validateCwtBase64 with an invalid ParseLimits reports it as a "
      "configuration error before touching the input") {
    ParseLimits bad = ParseLimits::defaults();
    bad.max_encoded_token_bytes = 0;
    HmacSha256Algorithm hmac(std::vector<uint8_t>(32, 0x00));
    CHECK_THROWS_AS(Cwt::validateCwtBase64("ignored", hmac, bad),
                    InvalidParseLimitsError);
  }
}
