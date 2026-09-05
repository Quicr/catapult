/**
 * @file uri_catu.cpp
 * @brief Coverage for the CTA-5007-B `catu` URI component matcher.
 */

#include <doctest/doctest.h>

#include <string>
#include <vector>

#include "catapult/crypto.hpp"
#include "catapult/uri.hpp"

using namespace catapult;

namespace {

std::vector<uint8_t> asBytes(const std::string& s) {
  return std::vector<uint8_t>(s.begin(), s.end());
}

UriComponentMatch match(UriMatchType type, const std::string& value) {
  return UriComponentMatch{type, asBytes(value)};
}

}  // namespace

TEST_SUITE("parseUri") {
  TEST_CASE("splits a typical https URI into its components") {
    auto p = parseUri("HTTPS://User:pw@Example.COM:0443/api/v1/track.m4s?x=1#f");
    REQUIRE(p.has_value());
    CHECK(p->scheme == "https");
    CHECK(p->host == "example.com");
    CHECK(p->port == "443");
    CHECK(p->path == "/api/v1/track.m4s");
    CHECK(p->query == "x=1");
    CHECK(p->parent_path == "/api/v1");
    CHECK(p->filename == "track.m4s");
    CHECK(p->stem == "track");
    CHECK(p->extension == "m4s");
  }

  TEST_CASE("normalises IPv6 authority and empty path") {
    auto p = parseUri("moq://[2001:db8::1]:4443");
    REQUIRE(p.has_value());
    CHECK(p->scheme == "moq");
    CHECK(p->host == "2001:db8::1");
    CHECK(p->port == "4443");
    CHECK(p->path.empty());
  }

  TEST_CASE("resolves dot segments per RFC 3986 §5.2.4") {
    auto p = parseUri("https://h/a/b/../c/./d");
    REQUIRE(p.has_value());
    CHECK(p->path == "/a/c/d");
  }

  TEST_CASE("rejects inputs without a scheme delimiter") {
    CHECK_FALSE(parseUri("no-scheme").has_value());
    CHECK_FALSE(parseUri("").has_value());
    CHECK_FALSE(parseUri("://x").has_value());
  }
}

TEST_SUITE("matchesCatu") {
  TEST_CASE("empty catu accepts any URI that parses") {
    CatUriMatchMap empty;
    CHECK(matchesCatu(empty, "https://example.com/"));
  }

  TEST_CASE("all listed components must match (AND semantics)") {
    CatUriMatchMap m;
    m.components[static_cast<int64_t>(UriComponentLabel::Scheme)] =
        match(UriMatchType::Exact, "https");
    m.components[static_cast<int64_t>(UriComponentLabel::Host)] =
        match(UriMatchType::Suffix, ".example.com");
    m.components[static_cast<int64_t>(UriComponentLabel::Path)] =
        match(UriMatchType::Prefix, "/api/");
    CHECK(matchesCatu(m, "https://api.example.com/api/v1"));
    CHECK_FALSE(matchesCatu(m, "https://example.com/api/v1"));
    CHECK_FALSE(matchesCatu(m, "https://api.example.com/other"));
    CHECK_FALSE(matchesCatu(m, "http://api.example.com/api/v1"));
  }

  TEST_CASE("Contains matches substrings inside the component only") {
    CatUriMatchMap m;
    m.components[static_cast<int64_t>(UriComponentLabel::Path)] =
        match(UriMatchType::Contains, "/segments/");
    CHECK(matchesCatu(m, "https://h/live/segments/0001.m4s"));
    CHECK_FALSE(matchesCatu(m, "https://h/live/other/0001.m4s"));
  }

  TEST_CASE("Regex is anchored to the whole component (not the whole URI)") {
    CatUriMatchMap m;
    m.components[static_cast<int64_t>(UriComponentLabel::Extension)] =
        match(UriMatchType::Regex, "m4[sv]");
    CHECK(matchesCatu(m, "https://h/a/b.m4s"));
    CHECK(matchesCatu(m, "https://h/a/b.m4v"));
    CHECK_FALSE(matchesCatu(m, "https://h/a/b.mp4"));
  }

  TEST_CASE("SHA-256 match compares the digest of the component") {
    std::string host = "cdn.example";
    auto digest = hashSha256(asBytes(host));
    CatUriMatchMap m;
    m.components[static_cast<int64_t>(UriComponentLabel::Host)] =
        UriComponentMatch{UriMatchType::SHA256, digest};
    CHECK(matchesCatu(m, "https://cdn.example/x"));
    CHECK_FALSE(matchesCatu(m, "https://other.example/x"));
  }

  TEST_CASE("SHA-512/256 match compares the truncated digest") {
    std::string filename = "master.m3u8";
    auto digest = hashSha512_256(asBytes(filename));
    REQUIRE(digest.size() == 32);
    CatUriMatchMap m;
    m.components[static_cast<int64_t>(UriComponentLabel::Filename)] =
        UriComponentMatch{UriMatchType::SHA512_256, digest};
    CHECK(matchesCatu(m, "https://h/live/master.m3u8"));
    CHECK_FALSE(matchesCatu(m, "https://h/live/other.m3u8"));
  }

  TEST_CASE("Unknown component labels fail closed") {
    CatUriMatchMap m;
    m.components[99] = match(UriMatchType::Exact, "anything");
    CHECK_FALSE(matchesCatu(m, "https://h/"));
  }

  TEST_CASE("Non-parseable URIs never match") {
    CatUriMatchMap m;
    m.components[static_cast<int64_t>(UriComponentLabel::Scheme)] =
        match(UriMatchType::Exact, "https");
    CHECK_FALSE(matchesCatu(m, "not-a-uri"));
  }
}
