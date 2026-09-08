/**
 * @file test_moqt_claims.cpp
 * @brief Comprehensive unit tests for MOQT claims functionality
 */

#include "catapult/moqt_claims.hpp"

#include <cbor.h>
#include <doctest/doctest.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <ranges>
#include <string_view>
#include <vector>

#include "catapult/cwt.hpp"
#include "catapult/dpop.hpp"
#include "catapult/error.hpp"
#include "catapult/token.hpp"

using namespace catapult;
using namespace std::chrono_literals;
using namespace std::string_view_literals;

TEST_SUITE("MOQT Claims Tests") {
  TEST_CASE("MOQT Action Validation") {
    // Test valid actions
    CHECK(moqt_actions::is_valid_action(moqt_actions::CLIENT_SETUP));
    CHECK(moqt_actions::is_valid_action(moqt_actions::SERVER_SETUP));
    CHECK(moqt_actions::is_valid_action(moqt_actions::ANNOUNCE));
    CHECK(moqt_actions::is_valid_action(moqt_actions::SUBSCRIBE_NAMESPACE));
    CHECK(moqt_actions::is_valid_action(moqt_actions::SUBSCRIBE));
    CHECK(moqt_actions::is_valid_action(moqt_actions::SUBSCRIBE_UPDATE));
    CHECK(moqt_actions::is_valid_action(moqt_actions::PUBLISH));
    CHECK(moqt_actions::is_valid_action(moqt_actions::FETCH));
    CHECK(moqt_actions::is_valid_action(moqt_actions::TRACK_STATUS));

    // Test invalid actions
    CHECK_FALSE(moqt_actions::is_valid_action(-1));
    CHECK_FALSE(moqt_actions::is_valid_action(9));
    CHECK_FALSE(moqt_actions::is_valid_action(100));

    // Test action names
    CHECK(moqt_actions::action_name(moqt_actions::PUBLISH) == "PUBLISH");
    CHECK(moqt_actions::action_name(moqt_actions::SUBSCRIBE) == "SUBSCRIBE");
    CHECK(moqt_actions::action_name(-1) == "UNKNOWN");
  }

  TEST_CASE("Binary Match Tests") {
    SUBCASE("Exact Match") {
      auto match = MoqtBinaryMatch::exact("example.com");

      CHECK(match.matches("example.com"));
      CHECK_FALSE(match.matches("other.com"));
      CHECK_FALSE(match.matches("example.com.evil"));
      CHECK_FALSE(match.matches("prefix.example.com"));

      CHECK(match.pattern_as_string() == "example.com");
      CHECK_FALSE(match.is_empty());
    }

    SUBCASE("Prefix Match") {
      auto match = MoqtBinaryMatch::prefix("example");

      CHECK(match.matches("example"));
      CHECK(match.matches("example.com"));
      CHECK(match.matches("example123"));
      CHECK_FALSE(match.matches("other.example"));
      CHECK_FALSE(match.matches("exam"));
    }

    SUBCASE("Suffix Match") {
      auto match = MoqtBinaryMatch::suffix(".com");

      CHECK(match.matches("example.com"));
      CHECK(match.matches("test.com"));
      CHECK(match.matches(".com"));
      CHECK_FALSE(match.matches("example.org"));
      CHECK_FALSE(match.matches("com"));
    }

    SUBCASE("Contains Match") {
      auto match = MoqtBinaryMatch::contains("test");

      CHECK(match.matches("test"));
      CHECK(match.matches("testing"));
      CHECK(match.matches("my_test_app"));
      CHECK(match.matches("contest"));
      CHECK_FALSE(match.matches("example"));
      CHECK_FALSE(match.matches("tes"));
    }

    SUBCASE("Empty Match") {
      auto match = MoqtBinaryMatch::any();

      CHECK(match.is_empty());
      CHECK(match.is_wildcard());
      CHECK(match.matches("anything"));
      CHECK(match.matches(""));
      CHECK(match.matches("example.com"));
    }

    SUBCASE("exact('') is not the wildcard") {
      // Regression: pre-hardening, `exact("")` returned is_empty()==true
      // and short-circuited matches() to true, silently upgrading it to
      // the wildcard. That masks a policy bug where an issuer meant to
      // gate an empty resource name but ended up gating every name.
      auto match = MoqtBinaryMatch::exact("");

      CHECK_FALSE(match.is_wildcard());
      CHECK_FALSE(match.is_empty());
      // Matches only the empty input, not everything.
      CHECK(match.matches(""));
      CHECK_FALSE(match.matches("any"));
      CHECK_FALSE(match.matches("example.com"));
    }

    SUBCASE("prefix('') / suffix('') / contains('') are rejected") {
      // An empty prefix / suffix / substring is by definition satisfied
      // by every input — the only spec-supported way to express that is
      // `any()`. Accepting them silently would let a policy author write
      // what looks like a specific restriction and get a wildcard.
      CHECK_THROWS_AS(MoqtBinaryMatch::prefix(""), InvalidClaimValueError);
      CHECK_THROWS_AS(MoqtBinaryMatch::suffix(""), InvalidClaimValueError);
      CHECK_THROWS_AS(MoqtBinaryMatch::contains(""), InvalidClaimValueError);
    }
  }

  TEST_CASE("MOQT Action Scope Tests") {
    SUBCASE("Basic Scope Creation") {
      std::array actions = {moqt_actions::PUBLISH, moqt_actions::ANNOUNCE};
      auto namespace_match = MoqtBinaryMatch::exact("example.com");
      auto track_match = MoqtBinaryMatch::prefix("/live");

      auto scope =
          MoqtActionScope::create(actions, namespace_match, track_match);

      CHECK(scope.action_count() == 2);
      CHECK(scope.contains_action(moqt_actions::PUBLISH));
      CHECK(scope.contains_action(moqt_actions::ANNOUNCE));
      CHECK_FALSE(scope.contains_action(moqt_actions::SUBSCRIBE));
    }

    SUBCASE("Authorization Tests") {
      std::array actions = {moqt_actions::PUBLISH, moqt_actions::FETCH};
      auto namespace_match = MoqtBinaryMatch::exact("streaming.example");
      auto track_match = MoqtBinaryMatch::prefix("/live");

      auto scope =
          MoqtActionScope::create(actions, namespace_match, track_match);

      // Valid authorizations
      CHECK(scope.authorizes(moqt_actions::PUBLISH, "streaming.example",
                             "/live/stream1"));
      CHECK(scope.authorizes(moqt_actions::FETCH, "streaming.example",
                             "/live/stream2"));
      CHECK(scope.authorizes(moqt_actions::PUBLISH, "streaming.example",
                             "/live"));

      // Invalid authorizations
      CHECK_FALSE(scope.authorizes(moqt_actions::SUBSCRIBE, "streaming.example",
                                   "/live/stream1"));
      CHECK_FALSE(scope.authorizes(moqt_actions::PUBLISH, "other.example",
                                   "/live/stream1"));
      CHECK_FALSE(scope.authorizes(moqt_actions::PUBLISH, "streaming.example",
                                   "/recorded/stream1"));
    }

    SUBCASE("Invalid Action Validation") {
      std::array invalid_actions = {-1, 10, 100};
      auto namespace_match = MoqtBinaryMatch::exact("test.com");
      auto track_match = MoqtBinaryMatch::any();

      CHECK_THROWS_AS(MoqtActionScope::create(invalid_actions, namespace_match,
                                              track_match),
                      InvalidClaimValueError);
    }
  }

  TEST_CASE("Compile-Time Action Set Tests") {
    SUBCASE("Basic Functionality") {
      constexpr auto action_set =
          CompileTimeActionSet<moqt_actions::PUBLISH, moqt_actions::ANNOUNCE,
                               moqt_actions::SUBSCRIBE>{};

      static_assert(action_set.size() == 3);
      static_assert(action_set.template contains<moqt_actions::PUBLISH>());
      static_assert(action_set.template contains<moqt_actions::ANNOUNCE>());
      static_assert(!action_set.template contains<moqt_actions::FETCH>());

      CHECK(action_set.contains(moqt_actions::PUBLISH));
      CHECK(action_set.contains(moqt_actions::ANNOUNCE));
      CHECK(action_set.contains(moqt_actions::SUBSCRIBE));
      CHECK_FALSE(action_set.contains(moqt_actions::FETCH));

      auto actions_span = action_set.get_actions();
      CHECK(actions_span.size() == 3);
    }

    SUBCASE("Role-Based Action Sets") {
      // Test publisher role
      static_assert(
          role_actions::publisher.template contains<moqt_actions::PUBLISH>());
      static_assert(
          role_actions::publisher.template contains<moqt_actions::ANNOUNCE>());
      static_assert(!role_actions::publisher
                         .template contains<moqt_actions::SUBSCRIBE>());

      CHECK(role_actions::publisher.contains(moqt_actions::PUBLISH));
      CHECK(role_actions::publisher.contains(moqt_actions::ANNOUNCE));
      CHECK_FALSE(role_actions::publisher.contains(moqt_actions::SUBSCRIBE));

      // Test subscriber role
      static_assert(role_actions::subscriber
                        .template contains<moqt_actions::SUBSCRIBE>());
      static_assert(
          role_actions::subscriber.template contains<moqt_actions::FETCH>());
      static_assert(
          !role_actions::subscriber.template contains<moqt_actions::PUBLISH>());

      CHECK(role_actions::subscriber.contains(moqt_actions::SUBSCRIBE));
      CHECK(role_actions::subscriber.contains(moqt_actions::FETCH));
      CHECK_FALSE(role_actions::subscriber.contains(moqt_actions::PUBLISH));

      // Test template utility functions
      CHECK(validates_role(role_actions::publisher, moqt_actions::PUBLISH));
      CHECK_FALSE(
          validates_role(role_actions::publisher, moqt_actions::SUBSCRIBE));

      CHECK(is_action_allowed<moqt_actions::PUBLISH, moqt_actions::ANNOUNCE>(
          moqt_actions::PUBLISH));
      CHECK_FALSE(
          is_action_allowed<moqt_actions::PUBLISH, moqt_actions::ANNOUNCE>(
              moqt_actions::SUBSCRIBE));
    }
  }

  TEST_CASE("MOQT Claims Tests") {
    SUBCASE("Basic Claims Creation") {
      auto claims = MoqtClaims::create();

      CHECK(claims.empty());
      CHECK(claims.getScopeCount() == 0);
      CHECK(claims.getTotalActionCount() == 0);
    }

    SUBCASE("Add Scopes") {
      auto claims = MoqtClaims::create(5);

      std::array publish_actions = {moqt_actions::PUBLISH,
                                    moqt_actions::ANNOUNCE};
      claims.addScope(publish_actions,
                      MoqtBinaryMatch::exact("publisher.example"),
                      MoqtBinaryMatch::prefix("/live"));

      std::array subscribe_actions = {moqt_actions::SUBSCRIBE,
                                      moqt_actions::FETCH};
      claims.addScope(subscribe_actions, MoqtBinaryMatch::suffix(".live"),
                      MoqtBinaryMatch::any());

      CHECK(claims.getScopeCount() == 2);
      CHECK(claims.getTotalActionCount() == 4);
      CHECK_FALSE(claims.empty());
    }

    SUBCASE("Authorization Tests") {
      auto claims = MoqtClaims::create();

      // Publisher scope
      std::array publish_actions = {moqt_actions::PUBLISH,
                                    moqt_actions::ANNOUNCE};
      claims.addScope(publish_actions,
                      MoqtBinaryMatch::exact("publisher.example"),
                      MoqtBinaryMatch::prefix("/live"));

      // Subscriber scope
      std::array subscribe_actions = {moqt_actions::SUBSCRIBE,
                                      moqt_actions::FETCH};
      claims.addScope(subscribe_actions, MoqtBinaryMatch::prefix("content"),
                      MoqtBinaryMatch::any());

      // Valid publish operations
      CHECK(claims.isAuthorized(moqt_actions::PUBLISH, "publisher.example",
                                "/live/stream1"));
      CHECK(claims.isAuthorized(moqt_actions::ANNOUNCE, "publisher.example",
                                "/live"));

      // Valid subscribe operations
      CHECK(claims.isAuthorized(moqt_actions::SUBSCRIBE, "content.example",
                                "/any/track"));
      CHECK(claims.isAuthorized(moqt_actions::FETCH, "content.media",
                                "/video123"));

      // Invalid operations
      CHECK_FALSE(claims.isAuthorized(moqt_actions::SUBSCRIBE,
                                      "publisher.example", "/live/stream1"));
      CHECK_FALSE(claims.isAuthorized(moqt_actions::PUBLISH, "other.com",
                                      "/live/stream1"));
      CHECK_FALSE(claims.isAuthorized(
          moqt_actions::PUBLISH, "publisher.example", "/recorded/stream1"));
    }

    SUBCASE("Compile-Time Scope Addition") {
      auto claims = MoqtClaims::create();

      claims.template addCompileTimeScope<moqt_actions::PUBLISH,
                                          moqt_actions::ANNOUNCE>(
          MoqtBinaryMatch::exact("test.example"),
          MoqtBinaryMatch::prefix("/ct"));

      CHECK(claims.getScopeCount() == 1);
      CHECK(claims.isAuthorized(moqt_actions::PUBLISH, "test.example",
                                "/ct/stream"));
      CHECK(claims.isAuthorized(moqt_actions::ANNOUNCE, "test.example", "/ct"));
      CHECK_FALSE(claims.isAuthorized(moqt_actions::SUBSCRIBE, "test.example",
                                      "/ct/stream"));
    }

    SUBCASE("Revalidation Interval") {
      auto claims = MoqtClaims::create();

      CHECK_FALSE(claims.getRevalidationInterval().has_value());

      claims.setRevalidationInterval(300s);

      CHECK(claims.getRevalidationInterval().has_value());
      CHECK(claims.getRevalidationInterval().value() == 300s);
      CHECK(claims.getRevalidationIntervalSeconds().value() == 300);

      CHECK_THROWS_AS(claims.setRevalidationInterval(std::chrono::seconds{0}),
                      InvalidClaimValueError);
      CHECK_THROWS_AS(claims.setRevalidationInterval(std::chrono::seconds{-10}),
                      InvalidClaimValueError);
    }
  }

  TEST_CASE("Compound Match Tests") {
    SUBCASE("Single condition behaves like MoqtBinaryMatch") {
      auto match = MoqtCompoundMatch::single(MoqtBinaryMatch::prefix("/live"));

      CHECK(match.matches("/live/stream1"));
      CHECK(match.matches("/live"));
      CHECK_FALSE(match.matches("/recorded/stream1"));
      CHECK_FALSE(match.is_empty());
      CHECK(match.size() == 1);
    }

    SUBCASE("Any matches everything") {
      auto match = MoqtCompoundMatch::any();

      CHECK(match.is_empty());
      CHECK(match.matches("anything"));
      CHECK(match.matches(""));
    }

    SUBCASE("AND semantics: prefix AND suffix") {
      auto match = MoqtCompoundMatch::all({
          MoqtBinaryMatch::prefix("/live"),
          MoqtBinaryMatch::suffix(".mp4"),
      });

      CHECK(match.matches("/live/stream.mp4"));
      CHECK(match.matches("/live.mp4"));
      CHECK_FALSE(match.matches("/live/stream.webm"));
      CHECK_FALSE(match.matches("/recorded/stream.mp4"));
      CHECK(match.size() == 2);
    }

    SUBCASE("AND semantics: prefix AND contains") {
      auto match = MoqtCompoundMatch::all({
          MoqtBinaryMatch::prefix("streaming."),
          MoqtBinaryMatch::contains("live"),
      });

      CHECK(match.matches("streaming.live.example"));
      CHECK(match.matches("streaming.example.live"));
      CHECK_FALSE(match.matches("streaming.example.vod"));
      CHECK_FALSE(match.matches("other.live.example"));
    }

    SUBCASE("Three conditions: prefix AND suffix AND contains") {
      auto match = MoqtCompoundMatch::all({
          MoqtBinaryMatch::prefix("/media/"),
          MoqtBinaryMatch::suffix("/video"),
          MoqtBinaryMatch::contains("hd"),
      });

      CHECK(match.matches("/media/hd/video"));
      CHECK(match.matches("/media/content-hd-stream/video"));
      CHECK_FALSE(match.matches("/media/sd/video"));
      CHECK_FALSE(match.matches("/media/hd/audio"));
      CHECK_FALSE(match.matches("/other/hd/video"));
    }

    SUBCASE("Empty conditions filtered out") {
      auto match = MoqtCompoundMatch::all({
          MoqtBinaryMatch::any(),
          MoqtBinaryMatch::prefix("/live"),
      });

      CHECK(match.size() == 1);
      CHECK(match.matches("/live/stream"));
      CHECK_FALSE(match.matches("/vod/stream"));
    }
  }

  TEST_CASE("Compound Match in Scope Authorization") {
    SUBCASE("Scope with compound namespace match") {
      std::array actions = {moqt_actions::PUBLISH};
      auto ns = MoqtCompoundMatch::all({
          MoqtBinaryMatch::prefix("streaming."),
          MoqtBinaryMatch::suffix(".example"),
      });
      auto tr = MoqtCompoundMatch::single(MoqtBinaryMatch::prefix("/live"));

      auto scope = MoqtActionScope::create(actions, ns, tr);

      CHECK(scope.authorizes(moqt_actions::PUBLISH, "streaming.media.example",
                             "/live/s1"));
      CHECK_FALSE(scope.authorizes(moqt_actions::PUBLISH,
                                   "streaming.media.other", "/live/s1"));
      CHECK_FALSE(scope.authorizes(moqt_actions::PUBLISH, "other.media.example",
                                   "/live/s1"));
    }

    SUBCASE("Scope with compound track match") {
      std::array actions = {moqt_actions::SUBSCRIBE, moqt_actions::FETCH};
      auto ns =
          MoqtCompoundMatch::single(MoqtBinaryMatch::exact("cdn.example"));
      auto tr = MoqtCompoundMatch::all({
          MoqtBinaryMatch::prefix("/video/"),
          MoqtBinaryMatch::suffix(".mp4"),
      });

      auto scope = MoqtActionScope::create(actions, ns, tr);

      CHECK(scope.authorizes(moqt_actions::SUBSCRIBE, "cdn.example",
                             "/video/clip.mp4"));
      CHECK_FALSE(scope.authorizes(moqt_actions::SUBSCRIBE, "cdn.example",
                                   "/video/clip.webm"));
      CHECK_FALSE(scope.authorizes(moqt_actions::SUBSCRIBE, "cdn.example",
                                   "/audio/clip.mp4"));
    }

    SUBCASE("Claims with compound matches - OR across scopes") {
      auto claims = MoqtClaims::create();

      std::array pub_actions = {moqt_actions::PUBLISH};
      claims.addScope(
          pub_actions,
          MoqtCompoundMatch::all({
              MoqtBinaryMatch::prefix("live."),
              MoqtBinaryMatch::suffix(".tv"),
          }),
          MoqtCompoundMatch::single(MoqtBinaryMatch::prefix("/hd")));

      std::array sub_actions = {moqt_actions::SUBSCRIBE};
      claims.addScope(
          sub_actions,
          MoqtCompoundMatch::single(MoqtBinaryMatch::exact("vod.example")),
          MoqtCompoundMatch::all({
              MoqtBinaryMatch::prefix("/catalog/"),
              MoqtBinaryMatch::contains("2024"),
          }));

      CHECK(claims.isAuthorized(moqt_actions::PUBLISH, "live.sports.tv",
                                "/hd/stream1"));
      CHECK_FALSE(claims.isAuthorized(moqt_actions::PUBLISH, "live.sports.com",
                                      "/hd/stream1"));
      CHECK(claims.isAuthorized(moqt_actions::SUBSCRIBE, "vod.example",
                                "/catalog/2024-best"));
      CHECK_FALSE(claims.isAuthorized(moqt_actions::SUBSCRIBE, "vod.example",
                                      "/catalog/2023-best"));
    }
  }

}  // TEST_SUITE("MOQT Claims Tests")

TEST_SUITE("Integration Tests") {
  TEST_CASE("CatToken with MOQT Claims") {
    SUBCASE("Builder Pattern") {
      auto token = CatToken()
                       .withIssuer("https://streaming.example")
                       .withAudience({"relay.example"})
                       .withExpiration(std::chrono::system_clock::now() + 1h)
                       .withVersion(1)
                       .withMoqtRevalidationInterval(300s);

      // Add MOQT scope using template method
      std::array actions = {moqt_actions::PUBLISH, moqt_actions::ANNOUNCE};
      token.withMoqtActionsDynamic(actions,
                                   MoqtBinaryMatch::exact("streaming.example"),
                                   MoqtBinaryMatch::prefix("/live"));

      const auto* moqt_claims = token.extended.getMoqtClaimsReadOnly();
      REQUIRE(moqt_claims != nullptr);

      CHECK(moqt_claims->getScopeCount() == 1);
      CHECK(moqt_claims->getRevalidationIntervalSeconds().value() == 300);
      CHECK(moqt_claims->isAuthorized(moqt_actions::PUBLISH,
                                      "streaming.example", "/live/stream1"));
    }

    SUBCASE("Compile-Time Scope") {
      auto token = CatToken().withIssuer("https://publisher.example");

      // Use compile-time scope addition
      token.template withMoqtActions<moqt_actions::PUBLISH,
                                     moqt_actions::ANNOUNCE>(
          MoqtBinaryMatch::exact("publisher.example"),
          MoqtBinaryMatch::prefix("/ct"));

      const auto* moqt_claims = token.extended.getMoqtClaimsReadOnly();
      REQUIRE(moqt_claims != nullptr);

      CHECK(moqt_claims->isAuthorized(moqt_actions::PUBLISH,
                                      "publisher.example", "/ct/stream"));
      CHECK(moqt_claims->isAuthorized(moqt_actions::ANNOUNCE,
                                      "publisher.example", "/ct"));
      CHECK_FALSE(moqt_claims->isAuthorized(moqt_actions::SUBSCRIBE,
                                            "publisher.example", "/ct"));
    }
  }

  TEST_CASE("Real-World Scenarios") {
    SUBCASE("Multi-Role Token") {
      auto token = CatToken()
                       .withIssuer("https://media-platform.example")
                       .withAudience({"media-relay.example"})
                       .withExpiration(std::chrono::system_clock::now() + 24h);

      // Publisher role
      std::array publisher_actions = {moqt_actions::ANNOUNCE,
                                      moqt_actions::PUBLISH};
      token.withMoqtActionsDynamic(
          publisher_actions,
          MoqtBinaryMatch::exact("publisher.media-platform.example"),
          MoqtBinaryMatch::prefix("/live"));

      // Subscriber role
      std::array subscriber_actions = {moqt_actions::SUBSCRIBE,
                                       moqt_actions::FETCH};
      token.withMoqtActionsDynamic(subscriber_actions,
                                   MoqtBinaryMatch::suffix(".live"),
                                   MoqtBinaryMatch::any());

      const auto* moqt_claims = token.extended.getMoqtClaimsReadOnly();
      REQUIRE(moqt_claims != nullptr);

      CHECK(moqt_claims->getScopeCount() == 2);

      // Test publisher permissions
      CHECK(moqt_claims->isAuthorized(moqt_actions::PUBLISH,
                                      "publisher.media-platform.example",
                                      "/live/stream1"));
      CHECK(moqt_claims->isAuthorized(
          moqt_actions::ANNOUNCE, "publisher.media-platform.example", "/live"));

      // Test subscriber permissions
      CHECK(moqt_claims->isAuthorized(moqt_actions::SUBSCRIBE, "sports.live",
                                      "/game123"));
      CHECK(moqt_claims->isAuthorized(moqt_actions::FETCH, "news.live",
                                      "/breaking"));

      // Test denied permissions
      CHECK_FALSE(moqt_claims->isAuthorized(moqt_actions::SUBSCRIBE,
                                            "publisher.media-platform.example",
                                            "/live/stream1"));
      CHECK_FALSE(moqt_claims->isAuthorized(moqt_actions::PUBLISH, "other.com",
                                            "/live"));
    }
  }

}  // TEST_SUITE("Integration Tests")

namespace {

// The libcbor DOM builders return `bool` and are marked warn_unused_result;
// in fixture code the containers are pre-sized so failure is a programming
// error. Assert instead of silently dropping the return value.
void must_push(cbor_item_t* array, cbor_item_t* pushee) {
  REQUIRE(cbor_array_push(array, pushee));
}
void must_add(cbor_item_t* map, cbor_pair pair) {
  REQUIRE(cbor_map_add(map, pair));
}

// Build a minimal CWT payload map { 1: "iss", 3: "aud", CLAIM_MOQT: <moqt> }
// so we can hand `Cwt::decodePayload` a well-formed token that only differs
// in the shape of the `moqt` claim under test.
std::vector<uint8_t> serialize_item_owned(cbor_item_t* root) {
  unsigned char* buf = nullptr;
  size_t buf_size = 0;
  size_t len = cbor_serialize_alloc(root, &buf, &buf_size);
  std::vector<uint8_t> out(buf, buf + len);
  free(buf);
  return out;
}

std::vector<uint8_t> wrap_moqt_claim_bytes(cbor_item_t* moqt_value_owned) {
  cbor_item_t* map = cbor_new_definite_map(3);

  cbor_item_t* iss_key = cbor_build_uint8(1);
  cbor_item_t* iss_val = cbor_build_string("issuer");
  must_add(map,
           cbor_pair{.key = cbor_move(iss_key), .value = cbor_move(iss_val)});

  // `aud` claim (label 3) is an array of text strings.
  cbor_item_t* aud_key = cbor_build_uint8(3);
  cbor_item_t* aud_arr = cbor_new_definite_array(1);
  must_push(aud_arr, cbor_move(cbor_build_string("aud")));
  must_add(map,
           cbor_pair{.key = cbor_move(aud_key), .value = cbor_move(aud_arr)});

  // CLAIM_MOQT = 65000 fits in 2 bytes; use uint16 so the fixture is
  // shortest-form and passes loadStrict's RFC 8949 §4.2.1 check.
  static_assert(catapult::CLAIM_MOQT <= 0xFFFF,
                "CLAIM_MOQT must fit in a CBOR uint16 for this fixture");
  cbor_item_t* moqt_key = cbor_build_uint16(
      static_cast<uint16_t>(catapult::CLAIM_MOQT));
  must_add(map, cbor_pair{.key = cbor_move(moqt_key),
                          .value = cbor_move(moqt_value_owned)});

  auto out = serialize_item_owned(map);
  cbor_decref(&map);
  return out;
}

// scope = [ [action], [ <bin_match> ] ] — namespace list carrying one entry.
cbor_item_t* build_scope_with_ns_match(int action, cbor_item_t* bin_match_owned) {
  cbor_item_t* scope = cbor_new_definite_array(2);
  cbor_item_t* actions = cbor_new_definite_array(1);
  must_push(actions,
            cbor_move(cbor_build_uint8(static_cast<uint8_t>(action))));
  must_push(scope, cbor_move(actions));

  cbor_item_t* ns_list = cbor_new_definite_array(1);
  must_push(ns_list, cbor_move(bin_match_owned));
  must_push(scope, cbor_move(ns_list));

  return scope;
}

}  // namespace

TEST_SUITE("MOQT wire-format hardening") {
  TEST_CASE("Decoder rejects nil in bin-match position (fail-closed)") {
    // A `nil` in the bin-match list has a specific "exact zero-length"
    // meaning in the current CAT-4-MOQT draft. The internal model cannot
    // yet represent that distinctly from "wildcard", so admitting it as
    // "any" would silently widen authorization to every namespace. We
    // must fail closed.
    cbor_item_t* moqt_arr = cbor_new_definite_array(1);
    must_push(moqt_arr,
              cbor_move(build_scope_with_ns_match(
                  catapult::moqt_actions::PUBLISH, cbor_new_null())));

    auto payload = wrap_moqt_claim_bytes(moqt_arr);
    CHECK_THROWS_AS(catapult::Cwt::decodePayload(payload),
                    catapult::InvalidClaimValueError);
  }

  TEST_CASE("Decoder rejects CONTAINS (type 3) as an unsupported extension") {
    // Type 3 (contains) is not part of the CAT-4-MOQT bin-match CDDL.
    // Accepting an unknown extension would let an issuer smuggle in a
    // broader authorization by relabelling a scope entry.
    cbor_item_t* tuple = cbor_new_definite_array(2);
    must_push(tuple, cbor_move(cbor_build_uint8(3)));  // type=CONTAINS
    must_push(tuple, cbor_move(cbor_build_bytestring(
                         reinterpret_cast<const unsigned char*>("live"), 4)));

    cbor_item_t* moqt_arr = cbor_new_definite_array(1);
    must_push(moqt_arr, cbor_move(build_scope_with_ns_match(
                            catapult::moqt_actions::PUBLISH, tuple)));

    auto payload = wrap_moqt_claim_bytes(moqt_arr);
    CHECK_THROWS_AS(catapult::Cwt::decodePayload(payload),
                    catapult::InvalidClaimValueError);
  }

  TEST_CASE("Decoder accepts type 0 (exact), 1 (prefix), 2 (suffix)") {
    // Sanity check that the negative fixtures above aren't rejecting the
    // shape for reasons unrelated to the type discriminator.
    for (uint8_t match_type : {uint8_t{0}, uint8_t{1}, uint8_t{2}}) {
      cbor_item_t* tuple = cbor_new_definite_array(2);
      must_push(tuple, cbor_move(cbor_build_uint8(match_type)));
      must_push(tuple, cbor_move(cbor_build_bytestring(
                           reinterpret_cast<const unsigned char*>("ns"), 2)));

      cbor_item_t* moqt_arr = cbor_new_definite_array(1);
      must_push(moqt_arr, cbor_move(build_scope_with_ns_match(
                              catapult::moqt_actions::PUBLISH, tuple)));

      auto payload = wrap_moqt_claim_bytes(moqt_arr);
      CHECK_NOTHROW(catapult::Cwt::decodePayload(payload));
    }
  }

  TEST_CASE("Encoder refuses to emit a CONTAINS bin-match") {
    // The encoder must not produce a wire form the decoder is required
    // to reject; otherwise a well-intentioned issuer could ship
    // tokens that no relay could parse.
    auto token =
        catapult::CatToken()
            .withIssuer("issuer")
            .withAudience({"aud"})
            .withMoqtActionsDynamic(
                std::array{catapult::moqt_actions::PUBLISH},
                catapult::MoqtBinaryMatch::contains("live"),
                catapult::MoqtBinaryMatch::any());

    catapult::Cwt cwt(catapult::ALG_ES256, token);
    // The encoder wraps semantic failures raised by claim builders into
    // an InvalidCborError. Assert the outer error type rather than the
    // inner InvalidClaimValueError.
    CHECK_THROWS_AS(cwt.encodePayload(), catapult::InvalidCborError);
  }
}

// CAT-4-MOQT (draft-ietf-moq-c4m-01) profile round-trip vectors.
//
// Each subcase constructs a token carrying a MOQT scope shape drawn from
// the draft's example set, encodes it via catapult's public API, decodes
// the resulting bytes back, and asserts both structural preservation
// (scope count, action set) and authorization equivalence (positive AND
// negative outcomes). The suite exists to lock the wire-form profile: a
// future refactor that quietly changes how "wildcard track" or "AND
// namespace conditions" are serialised will flip these round-trips and
// fail loudly rather than silently drift out of interop.
TEST_SUITE("MOQT profile round-trip vectors") {
  // Encode → decode → check authorization equivalence for a single scope
  // shape. Deliberately does NOT compare byte-for-byte hex against a
  // pre-computed vector — the tokens are unsigned raw payloads whose
  // shape catapult owns end-to-end, and asserting semantic equivalence
  // catches encoder regressions without pinning the byte layout of
  // implementation details (e.g. shortest-form int encoding rules on
  // action ids). Byte-form is anchored separately by
  // tests/test_vectors_c4m.cpp against the PR#47 draft vectors.
  auto roundtrip = [](const catapult::CatToken& token) {
    catapult::Cwt cwt(catapult::ALG_HMAC256_256, token);
    auto payload = cwt.encodePayload();
    return catapult::Cwt::decodePayload(payload);
  };

  TEST_CASE("publisher: exact-namespace + prefix-track") {
    // draft §Publisher example: PUBLISH_NAMESPACE + PUBLISH allowed on the
    // exact namespace "example.com" with any track starting with "video-".
    auto tok =
        catapult::CatToken()
            .withIssuer("https://auth.example.com")
            .withAudience({"https://relay.example.com"})
            .withMoqtActionsDynamic(
                std::array{catapult::moqt_actions::PUBLISH_NAMESPACE,
                           catapult::moqt_actions::PUBLISH},
                catapult::MoqtBinaryMatch::exact("example.com"),
                catapult::MoqtBinaryMatch::prefix("video-"));

    auto decoded = roundtrip(tok);
    const auto* moqt = decoded.extended.getMoqtClaimsReadOnly();
    REQUIRE(moqt != nullptr);
    REQUIRE(moqt->getScopeCount() == 1);

    CHECK(moqt->isAuthorized(catapult::moqt_actions::PUBLISH, "example.com",
                             "video-hd"));
    CHECK(moqt->isAuthorized(catapult::moqt_actions::PUBLISH_NAMESPACE,
                             "example.com", "video-sd"));
    // Wrong action → deny.
    CHECK_FALSE(moqt->isAuthorized(catapult::moqt_actions::SUBSCRIBE,
                                   "example.com", "video-hd"));
    // Right action, wrong namespace → deny.
    CHECK_FALSE(moqt->isAuthorized(catapult::moqt_actions::PUBLISH,
                                   "other.example", "video-hd"));
    // Right action + namespace, wrong track prefix → deny.
    CHECK_FALSE(moqt->isAuthorized(catapult::moqt_actions::PUBLISH,
                                   "example.com", "audio-main"));
  }

  TEST_CASE("subscriber: prefix-namespace + wildcard-track") {
    // draft §Subscriber example: any track under any namespace prefixed
    // by "conference.example". Wildcard track is expressed as `any()`.
    auto tok =
        catapult::CatToken()
            .withIssuer("https://auth.example.com")
            .withAudience({"https://relay.example.com"})
            .withMoqtActionsDynamic(
                std::array{catapult::moqt_actions::SUBSCRIBE_NAMESPACE,
                           catapult::moqt_actions::SUBSCRIBE,
                           catapult::moqt_actions::FETCH},
                catapult::MoqtBinaryMatch::prefix("conference.example"),
                catapult::MoqtBinaryMatch::any());

    auto decoded = roundtrip(tok);
    const auto* moqt = decoded.extended.getMoqtClaimsReadOnly();
    REQUIRE(moqt != nullptr);
    REQUIRE(moqt->getScopeCount() == 1);

    // Any track under the allowed namespace prefix authorizes.
    CHECK(moqt->isAuthorized(catapult::moqt_actions::SUBSCRIBE,
                             "conference.example.room1", "audio"));
    CHECK(moqt->isAuthorized(catapult::moqt_actions::FETCH,
                             "conference.example.room42", ""));
    // Namespace that does not carry the prefix → deny even for allowed
    // action.
    CHECK_FALSE(moqt->isAuthorized(catapult::moqt_actions::SUBSCRIBE,
                                   "other.domain", "audio"));
    // Action not in the scope → deny.
    CHECK_FALSE(moqt->isAuthorized(catapult::moqt_actions::PUBLISH,
                                   "conference.example.room1", "audio"));
  }

  TEST_CASE("multi-scope: two scopes ORed, one publish + one subscribe") {
    // draft §multi_scope: publish only for exact namespaces
    // {"live.example","studio-a"}; subscribe for any namespace prefixed by
    // "live.example". Verifies OR-across-scopes semantics after encode +
    // decode round-trip.
    auto tok =
        catapult::CatToken()
            .withIssuer("https://auth.example.com")
            .withAudience({"https://relay.example.com"})
            .withMoqtActionsDynamic(
                std::array{catapult::moqt_actions::PUBLISH_NAMESPACE,
                           catapult::moqt_actions::PUBLISH},
                catapult::MoqtCompoundMatch::all({
                    catapult::MoqtBinaryMatch::exact("live.example"),
                    catapult::MoqtBinaryMatch::exact("studio-a"),
                }),
                catapult::MoqtCompoundMatch::any())
            .withMoqtActionsDynamic(
                std::array{catapult::moqt_actions::SUBSCRIBE,
                           catapult::moqt_actions::FETCH},
                catapult::MoqtCompoundMatch::single(
                    catapult::MoqtBinaryMatch::prefix("live.example")),
                catapult::MoqtCompoundMatch::any());

    auto decoded = roundtrip(tok);
    const auto* moqt = decoded.extended.getMoqtClaimsReadOnly();
    REQUIRE(moqt != nullptr);
    REQUIRE(moqt->getScopeCount() == 2);

    // The isAuthorized() API takes a single namespace string; the AND
    // conditions on the first scope both apply to that value. Only a
    // namespace that satisfies BOTH exact-"live.example" AND
    // exact-"studio-a" would authorize, which is impossible (a string
    // cannot equal two different values), so publish authorization
    // through this scope is unreachable — matches the draft's intent
    // that AND across exact conditions is a conjunction, not a union.
    CHECK_FALSE(moqt->isAuthorized(catapult::moqt_actions::PUBLISH,
                                   "live.example", "cam1"));
    CHECK_FALSE(moqt->isAuthorized(catapult::moqt_actions::PUBLISH,
                                   "studio-a", "cam1"));
    // Subscribe scope: any namespace prefixed by "live.example" is fine.
    CHECK(moqt->isAuthorized(catapult::moqt_actions::SUBSCRIBE,
                             "live.example.studio-b", "cam1"));
    CHECK(moqt->isAuthorized(catapult::moqt_actions::FETCH, "live.example",
                             "cam1"));
    // Subscribe against a namespace outside the prefix → deny.
    CHECK_FALSE(moqt->isAuthorized(catapult::moqt_actions::SUBSCRIBE,
                                   "recorded.example", "cam1"));
  }

  TEST_CASE("admin: all actions + wildcard namespace + wildcard track") {
    // The wildcard-everywhere shape must survive round-trip. Every valid
    // action must authorize regardless of namespace or track. This is the
    // shape a fully privileged operator token takes.
    std::array all_actions = {catapult::moqt_actions::CLIENT_SETUP,
                              catapult::moqt_actions::SERVER_SETUP,
                              catapult::moqt_actions::PUBLISH_NAMESPACE,
                              catapult::moqt_actions::SUBSCRIBE_NAMESPACE,
                              catapult::moqt_actions::SUBSCRIBE,
                              catapult::moqt_actions::REQUEST_UPDATE,
                              catapult::moqt_actions::PUBLISH,
                              catapult::moqt_actions::FETCH,
                              catapult::moqt_actions::TRACK_STATUS};
    auto tok = catapult::CatToken()
                   .withIssuer("https://auth.example.com")
                   .withAudience({"https://relay.example.com"})
                   .withMoqtActionsDynamic(all_actions,
                                           catapult::MoqtBinaryMatch::any(),
                                           catapult::MoqtBinaryMatch::any());

    auto decoded = roundtrip(tok);
    const auto* moqt = decoded.extended.getMoqtClaimsReadOnly();
    REQUIRE(moqt != nullptr);
    REQUIRE(moqt->getScopeCount() == 1);

    for (int action : all_actions) {
      CAPTURE(action);
      CHECK(moqt->isAuthorized(action, "any.namespace", "any-track"));
    }
    // Unknown action id → deny regardless of wildcard shape.
    CHECK_FALSE(moqt->isAuthorized(99, "any.namespace", "any-track"));
  }

  TEST_CASE("suffix on both namespace and track") {
    // draft §suffix example: subscribe to any namespace ending with
    // ".example.com" on any track ending with "-audio".
    auto tok = catapult::CatToken()
                   .withIssuer("https://auth.example.com")
                   .withAudience({"https://relay.example.com"})
                   .withMoqtActionsDynamic(
                       std::array{catapult::moqt_actions::SUBSCRIBE},
                       catapult::MoqtBinaryMatch::suffix(".example.com"),
                       catapult::MoqtBinaryMatch::suffix("-audio"));

    auto decoded = roundtrip(tok);
    const auto* moqt = decoded.extended.getMoqtClaimsReadOnly();
    REQUIRE(moqt != nullptr);
    REQUIRE(moqt->getScopeCount() == 1);

    CHECK(moqt->isAuthorized(catapult::moqt_actions::SUBSCRIBE,
                             "cdn.example.com", "stream1-audio"));
    CHECK_FALSE(moqt->isAuthorized(catapult::moqt_actions::SUBSCRIBE,
                                   "cdn.example.com", "stream1-video"));
    CHECK_FALSE(moqt->isAuthorized(catapult::moqt_actions::SUBSCRIBE,
                                   "cdn.other.org", "stream1-audio"));
  }

  TEST_CASE("exact('') matches only the empty namespace, not wildcard") {
    // Regression for L-08: encode a scope whose namespace match is
    // exact(""), round-trip, and confirm that only the empty namespace
    // string authorises. Pre-fix this would authorise every namespace
    // because `is_empty()` on the match short-circuited to wildcard.
    auto tok = catapult::CatToken()
                   .withIssuer("https://auth.example.com")
                   .withAudience({"https://relay.example.com"})
                   .withMoqtActionsDynamic(
                       std::array{catapult::moqt_actions::SUBSCRIBE},
                       catapult::MoqtBinaryMatch::exact(""),
                       catapult::MoqtBinaryMatch::any());

    catapult::Cwt cwt(catapult::ALG_HMAC256_256, tok);
    auto payload = cwt.encodePayload();
    auto decoded = catapult::Cwt::decodePayload(payload);
    const auto* moqt = decoded.extended.getMoqtClaimsReadOnly();
    REQUIRE(moqt != nullptr);
    REQUIRE(moqt->getScopeCount() == 1);

    CHECK(moqt->isAuthorized(catapult::moqt_actions::SUBSCRIBE, "",
                             "any-track"));
    CHECK_FALSE(moqt->isAuthorized(catapult::moqt_actions::SUBSCRIBE,
                                   "example.com", "any-track"));
    CHECK_FALSE(moqt->isAuthorized(catapult::moqt_actions::SUBSCRIBE,
                                   "anything", "any-track"));
  }

  TEST_CASE("revalidation interval survives round-trip alongside scopes") {
    // `moqt-reval` (label 65001) travels as a separate top-level uint
    // claim, but is semantically bound to the presence of `moqt`. A
    // round-trip must preserve both, and the pair must remain paired.
    auto tok = catapult::CatToken()
                   .withIssuer("https://auth.example.com")
                   .withAudience({"https://relay.example.com"})
                   .withMoqtActionsDynamic(
                       std::array{catapult::moqt_actions::SUBSCRIBE},
                       catapult::MoqtBinaryMatch::prefix("live."),
                       catapult::MoqtBinaryMatch::any())
                   .withMoqtRevalidationInterval(std::chrono::seconds{300});

    auto decoded = roundtrip(tok);
    const auto* moqt = decoded.extended.getMoqtClaimsReadOnly();
    REQUIRE(moqt != nullptr);
    REQUIRE(moqt->getRevalidationInterval().has_value());
    CHECK(moqt->getRevalidationInterval()->count() == 300);
  }
}

// Positive wire-form vectors: the decoder must accept every shape the
// CAT-4-MOQT profile permits. These pair with the negative-form asserts
// in "MOQT wire-format hardening" above so the accepted/rejected
// boundary is documented from both directions.
TEST_SUITE("MOQT wire-format positive vectors") {
  TEST_CASE("Decoder accepts scope with only an action list") {
    // Minimal-permissible scope: no namespace/track array at all. Every
    // action authorizes for every resource — the wildcard shape at the
    // lowest CBOR expression.
    cbor_item_t* scope = cbor_new_definite_array(1);
    cbor_item_t* actions = cbor_new_definite_array(1);
    must_push(actions, cbor_move(cbor_build_uint8(
                           catapult::moqt_actions::TRACK_STATUS)));
    must_push(scope, cbor_move(actions));

    cbor_item_t* moqt_arr = cbor_new_definite_array(1);
    must_push(moqt_arr, cbor_move(scope));

    auto payload = wrap_moqt_claim_bytes(moqt_arr);
    catapult::CatToken tok;
    CHECK_NOTHROW(tok = catapult::Cwt::decodePayload(payload));
    const auto* moqt = tok.extended.getMoqtClaimsReadOnly();
    REQUIRE(moqt != nullptr);
    CHECK(moqt->isAuthorized(catapult::moqt_actions::TRACK_STATUS,
                             "anywhere", "any"));
  }

  TEST_CASE("Decoder accepts scope with actions + ns + null track") {
    // Null in a track slot expresses "any track" — distinct from a null
    // element inside a namespace match list, which is fail-closed. This
    // reads as "no track restriction" and must decode without widening
    // the namespace side.
    cbor_item_t* scope = cbor_new_definite_array(3);
    cbor_item_t* actions = cbor_new_definite_array(1);
    must_push(actions,
              cbor_move(cbor_build_uint8(catapult::moqt_actions::SUBSCRIBE)));
    must_push(scope, cbor_move(actions));

    cbor_item_t* ns_list = cbor_new_definite_array(1);
    must_push(ns_list, cbor_move(cbor_build_bytestring(
                           reinterpret_cast<const unsigned char*>("live."), 5)));
    must_push(scope, cbor_move(ns_list));
    must_push(scope, cbor_move(cbor_new_null()));

    cbor_item_t* moqt_arr = cbor_new_definite_array(1);
    must_push(moqt_arr, cbor_move(scope));

    auto payload = wrap_moqt_claim_bytes(moqt_arr);
    catapult::CatToken tok;
    CHECK_NOTHROW(tok = catapult::Cwt::decodePayload(payload));
    const auto* moqt = tok.extended.getMoqtClaimsReadOnly();
    REQUIRE(moqt != nullptr);
    // Namespace-match-only path: exact bytestring form authorises only
    // the exact namespace, any track.
    CHECK(moqt->isAuthorized(catapult::moqt_actions::SUBSCRIBE, "live.",
                             "any-track"));
    CHECK_FALSE(moqt->isAuthorized(catapult::moqt_actions::SUBSCRIBE, "vod.",
                                   "any-track"));
  }

  TEST_CASE("Decoder accepts bare bytestring in the track slot") {
    // The track slot admits a bare bytestring as shorthand for the exact
    // match form, per the encoder's own emission (see cwt.cpp
    // buildMoqtClaimItem: single-condition track_match with EXACT
    // pattern is serialised bare). The decoder must accept it.
    cbor_item_t* scope = cbor_new_definite_array(3);
    cbor_item_t* actions = cbor_new_definite_array(1);
    must_push(actions,
              cbor_move(cbor_build_uint8(catapult::moqt_actions::SUBSCRIBE)));
    must_push(scope, cbor_move(actions));

    cbor_item_t* ns_list = cbor_new_definite_array(1);
    must_push(ns_list, cbor_move(cbor_build_bytestring(
                           reinterpret_cast<const unsigned char*>("ns"), 2)));
    must_push(scope, cbor_move(ns_list));
    must_push(scope, cbor_move(cbor_build_bytestring(
                         reinterpret_cast<const unsigned char*>("track"), 5)));

    cbor_item_t* moqt_arr = cbor_new_definite_array(1);
    must_push(moqt_arr, cbor_move(scope));

    auto payload = wrap_moqt_claim_bytes(moqt_arr);
    catapult::CatToken tok;
    CHECK_NOTHROW(tok = catapult::Cwt::decodePayload(payload));
    const auto* moqt = tok.extended.getMoqtClaimsReadOnly();
    REQUIRE(moqt != nullptr);
    CHECK(moqt->isAuthorized(catapult::moqt_actions::SUBSCRIBE, "ns", "track"));
    CHECK_FALSE(moqt->isAuthorized(catapult::moqt_actions::SUBSCRIBE, "ns",
                                   "other"));
  }

  TEST_CASE("Decoder accepts two-condition track match list") {
    // Compound track match with two conditions is emitted as an
    // array-of-arrays: [ [type,pat], [type,pat] ]. Verify decode.
    cbor_item_t* prefix_tuple = cbor_new_definite_array(2);
    must_push(prefix_tuple, cbor_move(cbor_build_uint8(1)));  // prefix
    must_push(prefix_tuple, cbor_move(cbor_build_bytestring(
                                reinterpret_cast<const unsigned char*>("/hd/"),
                                4)));
    cbor_item_t* suffix_tuple = cbor_new_definite_array(2);
    must_push(suffix_tuple, cbor_move(cbor_build_uint8(2)));  // suffix
    must_push(suffix_tuple, cbor_move(cbor_build_bytestring(
                                reinterpret_cast<const unsigned char*>(".mp4"),
                                4)));

    cbor_item_t* scope = cbor_new_definite_array(3);
    cbor_item_t* actions = cbor_new_definite_array(1);
    must_push(actions,
              cbor_move(cbor_build_uint8(catapult::moqt_actions::FETCH)));
    must_push(scope, cbor_move(actions));

    cbor_item_t* ns_list = cbor_new_definite_array(1);
    must_push(ns_list, cbor_move(cbor_build_bytestring(
                           reinterpret_cast<const unsigned char*>("cdn"), 3)));
    must_push(scope, cbor_move(ns_list));

    cbor_item_t* tr_list = cbor_new_definite_array(2);
    must_push(tr_list, cbor_move(prefix_tuple));
    must_push(tr_list, cbor_move(suffix_tuple));
    must_push(scope, cbor_move(tr_list));

    cbor_item_t* moqt_arr = cbor_new_definite_array(1);
    must_push(moqt_arr, cbor_move(scope));

    auto payload = wrap_moqt_claim_bytes(moqt_arr);
    catapult::CatToken tok;
    CHECK_NOTHROW(tok = catapult::Cwt::decodePayload(payload));
    const auto* moqt = tok.extended.getMoqtClaimsReadOnly();
    REQUIRE(moqt != nullptr);
    // Compound AND across track: must start with /hd/ AND end with .mp4.
    CHECK(moqt->isAuthorized(catapult::moqt_actions::FETCH, "cdn",
                             "/hd/movie.mp4"));
    CHECK_FALSE(moqt->isAuthorized(catapult::moqt_actions::FETCH, "cdn",
                                   "/hd/movie.webm"));
    CHECK_FALSE(moqt->isAuthorized(catapult::moqt_actions::FETCH, "cdn",
                                   "/sd/movie.mp4"));
  }
}