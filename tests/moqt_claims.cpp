/**
 * @file test_moqt_claims.cpp
 * @brief Comprehensive unit tests for MOQT claims functionality
 */

#include <doctest/doctest.h>

#include "catapult/moqt_claims.hpp"
#include "catapult/token.hpp"
#include "catapult/dpop.hpp"

#include <chrono>
#include <string_view>
#include <array>
#include <ranges>

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
        auto match = MoqtBinaryMatch{};
        
        CHECK(match.is_empty());
        CHECK(match.matches("anything"));
        CHECK(match.matches(""));
        CHECK(match.matches("example.com"));
    }
}

TEST_CASE("MOQT Action Scope Tests") {
    SUBCASE("Basic Scope Creation") {
        std::array actions = {moqt_actions::PUBLISH, moqt_actions::ANNOUNCE};
        auto namespace_match = MoqtBinaryMatch::exact("example.com");
        auto track_match = MoqtBinaryMatch::prefix("/live");
        
        auto scope = MoqtActionScope::create(actions, namespace_match, track_match);
        
        CHECK(scope.action_count() == 2);
        CHECK(scope.contains_action(moqt_actions::PUBLISH));
        CHECK(scope.contains_action(moqt_actions::ANNOUNCE));
        CHECK_FALSE(scope.contains_action(moqt_actions::SUBSCRIBE));
    }
    
    SUBCASE("Authorization Tests") {
        std::array actions = {moqt_actions::PUBLISH, moqt_actions::FETCH};
        auto namespace_match = MoqtBinaryMatch::exact("streaming.example");
        auto track_match = MoqtBinaryMatch::prefix("/live");
        
        auto scope = MoqtActionScope::create(actions, namespace_match, track_match);
        
        // Valid authorizations
        CHECK(scope.authorizes(moqt_actions::PUBLISH, "streaming.example", "/live/stream1"));
        CHECK(scope.authorizes(moqt_actions::FETCH, "streaming.example", "/live/stream2"));
        CHECK(scope.authorizes(moqt_actions::PUBLISH, "streaming.example", "/live"));
        
        // Invalid authorizations
        CHECK_FALSE(scope.authorizes(moqt_actions::SUBSCRIBE, "streaming.example", "/live/stream1"));
        CHECK_FALSE(scope.authorizes(moqt_actions::PUBLISH, "other.example", "/live/stream1"));
        CHECK_FALSE(scope.authorizes(moqt_actions::PUBLISH, "streaming.example", "/recorded/stream1"));
    }
    
    SUBCASE("Invalid Action Validation") {
        std::array invalid_actions = {-1, 10, 100};
        auto namespace_match = MoqtBinaryMatch::exact("test.com");
        auto track_match = MoqtBinaryMatch{};
        
        CHECK_THROWS_AS(MoqtActionScope::create(invalid_actions, namespace_match, track_match), 
                       InvalidClaimValueError);
    }
}

TEST_CASE("Compile-Time Action Set Tests") {
    SUBCASE("Basic Functionality") {
        constexpr auto action_set = CompileTimeActionSet<
            moqt_actions::PUBLISH, 
            moqt_actions::ANNOUNCE,
            moqt_actions::SUBSCRIBE
        >{};
        
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
        
        std::array publish_actions = {moqt_actions::PUBLISH, moqt_actions::ANNOUNCE};
        claims.addScope(publish_actions, 
                       MoqtBinaryMatch::exact("publisher.example"),
                       MoqtBinaryMatch::prefix("/live"));
        
        std::array subscribe_actions = {moqt_actions::SUBSCRIBE, moqt_actions::FETCH};
        claims.addScope(subscribe_actions,
                       MoqtBinaryMatch::suffix(".live"),
                       MoqtBinaryMatch{});
        
        CHECK(claims.getScopeCount() == 2);
        CHECK(claims.getTotalActionCount() == 4);
        CHECK_FALSE(claims.empty());
    }
    
    SUBCASE("Authorization Tests") {
        auto claims = MoqtClaims::create();
        
        // Publisher scope
        std::array publish_actions = {moqt_actions::PUBLISH, moqt_actions::ANNOUNCE};
        claims.addScope(publish_actions,
                       MoqtBinaryMatch::exact("publisher.example"),
                       MoqtBinaryMatch::prefix("/live"));
        
        // Subscriber scope
        std::array subscribe_actions = {moqt_actions::SUBSCRIBE, moqt_actions::FETCH};
        claims.addScope(subscribe_actions,
                       MoqtBinaryMatch::prefix("content"),
                       MoqtBinaryMatch{});
        
        // Valid publish operations
        CHECK(claims.isAuthorized(moqt_actions::PUBLISH, "publisher.example", "/live/stream1"));
        CHECK(claims.isAuthorized(moqt_actions::ANNOUNCE, "publisher.example", "/live"));
        
        // Valid subscribe operations
        CHECK(claims.isAuthorized(moqt_actions::SUBSCRIBE, "content.example", "/any/track"));
        CHECK(claims.isAuthorized(moqt_actions::FETCH, "content.media", "/video123"));
        
        // Invalid operations
        CHECK_FALSE(claims.isAuthorized(moqt_actions::SUBSCRIBE, "publisher.example", "/live/stream1"));
        CHECK_FALSE(claims.isAuthorized(moqt_actions::PUBLISH, "other.com", "/live/stream1"));
        CHECK_FALSE(claims.isAuthorized(moqt_actions::PUBLISH, "publisher.example", "/recorded/stream1"));
    }
    
    SUBCASE("Compile-Time Scope Addition") {
        auto claims = MoqtClaims::create();
        
        claims.template addCompileTimeScope<moqt_actions::PUBLISH, moqt_actions::ANNOUNCE>(
            MoqtBinaryMatch::exact("test.example"),
            MoqtBinaryMatch::prefix("/ct")
        );
        
        CHECK(claims.getScopeCount() == 1);
        CHECK(claims.isAuthorized(moqt_actions::PUBLISH, "test.example", "/ct/stream"));
        CHECK(claims.isAuthorized(moqt_actions::ANNOUNCE, "test.example", "/ct"));
        CHECK_FALSE(claims.isAuthorized(moqt_actions::SUBSCRIBE, "test.example", "/ct/stream"));
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

TEST_CASE("Secure Binary Data Tests") {
    SUBCASE("Basic Functionality") {
        auto secure_data = SecureBinaryData("sensitive-key");
        
        CHECK(secure_data.size() == 13);
        
        // Test correct comparison
        std::vector<uint8_t> correct_key = {'s','e','n','s','i','t','i','v','e','-','k','e','y'};
        CHECK(secure_data.secure_compare(correct_key));
        
        // Test incorrect comparison
        std::vector<uint8_t> wrong_key = {'w','r','o','n','g','-','k','e','y'};
        CHECK_FALSE(secure_data.secure_compare(wrong_key));
        
        // Test different length
        std::vector<uint8_t> short_key = {'s','h','o','r','t'};
        CHECK_FALSE(secure_data.secure_compare(short_key));
    }
    
    SUBCASE("Move Semantics") {
        auto secure_data1 = SecureBinaryData("test-data");
        CHECK(secure_data1.size() == 9);
        
        auto secure_data2 = std::move(secure_data1);
        CHECK(secure_data2.size() == 9);
        CHECK(secure_data1.size() == 0);  // Moved-from object
    }
}

TEST_CASE("Extended CAT Claims Tests") {
    SUBCASE("Basic Functionality") {
        ExtendedCatClaims extended;
        
        CHECK_FALSE(extended.hasMoqtClaims());
        
        // Create MOQT claims
        auto moqt_claims = MoqtClaims::create();
        std::array actions = {moqt_actions::PUBLISH};
        moqt_claims.addScope(actions, 
                            MoqtBinaryMatch::exact("test.example"),
                            MoqtBinaryMatch{});
        
        extended.setMoqtClaims(std::move(moqt_claims));
        
        CHECK(extended.hasMoqtClaims());
        
        const auto* claims = extended.getMoqtClaimsReadOnly();
        REQUIRE(claims != nullptr);
        CHECK(claims->getScopeCount() == 1);
        CHECK(claims->isAuthorized(moqt_actions::PUBLISH, "test.example", "/any/track"));
    }
    
    SUBCASE("Mutable Access") {
        ExtendedCatClaims extended;
        
        // Get mutable access (creates claims if doesn't exist)
        auto& claims = extended.getMoqtClaims();
        
        std::array actions = {moqt_actions::SUBSCRIBE};
        claims.addScope(actions,
                       MoqtBinaryMatch::prefix("sub"),
                       MoqtBinaryMatch{});
        
        CHECK(extended.hasMoqtClaims());
        CHECK(claims.getScopeCount() == 1);
    }
}

TEST_CASE("Compile-Time String Conversion Tests") {
    SUBCASE("Basic Conversion") {
        constexpr auto binary = string_to_binary("hello");
        static_assert(binary.size() == 5);
        static_assert(binary[0] == 'h');
        static_assert(binary[4] == 'o');
        
        CHECK(std::string(binary.begin(), binary.end()) == "hello");
    }
    
    SUBCASE("Empty String") {
        constexpr auto binary = string_to_binary("");
        static_assert(binary.size() == 0);
    }
}

TEST_CASE("Performance Tests") {
    SUBCASE("Large Scope Set Authorization") {
        auto claims = MoqtClaims::create(1000);
        
        // Create many scopes
        for (int i = 0; i < 500; ++i) {
            std::string ns = "namespace" + std::to_string(i) + ".example";
            std::array actions = {moqt_actions::PUBLISH, moqt_actions::FETCH};
            claims.addScope(actions,
                           MoqtBinaryMatch::exact(ns),
                           MoqtBinaryMatch::prefix("/stream"));
        }
        
        CHECK(claims.getScopeCount() == 500);
        CHECK(claims.getTotalActionCount() == 1000);
        
        // Test authorization performance
        bool result = claims.isAuthorized(moqt_actions::PUBLISH, 
                                         "namespace250.example", 
                                         "/stream/live");
        CHECK(result);
        
        // Test non-matching case
        result = claims.isAuthorized(moqt_actions::PUBLISH,
                                   "nonexistent.example",
                                   "/stream/live");
        CHECK_FALSE(result);
    }
}

TEST_CASE("Range-based Operations") {
    SUBCASE("Action Range Processing") {
        auto claims = MoqtClaims::create();
        
        // Use ranges to create actions
        auto all_actions = std::views::iota(0, 9) 
                          | std::views::filter([](int a) { return moqt_actions::is_valid_action(a); });
        
        std::vector<int> action_vector(all_actions.begin(), all_actions.end());
        
        claims.addScope(action_vector,
                       MoqtBinaryMatch::exact("all.example"),
                       MoqtBinaryMatch{});
        
        // Should authorize all valid actions
        for (int action = 0; action <= 8; ++action) {
            CHECK(claims.isAuthorized(action, "all.example", "/any/track"));
        }
        
        CHECK(claims.getTotalActionCount() == 9);
    }
}

} // TEST_SUITE("MOQT Claims Tests")

TEST_SUITE("Integration Tests") {

TEST_CASE("CatToken with MOQT Claims") {
    SUBCASE("Builder Pattern") {
        auto token = CatToken()
            .withIssuer("https://streaming.example")
            .withAudience({"relay.example"})
            .withExpiration(std::chrono::system_clock::now() + 1h)
            .withVersion("1.0")
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
        CHECK(moqt_claims->isAuthorized(moqt_actions::PUBLISH, "streaming.example", "/live/stream1"));
    }
    
    SUBCASE("Compile-Time Scope") {
        auto token = CatToken()
            .withIssuer("https://publisher.example");
            
        
        // Use compile-time scope addition
        token.template withMoqtActions<moqt_actions::PUBLISH, moqt_actions::ANNOUNCE>(
            MoqtBinaryMatch::exact("publisher.example"),
            MoqtBinaryMatch::prefix("/ct")
        );
        
        const auto* moqt_claims = token.extended.getMoqtClaimsReadOnly();
        REQUIRE(moqt_claims != nullptr);
        
        CHECK(moqt_claims->isAuthorized(moqt_actions::PUBLISH, "publisher.example", "/ct/stream"));
        CHECK(moqt_claims->isAuthorized(moqt_actions::ANNOUNCE, "publisher.example", "/ct"));
        CHECK_FALSE(moqt_claims->isAuthorized(moqt_actions::SUBSCRIBE, "publisher.example", "/ct"));
    }
}

TEST_CASE("Real-World Scenarios") {
    SUBCASE("Multi-Role Token") {
        auto token = CatToken()
            .withIssuer("https://media-platform.example")
            .withAudience({"media-relay.example"})
            .withExpiration(std::chrono::system_clock::now() + 24h);
            
        
        // Publisher role
        std::array publisher_actions = {moqt_actions::ANNOUNCE, moqt_actions::PUBLISH};
        token.withMoqtActionsDynamic(publisher_actions,
                           MoqtBinaryMatch::exact("publisher.media-platform.example"),
                           MoqtBinaryMatch::prefix("/live"));
        
        // Subscriber role
        std::array subscriber_actions = {moqt_actions::SUBSCRIBE, moqt_actions::FETCH};
        token.withMoqtActionsDynamic(subscriber_actions,
                           MoqtBinaryMatch::suffix(".live"),
                           MoqtBinaryMatch{});

        std::array admin_actions = {moqt_actions::CLIENT_SETUP, moqt_actions::SERVER_SETUP};
        token.withMoqtActionsDynamic(admin_actions,
                           MoqtBinaryMatch{},  // All namespaces
                           MoqtBinaryMatch{});  // All tracks
        
        const auto* moqt_claims = token.extended.getMoqtClaimsReadOnly();
        REQUIRE(moqt_claims != nullptr);
        
        CHECK(moqt_claims->getScopeCount() == 3);
        
        // Test publisher permissions
        CHECK(moqt_claims->isAuthorized(moqt_actions::PUBLISH, 
                                       "publisher.media-platform.example", "/live/stream1"));
        CHECK(moqt_claims->isAuthorized(moqt_actions::ANNOUNCE,
                                       "publisher.media-platform.example", "/live"));
        
        // Test subscriber permissions  
        CHECK(moqt_claims->isAuthorized(moqt_actions::SUBSCRIBE, "sports.live", "/game123"));
        CHECK(moqt_claims->isAuthorized(moqt_actions::FETCH, "news.live", "/breaking"));
        
        CHECK(moqt_claims->isAuthorized(moqt_actions::CLIENT_SETUP, "any.namespace", "/any/track"));
        CHECK(moqt_claims->isAuthorized(moqt_actions::SERVER_SETUP, "admin.namespace", "/control"));
        
        // Test denied permissions
        CHECK_FALSE(moqt_claims->isAuthorized(moqt_actions::SUBSCRIBE, 
                                             "publisher.media-platform.example", "/live/stream1"));
        CHECK_FALSE(moqt_claims->isAuthorized(moqt_actions::PUBLISH, "other.com", "/live"));
    }
}

} // TEST_SUITE("Integration Tests")