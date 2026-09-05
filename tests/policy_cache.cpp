/**
 * @file policy_cache.cpp
 * @brief Tests for the PolicyCache hook and InMemoryPolicyCache default.
 */

#include <doctest/doctest.h>

#include <chrono>
#include <stdexcept>
#include <string>

#include "catapult/policy_cache.hpp"

using namespace catapult;
using namespace std::chrono_literals;

namespace {

using Clock = std::chrono::system_clock;

AuthorizationDecision allowFor(std::chrono::seconds ttl,
                               Clock::time_point now) {
  return AuthorizationDecision{AuthorizationOutcome::Allow, now + ttl};
}

}  // namespace

TEST_SUITE("InMemoryPolicyCache") {
  TEST_CASE("Zero max_entries is rejected") {
    CHECK_THROWS_AS(InMemoryPolicyCache(0), std::invalid_argument);
  }

  TEST_CASE("Miss on empty cache returns nullopt") {
    InMemoryPolicyCache cache;
    auto now = Clock::now();
    CHECK(!cache.lookup("digest-1", now).has_value());
    CHECK(cache.size() == 0);
  }

  TEST_CASE("Store then lookup returns the same decision") {
    InMemoryPolicyCache cache;
    auto now = Clock::now();
    cache.store("digest-1", allowFor(60s, now), now);
    auto got = cache.lookup("digest-1", now);
    REQUIRE(got.has_value());
    CHECK(got->outcome == AuthorizationOutcome::Allow);
    CHECK(cache.size() == 1);
  }

  TEST_CASE("Expired entry is treated as a miss and evicted") {
    InMemoryPolicyCache cache;
    auto now = Clock::now();
    cache.store("digest-1", allowFor(60s, now), now);
    // Advance past expiration.
    auto later = now + 120s;
    CHECK(!cache.lookup("digest-1", later).has_value());
    CHECK(cache.size() == 0);
  }

  TEST_CASE("Store of an already-stale entry is silently dropped") {
    InMemoryPolicyCache cache;
    auto now = Clock::now();
    // TTL of -1s: the entry is stale on arrival. Recording it would
    // only crowd out fresh state.
    AuthorizationDecision stale{AuthorizationOutcome::Allow, now - 1s};
    cache.store("digest-1", stale, now);
    CHECK(cache.size() == 0);
  }

  TEST_CASE("LRU: oldest entry is evicted when the cache is full") {
    InMemoryPolicyCache cache(2);
    auto now = Clock::now();
    cache.store("A", allowFor(3600s, now), now);
    cache.store("B", allowFor(3600s, now), now);
    // Touch A so B is now least-recently-used.
    (void)cache.lookup("A", now);
    cache.store("C", allowFor(3600s, now), now);
    // A and C survive; B was LRU when C landed.
    CHECK(cache.lookup("A", now).has_value());
    CHECK(!cache.lookup("B", now).has_value());
    CHECK(cache.lookup("C", now).has_value());
  }

  TEST_CASE("Overwrite of an existing key updates expiration in place") {
    InMemoryPolicyCache cache;
    auto now = Clock::now();
    cache.store("digest-1", allowFor(10s, now), now);
    cache.store("digest-1", allowFor(3600s, now), now);
    // The second store extended the TTL. Advance past the first TTL —
    // the entry must still be fresh.
    auto later = now + 60s;
    auto got = cache.lookup("digest-1", later);
    REQUIRE(got.has_value());
    CHECK(cache.size() == 1);
  }

  TEST_CASE("Cache never substitutes its own TTL") {
    // Caller-authoritative expiration: the store MUST record exactly the
    // expires_at we passed in. A cache that stretched entry lifetime
    // beyond token exp would let a compromised backend widen access.
    InMemoryPolicyCache cache;
    auto now = Clock::now();
    auto want_expiry = now + 42s;
    cache.store("digest-1",
                AuthorizationDecision{AuthorizationOutcome::Deny, want_expiry},
                now);
    auto got = cache.lookup("digest-1", now);
    REQUIRE(got.has_value());
    CHECK(got->expires_at == want_expiry);
    CHECK(got->outcome == AuthorizationOutcome::Deny);
  }
}
