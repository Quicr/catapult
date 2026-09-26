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

TEST_SUITE("PolicyCacheKey") {
  TEST_CASE(
      "Context isolation: same (token,resource) but different decision "
      "inputs are different entries") {
    // FC-7: two requests with the same token and resource but different
    // PolicyContext (say, different client_ip) MUST NOT collapse to the
    // same cached decision. Structurally: differing
    // decision_inputs_digest ⇒ different cache identity.
    InMemoryPolicyCache cache;
    auto now = Clock::now();
    const std::string tr = "token-resource";
    const std::string ctx_a = "client-ip-A";
    const std::string ctx_b = "client-ip-B";
    PolicyCacheKey ka{tr, ctx_a, 1};
    PolicyCacheKey kb{tr, ctx_b, 1};

    cache.store(
        ka, AuthorizationDecision{AuthorizationOutcome::Allow, now + 60s},
        now);
    cache.store(
        kb, AuthorizationDecision{AuthorizationOutcome::Deny, now + 60s},
        now);

    auto got_a = cache.lookup(ka, now);
    auto got_b = cache.lookup(kb, now);
    REQUIRE(got_a.has_value());
    REQUIRE(got_b.has_value());
    CHECK(got_a->outcome == AuthorizationOutcome::Allow);
    CHECK(got_b->outcome == AuthorizationOutcome::Deny);
    CHECK(cache.size() == 2);
  }

  TEST_CASE("policy_generation bump invalidates every prior entry") {
    // Any policy-code, key-set, or revocation-list update bumps the
    // generation. Prior entries become unreachable in the new namespace
    // even though (token_resource_digest, decision_inputs_digest) are
    // identical.
    InMemoryPolicyCache cache;
    auto now = Clock::now();
    PolicyCacheKey before{"tr", "ctx", 1};
    PolicyCacheKey after{"tr", "ctx", 2};

    cache.store(
        before,
        AuthorizationDecision{AuthorizationOutcome::Allow, now + 3600s}, now);
    REQUIRE(cache.lookup(before, now).has_value());
    CHECK(!cache.lookup(after, now).has_value());
  }

  TEST_CASE("encodeKey is collision-free across component boundaries") {
    // A naive concatenation ("ab" | "cd" == "a" | "bcd") would let a
    // caller who controls one digest bleed bytes into the other. The
    // length-prefixed encoding must keep the split unambiguous.
    PolicyCacheKey k1{"ab", "cd", 0};
    PolicyCacheKey k2{"a", "bcd", 0};
    PolicyCacheKey k3{"abc", "d", 0};
    const auto e1 = policy_cache_detail::encodeKey(k1);
    const auto e2 = policy_cache_detail::encodeKey(k2);
    const auto e3 = policy_cache_detail::encodeKey(k3);
    CHECK(e1 != e2);
    CHECK(e1 != e3);
    CHECK(e2 != e3);
  }

  TEST_CASE("encodeKey distinguishes policy_generation") {
    PolicyCacheKey k1{"tr", "ctx", 1};
    PolicyCacheKey k2{"tr", "ctx", 2};
    CHECK(policy_cache_detail::encodeKey(k1) !=
          policy_cache_detail::encodeKey(k2));
  }

  TEST_CASE("Empty digests are still keyed distinctly by generation") {
    // A caller with no context inputs (context-free decision) still
    // needs the generation to invalidate on policy rotation.
    InMemoryPolicyCache cache;
    auto now = Clock::now();
    PolicyCacheKey g1{"tr", {}, 1};
    PolicyCacheKey g2{"tr", {}, 2};
    cache.store(
        g1, AuthorizationDecision{AuthorizationOutcome::Allow, now + 60s},
        now);
    CHECK(cache.lookup(g1, now).has_value());
    CHECK(!cache.lookup(g2, now).has_value());
  }
}

TEST_SUITE("InMemoryPolicyCache digest byte cap") {
  TEST_CASE("Over-cap digest on store is silently dropped") {
    // Attacker-controlled multi-KB digests must not grow per-entry
    // memory unboundedly. `store()` returns without recording.
    InMemoryPolicyCache cache(1024, /*max_digest_bytes=*/32);
    auto now = Clock::now();
    std::string oversize(64, 'X');
    cache.store(oversize, allowFor(60s, now), now);
    CHECK(cache.size() == 0);
  }

  TEST_CASE("Over-cap digest on lookup is a miss") {
    InMemoryPolicyCache cache(1024, /*max_digest_bytes=*/32);
    auto now = Clock::now();
    std::string oversize(64, 'X');
    CHECK(!cache.lookup(oversize, now).has_value());
  }

  TEST_CASE("At-cap digest is accepted") {
    // Boundary: exactly `max_digest_bytes` must still round-trip.
    InMemoryPolicyCache cache(1024, /*max_digest_bytes=*/32);
    auto now = Clock::now();
    std::string exact(32, 'Y');
    cache.store(exact, allowFor(60s, now), now);
    CHECK(cache.lookup(exact, now).has_value());
  }

  TEST_CASE("Zero max_digest_bytes coerces to the default") {
    // A caller that default-init'd with zero still gets a sane cap
    // rather than a store that refuses every insertion.
    InMemoryPolicyCache cache(1024, /*max_digest_bytes=*/0);
    auto now = Clock::now();
    std::string typical(32, 'Z');
    cache.store(typical, allowFor(60s, now), now);
    CHECK(cache.lookup(typical, now).has_value());
  }
}

TEST_SUITE("InMemoryPolicyCache fixed-digest fast path") {
  TEST_CASE("Store and lookup roundtrip via PolicyCacheDigest") {
    InMemoryPolicyCache cache;
    auto now = Clock::now();
    PolicyCacheDigest d{};
    for (std::size_t i = 0; i < d.size(); ++i) {
      d[i] = static_cast<std::uint8_t>(i);
    }
    cache.store(d, allowFor(60s, now), now);
    auto got = cache.lookup(d, now);
    REQUIRE(got.has_value());
    CHECK(got->outcome == AuthorizationOutcome::Allow);
  }

  TEST_CASE("Digest and string_view keys share the same identity") {
    // A `store(PolicyCacheDigest)` followed by a `lookup(string_view)`
    // over the same 32 bytes MUST hit. Otherwise a caller who mixes
    // the two APIs (say, a legacy component still on string_view) sees
    // spurious misses.
    InMemoryPolicyCache cache;
    auto now = Clock::now();
    PolicyCacheDigest d{};
    for (std::size_t i = 0; i < d.size(); ++i) {
      d[i] = static_cast<std::uint8_t>(0xA5 ^ i);
    }
    cache.store(d, allowFor(60s, now), now);
    std::string_view as_view(reinterpret_cast<const char*>(d.data()),
                             d.size());
    auto got = cache.lookup(as_view, now);
    REQUIRE(got.has_value());
    CHECK(got->outcome == AuthorizationOutcome::Allow);
  }

  TEST_CASE("Distinct digests are distinct entries") {
    InMemoryPolicyCache cache;
    auto now = Clock::now();
    PolicyCacheDigest a{};
    PolicyCacheDigest b{};
    a[0] = 1;
    b[0] = 2;
    cache.store(a, AuthorizationDecision{AuthorizationOutcome::Allow,
                                         now + 60s},
                now);
    cache.store(b,
                AuthorizationDecision{AuthorizationOutcome::Deny, now + 60s},
                now);
    auto got_a = cache.lookup(a, now);
    auto got_b = cache.lookup(b, now);
    REQUIRE(got_a.has_value());
    REQUIRE(got_b.has_value());
    CHECK(got_a->outcome == AuthorizationOutcome::Allow);
    CHECK(got_b->outcome == AuthorizationOutcome::Deny);
    CHECK(cache.size() == 2);
  }

  TEST_CASE("Expired entry via digest is a miss and eviction") {
    InMemoryPolicyCache cache;
    auto now = Clock::now();
    PolicyCacheDigest d{};
    d[0] = 42;
    cache.store(d, allowFor(60s, now), now);
    CHECK(!cache.lookup(d, now + 120s).has_value());
    CHECK(cache.size() == 0);
  }
}
