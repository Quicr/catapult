/**
 * @file usage_state.cpp
 * @brief Tests for the UsageStateHook abstraction and its in-memory default.
 */

#include <doctest/doctest.h>

#include <chrono>
#include <optional>

#include "catapult/claims.hpp"
#include "catapult/usage_state.hpp"

using namespace catapult;
using namespace std::chrono_literals;

namespace {
using Clock = std::chrono::system_clock;
}

TEST_SUITE("InMemoryUsageState") {
  TEST_CASE("Fresh cti is admitted under RejectOnReplay") {
    InMemoryUsageState store;
    auto now = Clock::now();
    CHECK(store.admit("cti-1", CatReplayMode::RejectOnReplay, now,
                      now + 1h) == UsageAdmitResult::Admitted);
    CHECK(store.size() == 1);
  }

  TEST_CASE("Second sighting under RejectOnReplay is Replay") {
    InMemoryUsageState store;
    auto now = Clock::now();
    REQUIRE(store.admit("cti-1", CatReplayMode::RejectOnReplay, now,
                        now + 1h) == UsageAdmitResult::Admitted);
    CHECK(store.admit("cti-1", CatReplayMode::RejectOnReplay, now + 1s,
                      now + 1h) == UsageAdmitResult::Replay);
    // Reject-on-replay does not promote to Revoked; a third sighting is
    // still Replay, and the entry is not persisted after expiry.
    CHECK(store.admit("cti-1", CatReplayMode::RejectOnReplay, now + 2s,
                      now + 1h) == UsageAdmitResult::Replay);
  }

  TEST_CASE("Second sighting under RevokeOnReplay is Revoked and sticky") {
    InMemoryUsageState store;
    auto now = Clock::now();
    REQUIRE(store.admit("cti-1", CatReplayMode::RevokeOnReplay, now,
                        now + 1h) == UsageAdmitResult::Admitted);
    // Second sighting → Revoked; the entry is moved to the revoked set.
    CHECK(store.admit("cti-1", CatReplayMode::RevokeOnReplay, now + 1s,
                      now + 1h) == UsageAdmitResult::Revoked);
    // A later presentation under a different mode still fails: revocation
    // is a property of the cti, not of the current presentation's mode.
    CHECK(store.admit("cti-1", CatReplayMode::RejectOnReplay, now + 2s,
                      now + 1h) == UsageAdmitResult::Revoked);
  }

  TEST_CASE("Revocation survives past the admitted entry's expiry") {
    InMemoryUsageState store;
    auto now = Clock::now();
    REQUIRE(store.admit("cti-1", CatReplayMode::RevokeOnReplay, now,
                        now + 60s) == UsageAdmitResult::Admitted);
    REQUIRE(store.admit("cti-1", CatReplayMode::RevokeOnReplay, now + 1s,
                        now + 60s) == UsageAdmitResult::Revoked);
    // Well past the original exp — a fresh readmit MUST still see Revoked
    // rather than reclaim the slot.
    CHECK(store.admit("cti-1", CatReplayMode::RejectOnReplay, now + 3600s,
                      now + 7200s) == UsageAdmitResult::Revoked);
  }

  TEST_CASE("Expired admission is reclaimed on next presentation") {
    InMemoryUsageState store;
    auto now = Clock::now();
    REQUIRE(store.admit("cti-1", CatReplayMode::RejectOnReplay, now,
                        now + 60s) == UsageAdmitResult::Admitted);
    // Past the exp — the earlier grant is no longer live, so a fresh
    // presentation of the same cti under a new grant is not a replay of
    // a currently-valid token.
    CHECK(store.admit("cti-1", CatReplayMode::RejectOnReplay, now + 120s,
                      now + 200s) == UsageAdmitResult::Admitted);
  }

  TEST_CASE("Admission with no expiry never times out on its own") {
    InMemoryUsageState store;
    auto now = Clock::now();
    REQUIRE(store.admit("cti-1", CatReplayMode::RejectOnReplay, now,
                        std::nullopt) == UsageAdmitResult::Admitted);
    // A "forever" admission stays a replay indefinitely.
    CHECK(store.admit("cti-1", CatReplayMode::RejectOnReplay,
                      now + 24h, std::nullopt) ==
          UsageAdmitResult::Replay);
  }

  TEST_CASE("Explicit revoke() is honoured for future presentations") {
    InMemoryUsageState store;
    auto now = Clock::now();
    REQUIRE(store.admit("cti-1", CatReplayMode::RejectOnReplay, now,
                        now + 60s) == UsageAdmitResult::Admitted);
    CHECK(store.revoke("cti-1") == RevokeResult::Accepted);
    CHECK(store.admit("cti-1", CatReplayMode::RejectOnReplay, now + 1s,
                      now + 60s) == UsageAdmitResult::Revoked);
  }

  TEST_CASE("Distinct ctis coexist") {
    InMemoryUsageState store;
    auto now = Clock::now();
    CHECK(store.admit("a", CatReplayMode::RejectOnReplay, now, now + 1h) ==
          UsageAdmitResult::Admitted);
    CHECK(store.admit("b", CatReplayMode::RejectOnReplay, now, now + 1h) ==
          UsageAdmitResult::Admitted);
    CHECK(store.admit("c", CatReplayMode::RevokeOnReplay, now, now + 1h) ==
          UsageAdmitResult::Admitted);
    CHECK(store.size() == 3);
  }

  TEST_CASE("Bounded store returns StoreExhausted when full of live entries") {
    // max_entries=2, cleanup_every=100 so opportunistic cleanup does not
    // mask the bound within a single test.
    InMemoryUsageState store{2, 100};
    auto now = Clock::now();
    REQUIRE(store.admit("a", CatReplayMode::RejectOnReplay, now,
                        now + 1h) == UsageAdmitResult::Admitted);
    REQUIRE(store.admit("b", CatReplayMode::RejectOnReplay, now,
                        now + 1h) == UsageAdmitResult::Admitted);
    CHECK(store.admit("c", CatReplayMode::RejectOnReplay, now, now + 1h) ==
          UsageAdmitResult::StoreExhausted);
  }

  TEST_CASE("Bounded store reclaims expired admissions on next admit") {
    InMemoryUsageState store{2, 100};
    auto now = Clock::now();
    REQUIRE(store.admit("a", CatReplayMode::RejectOnReplay, now,
                        now + 60s) == UsageAdmitResult::Admitted);
    REQUIRE(store.admit("b", CatReplayMode::RejectOnReplay, now,
                        now + 60s) == UsageAdmitResult::Admitted);
    // Well past both admissions' expiries — a fresh admit should reclaim
    // one of the slots opportunistically.
    CHECK(store.admit("c", CatReplayMode::RejectOnReplay, now + 3600s,
                      now + 7200s) == UsageAdmitResult::Admitted);
  }

  TEST_CASE("Combined cap counts admitted and revoked together") {
    // The bound is the size of admitted + revoked combined, not per-set.
    // A store with one admitted and one revoked entry is at cap for a
    // max_entries=2 configuration, and the next admit MUST fail closed.
    InMemoryUsageState store{2, 100};
    auto now = Clock::now();
    REQUIRE(store.admit("a", CatReplayMode::RejectOnReplay, now,
                        now + 1h) == UsageAdmitResult::Admitted);
    REQUIRE(store.revoke("r") == RevokeResult::Accepted);
    CHECK(store.size() == 2);
    CHECK(store.admit("b", CatReplayMode::RejectOnReplay, now, now + 1h) ==
          UsageAdmitResult::StoreExhausted);
  }

  TEST_CASE("revoke() refuses at capacity and preserves older revocations") {
    // A full store must never silently drop an older revocation to make
    // room for a new one — that would forget operator intent that was
    // already committed. The new revocation is refused via StoreExhausted
    // and the store is left unchanged.
    InMemoryUsageState store{2, 100};
    REQUIRE(store.revoke("old") == RevokeResult::Accepted);
    REQUIRE(store.revoke("mid") == RevokeResult::Accepted);
    REQUIRE(store.size() == 2);

    // Store is at cap. The new revocation MUST be rejected, and neither
    // "old" nor "mid" may be evicted.
    CHECK(store.revoke("new") == RevokeResult::StoreExhausted);
    CHECK(store.size() == 2);

    // Both original revocations still block admissions. We can observe
    // one at a time — StoreExhausted takes precedence when the store is
    // full and there's no matching entry, so verify each after freeing
    // a slot via a fresh store or via purge. Simpler: just check both
    // via admit() calls that hit the revoked-set fast path (which does
    // not require capacity for its check).
    auto now = Clock::now();
    CHECK(store.admit("old", CatReplayMode::RejectOnReplay, now,
                      now + 1h) == UsageAdmitResult::Revoked);
    CHECK(store.admit("mid", CatReplayMode::RejectOnReplay, now,
                      now + 1h) == UsageAdmitResult::Revoked);
    // A truly-new cti still fails closed — the store is at cap.
    CHECK(store.admit("new", CatReplayMode::RejectOnReplay, now,
                      now + 1h) == UsageAdmitResult::StoreExhausted);
  }

  TEST_CASE("revoke() of a currently-admitted cti succeeds even at capacity") {
    // Revoking a cti that is already admitted transfers one slot between
    // sets — no net capacity change — so the operator's intent must land
    // even when the store is full. This is the escape hatch that lets
    // operators respond to a compromise without needing spare capacity.
    InMemoryUsageState store{2, 100};
    auto now = Clock::now();
    REQUIRE(store.admit("a", CatReplayMode::RejectOnReplay, now,
                        now + 1h) == UsageAdmitResult::Admitted);
    REQUIRE(store.admit("b", CatReplayMode::RejectOnReplay, now,
                        now + 1h) == UsageAdmitResult::Admitted);
    REQUIRE(store.size() == 2);
    CHECK(store.revoke("a") == RevokeResult::Accepted);
    CHECK(store.size() == 2);
    CHECK(store.admit("a", CatReplayMode::RejectOnReplay, now + 1s,
                      now + 1h) == UsageAdmitResult::Revoked);
  }

  TEST_CASE("Repeat revoke() of the same cti is idempotent") {
    // A repeat revoke() of a cti already in the revoked set is a no-op
    // that reports Accepted — the cti is (still) revoked, which is the
    // outcome the caller asked for. This lets callers loop over an
    // external revocation list without special-casing duplicates.
    InMemoryUsageState store{2, 100};
    REQUIRE(store.revoke("a") == RevokeResult::Accepted);
    REQUIRE(store.revoke("b") == RevokeResult::Accepted);
    REQUIRE(store.size() == 2);

    // Repeat revokes remain Accepted and do not consume capacity.
    CHECK(store.revoke("a") == RevokeResult::Accepted);
    CHECK(store.revoke("a") == RevokeResult::Accepted);
    CHECK(store.size() == 2);

    // Both original revocations still block.
    auto now = Clock::now();
    CHECK(store.admit("a", CatReplayMode::RejectOnReplay, now, now + 1h) ==
          UsageAdmitResult::Revoked);
    CHECK(store.admit("b", CatReplayMode::RejectOnReplay, now, now + 1h) ==
          UsageAdmitResult::Revoked);
  }

  TEST_CASE("RevokeOnReplay promotion respects the combined cap") {
    // An admitted entry promoted to revoked under RevokeOnReplay transfers
    // one slot between sets — no net capacity change — so a store at cap
    // must still be able to complete the promotion.
    InMemoryUsageState store{2, 100};
    auto now = Clock::now();
    REQUIRE(store.admit("a", CatReplayMode::RevokeOnReplay, now,
                        now + 1h) == UsageAdmitResult::Admitted);
    REQUIRE(store.admit("b", CatReplayMode::RejectOnReplay, now,
                        now + 1h) == UsageAdmitResult::Admitted);
    REQUIRE(store.size() == 2);
    // Second sighting of "a" promotes it. Store is still at cap.
    CHECK(store.admit("a", CatReplayMode::RevokeOnReplay, now + 1s,
                      now + 1h) == UsageAdmitResult::Revoked);
    CHECK(store.size() == 2);
    // "a" is now in the revoked set and MUST stay there.
    CHECK(store.admit("a", CatReplayMode::RejectOnReplay, now + 2s,
                      now + 1h) == UsageAdmitResult::Revoked);
  }
}
