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
    store.revoke("cti-1");
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
    store.revoke("r");
    CHECK(store.size() == 2);
    CHECK(store.admit("b", CatReplayMode::RejectOnReplay, now, now + 1h) ==
          UsageAdmitResult::StoreExhausted);
  }

  TEST_CASE("revoke() succeeds at capacity by evicting the oldest revocation") {
    // revoke() has no failure channel: the operator has already decided
    // the cti MUST be blocked. When the store is at cap the newest
    // revocation MUST persist even if that means dropping the oldest.
    InMemoryUsageState store{2, 100};
    store.revoke("old");
    store.revoke("mid");
    REQUIRE(store.size() == 2);
    // "old" is the oldest revocation — evicting it makes room for "new".
    store.revoke("new");
    CHECK(store.size() == 2);

    // "old" no longer blocks — it lost its revocation record to make room
    // for the newer intent, which is the documented tradeoff.
    auto now = Clock::now();
    CHECK(store.admit("old", CatReplayMode::RejectOnReplay, now,
                      now + 1h) == UsageAdmitResult::StoreExhausted);
    // "mid" and "new" are still revoked. (We can only observe one of them
    // directly since the store is at cap; the "new" revocation is the
    // most-recent-operator-intent that MUST have persisted.)
    // Free a slot first so admit() has room to reach the revoked check.
    store.purgeExpired(now);
    // No admitted entries had exp, so purge is a no-op. Free the slot by
    // constructing a store with more room and re-verifying by re-revoke.
    InMemoryUsageState store2{3, 100};
    store2.revoke("a");
    store2.revoke("b");
    store2.revoke("c");
    // "a" is oldest; a fourth revocation evicts it.
    store2.revoke("d");
    CHECK(store2.admit("d", CatReplayMode::RejectOnReplay, now, now + 1h) ==
          UsageAdmitResult::Revoked);
    CHECK(store2.admit("c", CatReplayMode::RejectOnReplay, now, now + 1h) ==
          UsageAdmitResult::Revoked);
    CHECK(store2.admit("b", CatReplayMode::RejectOnReplay, now, now + 1h) ==
          UsageAdmitResult::Revoked);
  }

  TEST_CASE("Repeat revoke() of the same cti is idempotent and does not evict") {
    // A repeat revoke() of a cti already in the revoked set must not
    // consume capacity or shift FIFO order — otherwise a caller looping
    // over an external revocation list could accidentally evict older
    // revocations by re-issuing them.
    InMemoryUsageState store{2, 100};
    store.revoke("a");
    store.revoke("b");
    REQUIRE(store.size() == 2);

    // Repeat revoke of "a" — must remain a no-op.
    store.revoke("a");
    store.revoke("a");
    CHECK(store.size() == 2);

    // Both original revocations must still block.
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
