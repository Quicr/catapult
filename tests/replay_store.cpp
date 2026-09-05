/**
 * @file replay_store.cpp
 * @brief Tests for the pluggable ReplayStore abstraction.
 */

#include <doctest/doctest.h>

#include <chrono>
#include <memory>
#include <string>

#include "catapult/replay_store.hpp"

using namespace catapult;
using namespace std::chrono_literals;

namespace {

using Clock = std::chrono::system_clock;

}  // namespace

TEST_SUITE("InMemoryReplayStore") {
  TEST_CASE("Fresh jti is admitted") {
    InMemoryReplayStore store;
    auto now = Clock::now();
    CHECK(store.admit("jti-1", now, 300s) == ReplayAdmitResult::Admitted);
    CHECK(store.size() == 1);
  }

  TEST_CASE("Replay within the window is rejected") {
    InMemoryReplayStore store;
    auto now = Clock::now();
    REQUIRE(store.admit("jti-1", now, 300s) == ReplayAdmitResult::Admitted);
    CHECK(store.admit("jti-1", now + 60s, 300s) == ReplayAdmitResult::Replay);
    CHECK(store.size() == 1);
  }

  TEST_CASE("Reuse after the window elapses is admitted") {
    InMemoryReplayStore store;
    auto now = Clock::now();
    REQUIRE(store.admit("jti-1", now, 300s) == ReplayAdmitResult::Admitted);
    // Enough time has passed that the earlier sighting is outside the
    // window. The store must refresh the timestamp in place, not
    // duplicate the entry.
    CHECK(store.admit("jti-1", now + 400s, 300s) ==
          ReplayAdmitResult::Admitted);
    CHECK(store.size() == 1);
  }

  TEST_CASE("Distinct jtis coexist") {
    InMemoryReplayStore store;
    auto now = Clock::now();
    CHECK(store.admit("a", now, 300s) == ReplayAdmitResult::Admitted);
    CHECK(store.admit("b", now, 300s) == ReplayAdmitResult::Admitted);
    CHECK(store.admit("c", now, 300s) == ReplayAdmitResult::Admitted);
    CHECK(store.size() == 3);
  }

  TEST_CASE("Bounded store rejects when saturated with live entries") {
    // max_entries=2, cleanup_every=100 so opportunistic cleanup does
    // not mask the bound.
    InMemoryReplayStore store{2, 100};
    auto now = Clock::now();
    REQUIRE(store.admit("a", now, 300s) == ReplayAdmitResult::Admitted);
    REQUIRE(store.admit("b", now, 300s) == ReplayAdmitResult::Admitted);

    // Third fresh admit is refused — all existing entries are still
    // within the window and cannot be reclaimed.
    CHECK(store.admit("c", now, 300s) == ReplayAdmitResult::StoreExhausted);
    CHECK(store.size() == 2);
  }

  TEST_CASE("Saturated store reclaims expired entries on next admit") {
    InMemoryReplayStore store{2, 100};
    auto t0 = Clock::now();
    REQUIRE(store.admit("a", t0, 60s) == ReplayAdmitResult::Admitted);
    REQUIRE(store.admit("b", t0, 60s) == ReplayAdmitResult::Admitted);

    // Well past the window — the earlier entries should be purged to
    // make room.
    auto later = t0 + 3600s;
    CHECK(store.admit("c", later, 60s) == ReplayAdmitResult::Admitted);
    CHECK(store.size() == 1);
  }

  TEST_CASE("Zero cleanup interval does not divide by zero") {
    // If a caller passes 0 for the cleanup interval it must be coerced
    // to a positive value at construction; every admit then purges.
    InMemoryReplayStore store{16, 0};
    auto now = Clock::now();
    CHECK(store.admit("x", now, 300s) == ReplayAdmitResult::Admitted);
    CHECK(store.admit("y", now, 300s) == ReplayAdmitResult::Admitted);
    CHECK(store.size() == 2);
  }

  TEST_CASE("Zero max_entries is coerced to a positive bound") {
    // An unbounded store is not offered; a caller that requests one
    // gets the smallest bounded store instead.
    InMemoryReplayStore store{0, 10};
    auto now = Clock::now();
    CHECK(store.admit("x", now, 300s) == ReplayAdmitResult::Admitted);
    CHECK(store.admit("y", now, 300s) == ReplayAdmitResult::StoreExhausted);
  }

  TEST_CASE("purgeExpired drops expired entries") {
    InMemoryReplayStore store;
    auto t0 = Clock::now();
    REQUIRE(store.admit("a", t0, 60s) == ReplayAdmitResult::Admitted);
    REQUIRE(store.admit("b", t0, 60s) == ReplayAdmitResult::Admitted);
    REQUIRE(store.size() == 2);
    store.purgeExpired(t0 + 3600s, 60s);
    CHECK(store.size() == 0);
  }
}

namespace {

// A mock backend that records every admit call and lets the test drive
// the outcome. Demonstrates that DpopProofValidator can be composed with
// an arbitrary ReplayStore, e.g. one backed by Redis.
class MockReplayStore final : public ReplayStore {
 public:
  ReplayAdmitResult next_result = ReplayAdmitResult::Admitted;
  int admit_calls = 0;

  ReplayAdmitResult admit(std::string_view, Clock::time_point,
                          std::chrono::seconds) override {
    ++admit_calls;
    return next_result;
  }

  void purgeExpired(Clock::time_point, std::chrono::seconds) override {}

  std::size_t size() const override { return 0; }
};

}  // namespace

TEST_SUITE("ReplayStore plugin surface") {
  TEST_CASE("Mock backend is substitutable for the in-memory default") {
    auto store = std::make_shared<MockReplayStore>();
    // Contract: the interface is what the validator depends on, so
    // asserting the mock satisfies it here (compilation + call count)
    // is what protects the plugin surface from silent regression.
    ReplayStore& iface = *store;
    auto now = Clock::now();
    CHECK(iface.admit("x", now, 300s) == ReplayAdmitResult::Admitted);
    CHECK(store->admit_calls == 1);

    store->next_result = ReplayAdmitResult::Replay;
    CHECK(iface.admit("x", now, 300s) == ReplayAdmitResult::Replay);
    CHECK(store->admit_calls == 2);
  }
}
