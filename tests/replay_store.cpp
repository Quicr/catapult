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

  TEST_CASE("Over-cap jti fails closed as StoreExhausted") {
    // Fail-closed semantics: an adversarial multi-KB jti must not
    // grow per-entry memory. Refusing surfaces the anomaly to the
    // validator, which treats StoreExhausted as a replay signal.
    InMemoryReplayStore store(1024, 100, /*max_jti_bytes=*/32);
    auto now = Clock::now();
    std::string oversize(64, 'X');
    CHECK(store.admit(oversize, now, 300s) ==
          ReplayAdmitResult::StoreExhausted);
    CHECK(store.size() == 0);
  }

  TEST_CASE("At-cap jti is admitted") {
    InMemoryReplayStore store(1024, 100, /*max_jti_bytes=*/32);
    auto now = Clock::now();
    std::string exact(32, 'Y');
    CHECK(store.admit(exact, now, 300s) == ReplayAdmitResult::Admitted);
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

namespace {

class FleetCapableReplayStore final : public ReplayStore {
 public:
  ReplayAdmitResult admit(std::string_view, Clock::time_point,
                          std::chrono::seconds) override {
    return ReplayAdmitResult::Admitted;
  }
  void purgeExpired(Clock::time_point, std::chrono::seconds) override {}
  std::size_t size() const override { return 0; }
  StoreCapabilities capabilities() const override {
    return StoreCapabilities{StoreAtomicity::ClusterWide,
                             StoreDurability::Persistent,
                             StoreScope::FleetWide, "mock-cluster"};
  }
};

}  // namespace

TEST_SUITE("ReplayStore fleet-capability gate") {
  TEST_CASE("In-memory default is refused by the default fleet requirements") {
    // FC-4: a production deployment declaring fleet-wide replay
    // guarantees must not boot against the process-local default.
    InMemoryReplayStore store;
    CHECK_THROWS_AS(requireFleetCapableReplayBackend(store),
                    InsufficientBackendCapabilitiesError);
  }

  TEST_CASE("Fleet-capable backend passes the same gate") {
    FleetCapableReplayStore store;
    CHECK_NOTHROW(requireFleetCapableReplayBackend(store));
  }

  TEST_CASE("Operator can relax individual requirements") {
    // A deployment that has consciously accepted single-node scope
    // (e.g. a single-relay demo) can relax the gate. That decision
    // must be explicit — the default is "everything required".
    InMemoryReplayStore store;
    FleetRequirements relaxed{
        /*require_cluster_atomicity=*/false,
        /*require_persistent=*/false,
        /*require_fleet_scope=*/false,
    };
    CHECK_NOTHROW(requireFleetCapableReplayBackend(store, relaxed));
  }

  TEST_CASE("Error names the reported backend so mismatch is diagnosable") {
    // "Wrong adapter wired" vs "adapter reports the wrong level" is a
    // distinction operators need at startup. Include the backend name.
    InMemoryReplayStore store;
    try {
      requireFleetCapableReplayBackend(store);
      FAIL("expected InsufficientBackendCapabilitiesError");
    } catch (const InsufficientBackendCapabilitiesError& e) {
      const std::string msg = e.what();
      CHECK(msg.find("in-memory") != std::string::npos);
    }
  }

  TEST_CASE("Default capabilities() on a hand-rolled adapter fails closed") {
    // If an operator writes a custom adapter and forgets to override
    // capabilities(), it MUST NOT be silently treated as fleet-capable.
    // The base default is pessimistic.
    class ForgetfulAdapter final : public ReplayStore {
     public:
      ReplayAdmitResult admit(std::string_view, Clock::time_point,
                              std::chrono::seconds) override {
        return ReplayAdmitResult::Admitted;
      }
      void purgeExpired(Clock::time_point, std::chrono::seconds) override {}
      std::size_t size() const override { return 0; }
    };
    ForgetfulAdapter adapter;
    CHECK_THROWS_AS(requireFleetCapableReplayBackend(adapter),
                    InsufficientBackendCapabilitiesError);
  }
}
