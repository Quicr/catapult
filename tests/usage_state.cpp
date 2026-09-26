/**
 * @file usage_state.cpp
 * @brief Tests for the UsageStateHook abstraction and its in-memory default.
 */

#include <doctest/doctest.h>

#include <atomic>
#include <chrono>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "catapult/claims.hpp"
#include "catapult/replay_store.hpp"
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

  TEST_CASE("Concurrent admit of the same cti admits exactly once") {
    // Contract: `admit()` must atomically check-and-record. If N threads
    // race against the same cti, exactly one MUST see Admitted; the rest
    // MUST see Replay (or Revoked, for RevokeOnReplay). A non-atomic
    // implementation would let two threads pass the "not seen" check
    // before either recorded a sighting, and both would be admitted —
    // silently disabling replay protection under load.
    InMemoryUsageState store{10'000, 1'000};
    auto now = Clock::now();
    const int threads = 16;
    const std::string cti = "shared-cti";
    std::atomic<int> admitted_count{0};
    std::atomic<int> replay_count{0};
    std::vector<std::thread> workers;
    workers.reserve(threads);
    for (int i = 0; i < threads; ++i) {
      workers.emplace_back([&]() {
        auto res = store.admit(cti, CatReplayMode::RejectOnReplay, now,
                                now + 1h);
        if (res == UsageAdmitResult::Admitted) admitted_count.fetch_add(1);
        else if (res == UsageAdmitResult::Replay) replay_count.fetch_add(1);
      });
    }
    for (auto& t : workers) t.join();
    CHECK(admitted_count.load() == 1);
    CHECK(replay_count.load() == threads - 1);
  }

  TEST_CASE("Concurrent admit of distinct ctis admits every one") {
    // Distinct ctis are independent — the store's mutex serialises admits
    // but must not stop them from succeeding. Under contention every
    // thread on a unique cti must land as Admitted.
    InMemoryUsageState store{10'000, 1'000};
    auto now = Clock::now();
    const int threads = 32;
    std::atomic<int> admitted_count{0};
    std::vector<std::thread> workers;
    workers.reserve(threads);
    for (int i = 0; i < threads; ++i) {
      workers.emplace_back([&, i]() {
        std::string cti = "cti-" + std::to_string(i);
        if (store.admit(cti, CatReplayMode::RejectOnReplay, now, now + 1h) ==
            UsageAdmitResult::Admitted) {
          admitted_count.fetch_add(1);
        }
      });
    }
    for (auto& t : workers) t.join();
    CHECK(admitted_count.load() == threads);
    CHECK(store.size() == static_cast<std::size_t>(threads));
  }

  TEST_CASE("Concurrent revoke() vs. admit() never admits the revoked cti") {
    // An operator revocation race must not lose to a live admission on
    // the same cti. Either the admit happens before revoke (Admitted;
    // subsequent admits see Revoked) or revoke happens first (all
    // admits see Revoked). Under no schedule may a thread that started
    // its admit after revoke returned Accepted see Admitted.
    for (int trial = 0; trial < 20; ++trial) {
      InMemoryUsageState store;
      auto now = Clock::now();
      const std::string cti = "target";
      std::atomic<bool> revoked_done{false};
      std::vector<std::thread> workers;
      std::atomic<int> post_revoke_admissions{0};
      // Thread A: revoke.
      workers.emplace_back([&]() {
        (void)store.revoke(cti);
        revoked_done.store(true);
      });
      // Threads B..: retry admit until they see either Admitted or
      // Revoked. If any admit lands after revoked_done is observed true
      // but sees Admitted, the store violated its contract.
      for (int i = 0; i < 8; ++i) {
        workers.emplace_back([&]() {
          auto res = store.admit(cti, CatReplayMode::RejectOnReplay, now,
                                  now + 1h);
          if (revoked_done.load() && res == UsageAdmitResult::Admitted) {
            post_revoke_admissions.fetch_add(1);
          }
        });
      }
      for (auto& t : workers) t.join();
      CHECK(post_revoke_admissions.load() == 0);
      // The final state must have the cti visible as Revoked to any
      // subsequent admit.
      CHECK(store.admit(cti, CatReplayMode::RejectOnReplay, now, now + 1h) ==
            UsageAdmitResult::Revoked);
    }
  }

  TEST_CASE("capacity() reflects the constructor's max_entries") {
    // Operators chart size() / capacity() to alert before StoreExhausted
    // fires. The value must match the cap the store actually enforces —
    // not a rounded or dynamically-adjusted one — so dashboards do not
    // mislead.
    InMemoryUsageState store{4096, 100};
    CHECK(store.capacity() == 4096u);
    // Zero is coerced to 1 in the constructor; capacity() must report the
    // effective cap, not the raw argument.
    InMemoryUsageState clamped{0, 100};
    CHECK(clamped.capacity() == 1u);
  }

  TEST_CASE("exhaustion_events() counts StoreExhausted from admit and revoke") {
    // Operators need a monotonic counter for hard-incident alerting: every
    // admit() that returned StoreExhausted and every revoke() that returned
    // StoreExhausted MUST increment the counter. A silent counter would
    // mean pages fire from log tailing alone — brittle at scale.
    InMemoryUsageState store{2, 100};
    auto now = Clock::now();
    CHECK(store.exhaustion_events() == 0u);
    REQUIRE(store.admit("a", CatReplayMode::RejectOnReplay, now,
                        now + 1h) == UsageAdmitResult::Admitted);
    REQUIRE(store.admit("b", CatReplayMode::RejectOnReplay, now,
                        now + 1h) == UsageAdmitResult::Admitted);
    CHECK(store.exhaustion_events() == 0u);

    // admit() at cap — first exhaustion event.
    REQUIRE(store.admit("c", CatReplayMode::RejectOnReplay, now, now + 1h) ==
            UsageAdmitResult::StoreExhausted);
    CHECK(store.exhaustion_events() == 1u);

    // A second admit() at cap increments again — the counter is monotonic
    // and not deduplicated per cti.
    REQUIRE(store.admit("d", CatReplayMode::RejectOnReplay, now, now + 1h) ==
            UsageAdmitResult::StoreExhausted);
    CHECK(store.exhaustion_events() == 2u);

    // revoke() that lands StoreExhausted also increments — same class of
    // incident, same counter.
    REQUIRE(store.revoke("new-revoke") == RevokeResult::StoreExhausted);
    CHECK(store.exhaustion_events() == 3u);
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

  TEST_CASE("Over-cap cti on admit fails closed as StoreExhausted") {
    // The validator maps StoreExhausted → ReplayAttackError, so this
    // is fail-closed: an adversarial multi-KB cti neither grows memory
    // nor is silently admitted.
    InMemoryUsageState store{1024, 100, /*max_cti_bytes=*/32};
    auto now = Clock::now();
    std::string oversize(64, 'X');
    CHECK(store.admit(oversize, CatReplayMode::RejectOnReplay, now,
                      now + 1h) == UsageAdmitResult::StoreExhausted);
    CHECK(store.size() == 0);
  }

  TEST_CASE("Over-cap cti on revoke fails closed as StoreExhausted") {
    // Refusing revoke of an oversize cti prevents an operator flow
    // that loops adversarial inputs through the write path from
    // growing memory. The revocation is not recorded.
    InMemoryUsageState store{1024, 100, /*max_cti_bytes=*/32};
    std::string oversize(64, 'X');
    CHECK(store.revoke(oversize) == RevokeResult::StoreExhausted);
    CHECK(store.size() == 0);
  }

  TEST_CASE("At-cap cti is accepted") {
    InMemoryUsageState store{1024, 100, /*max_cti_bytes=*/32};
    auto now = Clock::now();
    std::string exact(32, 'Y');
    CHECK(store.admit(exact, CatReplayMode::RejectOnReplay, now,
                      now + 1h) == UsageAdmitResult::Admitted);
  }
}

namespace {

class FleetCapableUsageState final : public UsageStateHook {
 public:
  UsageAdmitResult admit(std::string_view, CatReplayMode, Clock::time_point,
                         std::optional<Clock::time_point>) override {
    return UsageAdmitResult::Admitted;
  }
  RevokeResult revoke(std::string_view) override {
    return RevokeResult::Accepted;
  }
  void purgeExpired(Clock::time_point) override {}
  std::size_t size() const override { return 0; }
  StoreCapabilities capabilities() const override {
    return StoreCapabilities{StoreAtomicity::ClusterWide,
                             StoreDurability::Persistent,
                             StoreScope::FleetWide, "mock-cluster"};
  }
};

}  // namespace

TEST_SUITE("UsageStateHook fleet-capability gate") {
  TEST_CASE("In-memory default is refused by the default fleet requirements") {
    InMemoryUsageState store;
    CHECK_THROWS_AS(requireFleetCapableUsageBackend(store),
                    InsufficientBackendCapabilitiesError);
  }

  TEST_CASE("Fleet-capable backend passes the gate") {
    FleetCapableUsageState store;
    CHECK_NOTHROW(requireFleetCapableUsageBackend(store));
  }

  TEST_CASE(
      "Persistent requirement guards RevokeOnReplay against ephemeral state") {
    // A backend that provides cluster atomicity + fleet scope but loses
    // state on restart is dangerous for RevokeOnReplay: a revoked cti
    // must remain revoked across the entire attack window.
    class ClusterButEphemeral final : public UsageStateHook {
     public:
      UsageAdmitResult admit(std::string_view, CatReplayMode,
                             Clock::time_point,
                             std::optional<Clock::time_point>) override {
        return UsageAdmitResult::Admitted;
      }
      RevokeResult revoke(std::string_view) override {
        return RevokeResult::Accepted;
      }
      void purgeExpired(Clock::time_point) override {}
      std::size_t size() const override { return 0; }
      StoreCapabilities capabilities() const override {
        return StoreCapabilities{StoreAtomicity::ClusterWide,
                                 StoreDurability::Ephemeral,
                                 StoreScope::FleetWide, "cluster-cache"};
      }
    };
    ClusterButEphemeral store;
    CHECK_THROWS_AS(requireFleetCapableUsageBackend(store),
                    InsufficientBackendCapabilitiesError);
  }

  TEST_CASE("Default capabilities() on a hand-rolled adapter fails closed") {
    class ForgetfulAdapter final : public UsageStateHook {
     public:
      UsageAdmitResult admit(std::string_view, CatReplayMode,
                             Clock::time_point,
                             std::optional<Clock::time_point>) override {
        return UsageAdmitResult::Admitted;
      }
      RevokeResult revoke(std::string_view) override {
        return RevokeResult::Accepted;
      }
      void purgeExpired(Clock::time_point) override {}
      std::size_t size() const override { return 0; }
    };
    ForgetfulAdapter adapter;
    CHECK_THROWS_AS(requireFleetCapableUsageBackend(adapter),
                    InsufficientBackendCapabilitiesError);
  }
}
