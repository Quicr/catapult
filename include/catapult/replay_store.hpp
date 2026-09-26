/**
 * @file replay_store.hpp
 * @brief Pluggable replay-detection backend for DPoP JTI tracking.
 *
 * The `DpopProofValidator` delegates freshness/replay bookkeeping to a
 * `ReplayStore`. The default `InMemoryReplayStore` keeps state in a
 * mutex-guarded map and is suitable for single-process deployments.
 * Multi-process relays or fleets that need to survive restarts should
 * supply an external implementation (Redis, memcached, database, etc.)
 * that persists across processes and instances.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>

#include "store_capabilities.hpp"

namespace catapult {

/**
 * @brief Outcome of a check-and-record attempt against a replay store.
 */
enum class ReplayAdmitResult {
  Admitted,       ///< JTI was fresh and has now been recorded.
  Replay,         ///< JTI was already seen within the replay window.
  StoreExhausted  ///< Store cannot admit; treat as replay to fail closed.
};

/**
 * @brief Abstract replay-detection backend.
 *
 * Implementations MUST be safe to call concurrently. `admit()` is expected
 * to atomically check for prior use of the jti within the given window and,
 * on freshness, record it. Callers must not perform their own get-then-set
 * cycle around this call — that would reintroduce the TOCTOU race that
 * this interface exists to close.
 *
 * ## Lifetime and concurrency contract
 *
 * - **Ownership.** `DpopProofValidator` holds a `std::shared_ptr<ReplayStore>`;
 *   the store lives as long as any validator referencing it.
 * - **Concurrent invocation.** `admit()`, `purgeExpired()`, and `size()`
 *   are called from every worker thread and MUST be safe under
 *   concurrent access. Adapters over external services (Redis, DB) must
 *   handle their own connection pooling; the library does not gate calls.
 * - **Atomicity scope.** See `capabilities()` — the interface signature
 *   alone does not distinguish per-process from cluster-wide atomicity.
 *   `requireFleetCapableReplayBackend()` is how a deployment enforces
 *   its declared scope at startup.
 * - **Exception behaviour.** `admit()` propagating an exception aborts
 *   admission. Adapters that see transient backend errors SHOULD
 *   surface them as `StoreExhausted` (fail closed) rather than throw,
 *   so a bounded number of transient failures does not tear down the
 *   caller's exception-handling path.
 */
class ReplayStore {
 public:
  virtual ~ReplayStore() = default;

  /**
   * @brief Atomically check whether `jti` is fresh and record it if so.
   *
   * @param jti Unique DPoP proof identifier (opaque bytes, no length limit
   *   enforced here — callers should validate size upstream if needed).
   * @param now Caller's current timestamp. Passed in so the validator's
   *   sense of "now" and the store's sense of "now" cannot drift.
   * @param window Replay window: a jti seen within this many seconds ago
   *   is a replay.
   * @return `Admitted` if `jti` is fresh (and recorded);
   *         `Replay` if `jti` was already recorded within the window;
   *         `StoreExhausted` if the store is at capacity and cannot record
   *         a new entry. Callers must treat exhaustion as a replay to fail
   *         closed rather than silently admitting.
   */
  virtual ReplayAdmitResult admit(std::string_view jti,
                                  std::chrono::system_clock::time_point now,
                                  std::chrono::seconds window) = 0;

  /**
   * @brief Drop entries older than `now - window`.
   *
   * Optional maintenance hook. `admit()` implementations are expected to
   * perform their own housekeeping; this is exposed so operators can drive
   * cleanup from a scheduler if they prefer.
   */
  virtual void purgeExpired(std::chrono::system_clock::time_point now,
                            std::chrono::seconds window) = 0;

  /**
   * @brief Current number of tracked entries (best-effort snapshot).
   */
  virtual std::size_t size() const = 0;

  /**
   * @brief Report what atomicity / durability / scope this backend
   *        actually provides.
   *
   * The `admit()` signature alone cannot express whether the check is
   * cluster-atomic, whether state survives restart, or whether the
   * store is shared across relay instances. Operators use
   * `requireFleetCapableReplayBackend()` at startup to refuse a backend
   * whose reported capabilities are weaker than the deployment's
   * declared guarantee (see FC-4 in `docs/security-invariants.md`).
   *
   * The default returns the pessimistic in-process record so a
   * hand-rolled adapter that forgets to override is treated as
   * single-node and rejected by any fleet-wide check.
   */
  virtual StoreCapabilities capabilities() const {
    return StoreCapabilities{StoreAtomicity::PerProcess,
                             StoreDurability::Ephemeral,
                             StoreScope::SingleNode, "unspecified"};
  }
};

/**
 * @brief Thrown by `requireFleetCapableReplayBackend()` at startup when a
 *        deployment declares fleet-wide replay guarantees but is wired
 *        against a backend that cannot deliver them.
 *
 * This is a *configuration* error surfaced before the first request is
 * served, not an admission-time failure. Operators handle it by wiring
 * an appropriate adapter or by explicitly disabling the guarantee (and
 * documenting that decision on the deployment).
 */
class InsufficientBackendCapabilitiesError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

/**
 * @brief Enforce that `store` meets `requirements` at startup.
 *
 * Throws `InsufficientBackendCapabilitiesError` when any required
 * capability is missing. The error message names the reported backend
 * so an operator can tell "wrong adapter wired" from "adapter reports
 * the wrong level" at a glance.
 *
 * Idempotent and cheap; call once per validator wire-up.
 */
void requireFleetCapableReplayBackend(
    const ReplayStore& store,
    FleetRequirements requirements = FleetRequirements{});

/**
 * @brief In-process replay store backed by a mutex-guarded hash map.
 *
 * Bounded: rejects new entries once `max_entries` is reached, after
 * attempting to reclaim expired slots first. Suitable for a single-process
 * relay with a bounded working set of live jtis; not suitable when replay
 * state must survive restarts or be shared across processes.
 */
class InMemoryReplayStore final : public ReplayStore {
 public:
  /**
   * @brief Construct a bounded in-memory store.
   *
   * @param max_entries Hard cap on live entries. Zero is rejected: an
   *   unbounded store is a memory-exhaustion vector.
   * @param cleanup_every_n_admits Run opportunistic purge every N successful
   *   admits. Must be positive; the constructor coerces zero to 1 (i.e.
   *   purge on every admit) rather than dividing by zero at runtime.
   *
   * Internally sharded (fixed 16 shards keyed on the jti hash). Each
   * shard has its own mutex, map, and cleanup counter; the cap is split
   * evenly across shards so `max_entries` is preserved across the whole
   * store.
   */
  explicit InMemoryReplayStore(std::size_t max_entries = 1'000'000,
                               std::size_t cleanup_every_n_admits = 10'000);

  ReplayAdmitResult admit(std::string_view jti,
                          std::chrono::system_clock::time_point now,
                          std::chrono::seconds window) override;

  void purgeExpired(std::chrono::system_clock::time_point now,
                    std::chrono::seconds window) override;

  std::size_t size() const override;

  StoreCapabilities capabilities() const override {
    // In-tree in-memory: atomic within this process (mutex-guarded),
    // ephemeral (map dies with the process), single-node (each replica
    // has its own map). No fleet-wide guarantee whatsoever — that is
    // what `requireFleetCapableReplayBackend` exists to catch.
    return StoreCapabilities{StoreAtomicity::PerProcess,
                             StoreDurability::Ephemeral,
                             StoreScope::SingleNode, "in-memory"};
  }

 private:
  static constexpr std::size_t kShardCount = 16;

  struct Shard {
    mutable std::mutex mu;
    std::unordered_map<std::string, std::chrono::system_clock::time_point>
        entries;
    std::size_t admits_since_cleanup = 0;
    std::size_t max_entries = 0;

    void purgeExpiredLocked(std::chrono::system_clock::time_point now,
                            std::chrono::seconds window);
    // Bounded-budget variant: iterate at most `budget` entries, erasing
    // any that are outside the replay window. Used inside `admit()` so
    // one call cannot stall on an O(N) sweep of a large shard.
    // `purgeExpiredLocked` remains the unbounded sweep that operators
    // drive from `purgeExpired()` when they explicitly want to drain
    // everything expired.
    void purgeIncrementalLocked(std::chrono::system_clock::time_point now,
                                std::chrono::seconds window,
                                std::size_t budget);
  };

  mutable Shard shards_[kShardCount];
  const std::size_t cleanup_interval_;
  // See `InMemoryPolicyCache::active_shards_`: fewer than `kShardCount`
  // slices are used when `max_entries` is smaller than the shard count,
  // so the combined cap is exactly `max_entries`.
  std::size_t active_shards_ = kShardCount;

  std::size_t shardIndex(std::string_view jti) const noexcept;
};

}  // namespace catapult
