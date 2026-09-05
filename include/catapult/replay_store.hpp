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
#include <string>
#include <string_view>
#include <unordered_map>

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
};

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
   */
  explicit InMemoryReplayStore(std::size_t max_entries = 1'000'000,
                               std::size_t cleanup_every_n_admits = 10'000);

  ReplayAdmitResult admit(std::string_view jti,
                          std::chrono::system_clock::time_point now,
                          std::chrono::seconds window) override;

  void purgeExpired(std::chrono::system_clock::time_point now,
                    std::chrono::seconds window) override;

  std::size_t size() const override;

 private:
  mutable std::mutex mu_;
  std::unordered_map<std::string, std::chrono::system_clock::time_point>
      entries_;
  std::size_t admits_since_cleanup_{0};
  const std::size_t max_entries_;
  const std::size_t cleanup_interval_;

  void purgeExpiredLocked(std::chrono::system_clock::time_point now,
                          std::chrono::seconds window);
};

}  // namespace catapult
