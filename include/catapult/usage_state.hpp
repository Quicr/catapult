/**
 * @file usage_state.hpp
 * @brief Pluggable usage-state backend for CTA-5007-B `catreplay` enforcement.
 *
 * CTA-5007-B §4.6.9 defines two replay-protection modes that require the
 * resource server to remember which CAT tokens (identified by `cti`) have
 * already been admitted:
 *
 *   - `RejectOnReplay` (mode 1): a token seen a second time MUST be
 *     rejected.
 *   - `RevokeOnReplay` (mode 2): a token seen a second time MUST be
 *     rejected AND the corresponding grant MUST be marked revoked so any
 *     future presentation is also rejected, regardless of `catreplay` on
 *     that later presentation.
 *
 * `CatTokenValidator` cannot enforce either mode from library state alone
 * because the "have we seen this cti before?" answer is deployment-scoped:
 * a single-process test suite, a single-relay staging environment, and a
 * geo-distributed CDN each need very different backends. `UsageStateHook`
 * is the seam. The default `InMemoryUsageState` is bounded, mutex-guarded,
 * and suitable for single-process deployments and tests; multi-instance
 * relays plug in an external implementation.
 *
 * The interface mirrors `ReplayStore` intentionally — both close the same
 * class of TOCTOU race on a "check then record" pair — but the semantics
 * differ: `ReplayStore` protects DPoP proof `jti`s within a short freshness
 * window, whereas `UsageStateHook` tracks CAT `cti`s for the token's own
 * validity lifetime (typically bounded by `exp`).
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

#include "claims.hpp"

namespace catapult {

/**
 * @brief Outcome of a `UsageStateHook::admit()` call.
 */
enum class UsageAdmitResult {
  /// The cti has not been seen (or its prior sighting has expired) and has
  /// now been recorded. Caller should proceed with authorization.
  Admitted,
  /// The cti was already recorded within its validity window. Caller MUST
  /// fail closed for both `RejectOnReplay` and `RevokeOnReplay` modes.
  Replay,
  /// The cti was previously marked revoked by an explicit `revoke()` call.
  /// Caller MUST fail closed for `RevokeOnReplay`; behaviour on
  /// `RejectOnReplay` is the same because revoked implies "seen twice" by
  /// construction.
  Revoked,
  /// Store cannot admit a new entry (capacity exhausted). Callers MUST
  /// treat exhaustion as a replay to fail closed rather than silently
  /// admitting.
  StoreExhausted,
};

/**
 * @brief Abstract usage-state backend for CAT `catreplay` enforcement.
 *
 * Implementations MUST be safe to call concurrently from multiple threads.
 * `admit()` MUST atomically check for a prior sighting AND either record a
 * new one or return `Replay` / `Revoked`; callers must not perform their
 * own read-then-write cycle.
 */
class UsageStateHook {
 public:
  virtual ~UsageStateHook() = default;

  /**
   * @brief Atomically check whether `cti` has been used and record a fresh
   *        sighting if not.
   *
   * @param cti Token identifier bytes (RFC 8392 §3.1.7 `cti` is a byte
   *   string; callers pass a view over that vector as-is — no length limit
   *   enforced here, use `ParseLimits` upstream if needed).
   * @param mode `RejectOnReplay` or `RevokeOnReplay`. `None` MUST NOT be
   *   forwarded to this hook — the validator short-circuits that mode.
   *   Passing it anyway is a programmer error; implementations are free to
   *   admit as if the mode were `RejectOnReplay` rather than adding a
   *   throw path to the hot path.
   * @param now Caller's current timestamp. Passed in so the validator's
   *   sense of "now" and the store's sense of "now" cannot drift, and so
   *   tests can drive deterministic replay windows.
   * @param expiry Absolute epoch time at which the store may forget this
   *   sighting. Typically `token.core.exp`. Optional: when unset, the
   *   store keeps the entry indefinitely — appropriate for
   *   `RevokeOnReplay` and for tokens without `exp`.
   * @return see `UsageAdmitResult`.
   */
  virtual UsageAdmitResult admit(
      std::string_view cti, CatReplayMode mode,
      std::chrono::system_clock::time_point now,
      std::optional<std::chrono::system_clock::time_point> expiry) = 0;

  /**
   * @brief Mark `cti` as revoked so future `admit()` calls return
   *        `Revoked`, regardless of `mode`.
   *
   * Used by relays that manage explicit token revocation lists out of
   * band (compromise notifications, subscription cancellation, etc.).
   * Not called by `CatTokenValidator` itself — the validator only writes
   * through `admit()`; revocation is an operator action.
   */
  virtual void revoke(std::string_view cti) = 0;

  /**
   * @brief Drop admitted entries whose stored expiry is before `now`.
   *
   * Optional maintenance hook. `admit()` implementations are expected to
   * perform their own opportunistic housekeeping; this is exposed so
   * operators can drive cleanup from a scheduler if they prefer.
   *
   * Revoked entries are NOT purged: revocation is intentionally sticky.
   */
  virtual void purgeExpired(std::chrono::system_clock::time_point now) = 0;

  /**
   * @brief Best-effort snapshot of live entry count (admitted + revoked).
   */
  virtual std::size_t size() const = 0;
};

/**
 * @brief In-process usage-state store backed by mutex-guarded hash tables.
 *
 * Bounded: the single `max_entries` cap applies to `admitted + revoked`
 * combined. Two rules follow from having one shared bound:
 *
 *   - `admit()` fails closed when the cap is reached and expired
 *     admissions cannot be reclaimed. It returns `StoreExhausted`;
 *     `CatTokenValidator` treats that as `ReplayAttackError`, so a full
 *     store cannot silently admit a token whose sighting could not be
 *     recorded.
 *   - `revoke()` must succeed (it has no failure channel and the caller
 *     has already decided that the cti MUST be blocked). When the cap
 *     is reached, `revoke()` evicts the oldest revocation FIFO to make
 *     room. This preserves the "most recent operator intent wins"
 *     property at the cost of forgetting an older revocation. Operators
 *     who cannot tolerate that tradeoff MUST plug in an external
 *     backend whose capacity matches their revocation-list size.
 *
 * Suitable for a single-process relay whose live token working set fits
 * comfortably under the bound; not suitable when usage state must survive
 * restarts or be shared across processes.
 */
class InMemoryUsageState final : public UsageStateHook {
 public:
  /**
   * @brief Construct a bounded in-memory usage store.
   *
   * @param max_entries Hard cap on the combined size of the admitted and
   *   revoked sets. Zero is coerced to 1 to prevent an unbounded store
   *   (memory-exhaustion vector).
   * @param cleanup_every_n_admits Run opportunistic purge every N
   *   successful admits. Zero is coerced to 1 (purge on every admit).
   */
  explicit InMemoryUsageState(std::size_t max_entries = 1'000'000,
                              std::size_t cleanup_every_n_admits = 10'000);

  UsageAdmitResult admit(
      std::string_view cti, CatReplayMode mode,
      std::chrono::system_clock::time_point now,
      std::optional<std::chrono::system_clock::time_point> expiry) override;

  void revoke(std::string_view cti) override;

  void purgeExpired(std::chrono::system_clock::time_point now) override;

  std::size_t size() const override;

 private:
  struct Entry {
    // Absolute expiry; nullopt means "never forget" (RevokeOnReplay or
    // token without exp).
    std::optional<std::chrono::system_clock::time_point> expiry;
  };

  mutable std::mutex mu_;
  std::unordered_map<std::string, Entry> admitted_;
  std::unordered_set<std::string> revoked_;
  // FIFO of keys in `revoked_`, oldest first. Used to evict the oldest
  // revocation when a new one would exceed `max_entries_`. std::list so
  // that eviction from the front is O(1) and does not invalidate iterators
  // to unaffected entries.
  std::list<std::string> revoked_order_;
  std::size_t admits_since_cleanup_{0};
  const std::size_t max_entries_;
  const std::size_t cleanup_interval_;

  void purgeExpiredLocked(std::chrono::system_clock::time_point now);
  // Insert `key` into the revoked set + FIFO. Evicts the oldest revocation
  // if the store is otherwise at capacity. Caller must hold `mu_`.
  void insertRevokedLocked(const std::string& key);
};

}  // namespace catapult
