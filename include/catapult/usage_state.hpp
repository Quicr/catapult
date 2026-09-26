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
#include <limits>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

#include "claims.hpp"
#include "store_capabilities.hpp"

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
 * @brief Outcome of a `UsageStateHook::revoke()` call.
 *
 * `revoke()` reports its outcome so operators can observe whether the
 * intent was recorded. It never silently discards an older revocation to
 * satisfy a new one — a full store refuses the new entry rather than
 * lose earlier intent.
 */
enum class RevokeResult {
  /// The cti was inserted into the revoked set (or was already present).
  /// Future `admit()` calls for this cti will return `Revoked`.
  Accepted,
  /// The store is at capacity and cannot record the new revocation without
  /// evicting an existing entry. The revocation was NOT recorded; older
  /// entries are preserved. Callers MUST treat this as a hard failure and
  /// escalate (e.g. page an operator, plug in a larger backend). Returning
  /// success would silently drop earlier revocation intent, which is worse
  /// than surfacing the exhaustion.
  StoreExhausted,
};

/**
 * @brief Abstract usage-state backend for CAT `catreplay` enforcement.
 *
 * Implementations MUST be safe to call concurrently from multiple threads.
 * `admit()` MUST atomically check for a prior sighting AND either record a
 * new one or return `Replay` / `Revoked`; callers must not perform their
 * own read-then-write cycle.
 *
 * ## Lifetime and concurrency contract
 *
 * - **Ownership.** `CatTokenValidator` holds a non-owning raw pointer.
 *   The hook MUST outlive every validator that references it.
 * - **Configuration mutation.** `withUsageStateHook()` is NOT safe to
 *   call concurrently with `validate()` on the same validator. Rotate
 *   backends by preparing a new validator instance.
 * - **Concurrent invocation.** `admit()`, `revoke()`, `purgeExpired()`,
 *   and `size()` are called from every worker thread. Adapters over
 *   external services MUST handle their own connection pooling and
 *   preserve the atomicity contract of `admit()` under concurrent
 *   admissions of the same `cti`.
 * - **Exception behaviour.** Same as `ReplayStore`: prefer
 *   `StoreExhausted` on transient backend failure; a thrown exception
 *   aborts admission.
 * - **Fleet-wide guarantees.** See `capabilities()` and
 *   `requireFleetCapableUsageBackend()` for the startup gate.
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
   *
   * @return `Accepted` if the cti is now recorded as revoked (including
   *   the case where it was already revoked — the call is idempotent).
   *   `StoreExhausted` if the backend cannot record the revocation
   *   without evicting an older entry; in that case the new revocation
   *   is NOT recorded and older revocations are preserved. Callers MUST
   *   escalate rather than proceed as if revocation succeeded.
   */
  virtual RevokeResult revoke(std::string_view cti) = 0;

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

  /**
   * @brief Report the store's hard capacity ceiling.
   *
   * Returns `std::numeric_limits<std::size_t>::max()` for backends that
   * do not enforce a fixed cap (e.g. a Redis adapter whose limit is set
   * externally). Callers use `size() / capacity()` as a fill-percentage
   * gauge — alert at 80% so operators can grow the backend before
   * `StoreExhausted` fires under load.
   *
   * Default implementation returns "unbounded" so existing hook
   * implementations do not have to opt in; the shipped in-memory store
   * overrides it with its true cap.
   */
  virtual std::size_t capacity() const {
    return (std::numeric_limits<std::size_t>::max)();
  }

  /**
   * @brief Best-effort count of `StoreExhausted` outcomes observed on
   *        this instance.
   *
   * Increments on every `admit()` that returned `StoreExhausted` and on
   * every `revoke()` that returned `StoreExhausted`. Exposed so operators
   * can chart the rate of hard-incident events instead of only relying on
   * log tailing. Reset semantics are implementation-defined; the shipped
   * in-memory store makes the counter monotonic.
   *
   * Default is 0 for backends that don't yet track this.
   */
  virtual std::size_t exhaustion_events() const { return 0; }

  /**
   * @brief Report what atomicity / durability / scope this backend
   *        actually provides.
   *
   * See `ReplayStore::capabilities()` for rationale. `RevokeOnReplay`
   * additionally requires `StoreDurability::Persistent`: a revocation
   * that vanishes on process restart re-admits a token an operator has
   * already marked bad. `requireFleetCapableUsageBackend()` refuses to
   * boot such a configuration.
   */
  virtual StoreCapabilities capabilities() const {
    return StoreCapabilities{StoreAtomicity::PerProcess,
                             StoreDurability::Ephemeral,
                             StoreScope::SingleNode, "unspecified"};
  }
};

/**
 * @brief Enforce that `hook` meets `requirements` at startup.
 *
 * Same shape as `requireFleetCapableReplayBackend`; throws
 * `InsufficientBackendCapabilitiesError` (declared in `replay_store.hpp`,
 * re-used here so operator error handling can be uniform) when the
 * reported capabilities are too weak.
 */
void requireFleetCapableUsageBackend(
    const UsageStateHook& hook,
    FleetRequirements requirements = FleetRequirements{});

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
 *   - `revoke()` refuses to silently drop older revocations. When the
 *     cap is reached and no expired admission can be reclaimed, it
 *     returns `StoreExhausted` and leaves the store unchanged. Callers
 *     MUST treat that as a hard failure — swallowing it would forget an
 *     older revocation that an operator already committed to. Operators
 *     whose revocation-list size approaches the bound MUST plug in an
 *     external backend whose capacity matches their workload.
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
   * @param max_cti_bytes Reject ctis longer than this many bytes at the
   *   API boundary; over-cap inputs on `admit()` surface as
   *   `StoreExhausted` (fail closed) and on `revoke()` as
   *   `StoreExhausted` (revocation refused). Defaults to 128 bytes,
   *   comfortably above any legitimate CAT `cti` (RFC 8392 §3.1.7).
   *   Zero is coerced to the default.
   */
  explicit InMemoryUsageState(std::size_t max_entries = 1'000'000,
                              std::size_t cleanup_every_n_admits = 10'000,
                              std::size_t max_cti_bytes = 128);

  UsageAdmitResult admit(
      std::string_view cti, CatReplayMode mode,
      std::chrono::system_clock::time_point now,
      std::optional<std::chrono::system_clock::time_point> expiry) override;

  RevokeResult revoke(std::string_view cti) override;

  void purgeExpired(std::chrono::system_clock::time_point now) override;

  std::size_t size() const override;

  std::size_t capacity() const override {
    std::size_t total = 0;
    for (const auto& shard : shards_) total += shard.max_entries;
    return total;
  }

  std::size_t exhaustion_events() const override;

  StoreCapabilities capabilities() const override {
    // Same rationale as `InMemoryReplayStore`: per-process atomic,
    // ephemeral, single-node. Fleet-wide `catreplay` enforcement
    // requires an external adapter.
    return StoreCapabilities{StoreAtomicity::PerProcess,
                             StoreDurability::Ephemeral,
                             StoreScope::SingleNode, "in-memory"};
  }

 private:
  struct Entry {
    // Absolute expiry; nullopt means "never forget" (RevokeOnReplay or
    // token without exp).
    std::optional<std::chrono::system_clock::time_point> expiry;
  };

  static constexpr std::size_t kShardCount = 16;

  struct Shard {
    mutable std::mutex mu;
    std::unordered_map<std::string, Entry> admitted;
    std::unordered_set<std::string> revoked;
    std::size_t admits_since_cleanup = 0;
    std::size_t exhaustion_events = 0;
    std::size_t max_entries = 0;

    void purgeExpiredLocked(std::chrono::system_clock::time_point now);
    // Bounded-budget variant used inside `admit()` for opportunistic
    // housekeeping. Cap-recovery, which MUST be exhaustive, still uses
    // `purgeExpiredLocked`.
    void purgeIncrementalLocked(std::chrono::system_clock::time_point now,
                                std::size_t budget);
    RevokeResult insertRevokedLocked(const std::string& key);
  };

  mutable Shard shards_[kShardCount];
  const std::size_t cleanup_interval_;
  // Fewer than `kShardCount` slices are used when `max_entries` is
  // smaller than the shard count, so the combined cap is exactly
  // `max_entries`.
  std::size_t active_shards_ = kShardCount;
  std::size_t max_cti_bytes_ = 128;

  std::size_t shardIndex(std::string_view cti) const noexcept;
};

}  // namespace catapult
