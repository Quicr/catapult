/**
 * @file policy_cache.hpp
 * @brief Pluggable authorization-decision cache for relay hot paths.
 *
 * Token validation is the largest per-request cost catapult exposes:
 * signature verification, canonical-CBOR strict decode, geo/scope
 * checks, composite-claim evaluation. A relay that admits the same
 * `(token, resource)` pair many times per session repeats this work
 * unless it caches the outcome.
 *
 * `PolicyCache` is the seam. It stores caller-computed digests of the
 * (token, resource) tuple against `AuthorizationDecision` records, with
 * an entry-scoped expiration so a cached admit cannot outlive the
 * token's own `exp` (nor a shorter cache-only TTL the relay chooses).
 *
 * The library ships `InMemoryPolicyCache` as an in-tree default: a
 * mutex-guarded bounded LRU with wall-clock TTL. Multi-process fleets or
 * setups that need to share decisions across relay instances should
 * plug in an external implementation (Redis, memcached, database).
 *
 * ## Contract
 *
 * Implementations MUST be safe to call concurrently.
 *
 * `lookup()` returns the cached decision only if it is still fresh
 * (expiration in the future when compared against the caller's `now`).
 * A stale entry MUST be treated as a miss; whether the implementation
 * evicts the entry on read is optional but recommended.
 *
 * `store()` accepts an entry whose expiration is expressed as an
 * absolute `system_clock::time_point` — implementations MUST NOT
 * substitute their own TTL for the caller's. That would let an attacker
 * who controls the cache backend widen a decision beyond the token's
 * lifetime.
 *
 * Digest choice is the caller's responsibility. Practical relays hash
 * the encoded token bytes plus the resource path with a
 * collision-resistant function (SHA-256, BLAKE2). Truncating below 128
 * bits reintroduces cross-subject collision risk and is not
 * recommended.
 *
 * ## Fail-open vs fail-closed
 *
 * The cache is an optimization: a `lookup()` miss must fall through to
 * a fresh validation. Implementations that fail to answer (backend
 * outage, corruption) MUST return a miss rather than an incorrect hit —
 * the semantic identity is "cache off is always safe".
 *
 * A `store()` failure must not affect the current admission decision.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace catapult {

/**
 * @brief The verdict a policy cache remembers for a (token, resource)
 *        digest.
 */
enum class AuthorizationOutcome {
  Allow,  ///< Prior validation admitted this pair.
  Deny,   ///< Prior validation rejected this pair.
};

/**
 * @brief Cache entry: what the decision was and when it stops being
 *        trustworthy.
 *
 * `expires_at` is absolute wall-clock time. Callers derive it from the
 * minimum of the token's own `exp` and any cache-side TTL policy — the
 * cache never invents its own bound.
 */
struct AuthorizationDecision {
  AuthorizationOutcome outcome;
  std::chrono::system_clock::time_point expires_at;
};

/**
 * @brief Abstract authorization-decision cache.
 *
 * Digests are opaque bytes chosen by the caller. Implementations MUST
 * hash-map on the full digest and MUST NOT truncate.
 */
class PolicyCache {
 public:
  virtual ~PolicyCache() = default;

  /**
   * @brief Fetch a fresh decision for `digest`.
   *
   * @param digest Caller-computed digest of the (token, resource) pair.
   * @param now Caller's current time. Passed in so implementation clock
   *   and validator clock cannot drift.
   * @return The cached decision iff its `expires_at` is strictly greater
   *   than `now`; `std::nullopt` otherwise (miss, expired, or backend
   *   failure).
   */
  virtual std::optional<AuthorizationDecision> lookup(
      std::string_view digest,
      std::chrono::system_clock::time_point now) = 0;

  /**
   * @brief Record a decision.
   *
   * @param digest Caller-computed digest of the (token, resource) pair.
   * @param decision Verdict and absolute expiration.
   * @param now Caller's current time. Enables implementations to
   *   perform opportunistic eviction of stale entries in the same call.
   *
   * Implementations MAY drop the entry (e.g. capacity exhaustion) but
   * MUST NOT record it with a different `expires_at` than the caller
   * supplied.
   */
  virtual void store(std::string_view digest,
                     const AuthorizationDecision& decision,
                     std::chrono::system_clock::time_point now) = 0;

  /**
   * @brief Best-effort snapshot of the current number of tracked
   *        entries.
   */
  virtual std::size_t size() const = 0;
};

/**
 * @brief In-process bounded LRU cache with wall-clock TTL.
 *
 * Keeps at most `max_entries` decisions. On insertion above the cap the
 * least-recently-used entry is evicted. `lookup()` treats a stale entry
 * as a miss and evicts it on the way out so a slow-moving hot set does
 * not accumulate expired ballast.
 *
 * Suitable for a single-process relay. Fleets that must share
 * decisions across instances (or survive process restarts) should plug
 * in an out-of-tree implementation.
 */
class InMemoryPolicyCache final : public PolicyCache {
 public:
  /**
   * @brief Construct a bounded LRU cache.
   *
   * @param max_entries Hard cap on live entries. Zero is rejected: an
   *   unbounded decision cache is a memory-exhaustion vector when the
   *   digest space is attacker-controlled.
   */
  explicit InMemoryPolicyCache(std::size_t max_entries = 100'000);

  std::optional<AuthorizationDecision> lookup(
      std::string_view digest,
      std::chrono::system_clock::time_point now) override;

  void store(std::string_view digest,
             const AuthorizationDecision& decision,
             std::chrono::system_clock::time_point now) override;

  std::size_t size() const override;

 private:
  struct Entry {
    std::string digest;
    AuthorizationDecision decision;
  };
  using EntryList = std::list<Entry>;

  mutable std::mutex mu_;
  EntryList entries_;
  std::unordered_map<std::string, EntryList::iterator> index_;
  const std::size_t max_entries_;

  void touchLocked(EntryList::iterator it);
  void evictExpiredLocked(std::chrono::system_clock::time_point now);
};

}  // namespace catapult
