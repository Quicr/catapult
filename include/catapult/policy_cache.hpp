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
 * @brief Full identity for a cached authorization decision.
 *
 * The historical `PolicyCache` interface keyed on `hash(token, resource)`
 * alone. That is unsafe in practice: two requests with the same token
 * and resource but different `PolicyContext` (client IP, DPoP proof,
 * session identity, MOQT tuple) can resolve to different decisions, and
 * a policy or revocation feed update MUST invalidate every prior cached
 * verdict issued under the old rules. Keying on `(token, resource)`
 * alone would let a cache silently return a stale allow after either
 * change (see FC-7 in `docs/security-invariants.md`).
 *
 * A production cache key MUST therefore include:
 *
 *   - `token_resource_digest`: caller-computed digest of the encoded
 *     token bytes + resource path. This is the "what is being decided"
 *     component.
 *   - `decision_inputs_digest`: caller-computed digest over every
 *     `PolicyContext` field that the decision depended on. If the
 *     decision depends on `client_ip` and `dpop_proof`, both feed the
 *     digest. Empty means "no context inputs affected the decision" and
 *     is only correct when the token cannot carry a context-requiring
 *     claim.
 *   - `policy_generation`: monotonically increasing counter the operator
 *     bumps on any policy code, key-set, or revocation-list update.
 *     Bumping this value MUST invalidate every prior cached decision;
 *     implementations achieve that by including the generation in the
 *     hash-map key so an older entry becomes unreachable.
 *
 * `PolicyCacheKey` is a value type. The digest views must reference
 * caller storage that outlives the `lookup`/`store` call; the cache
 * copies bytes internally and never retains views past the call.
 */
struct PolicyCacheKey {
  std::string_view token_resource_digest;
  std::string_view decision_inputs_digest;
  std::uint64_t policy_generation = 0;
};

/**
 * @brief Abstract authorization-decision cache.
 *
 * Digests are opaque bytes chosen by the caller. Implementations MUST
 * hash-map on the full digest and MUST NOT truncate.
 *
 * ## Lifetime and concurrency contract
 *
 * - **Ownership.** The relay owns the cache instance and passes it to
 *   the admission path by reference. The cache MUST outlive every
 *   admission thread that references it.
 * - **Concurrent invocation.** `lookup()`, `store()`, and `size()` are
 *   called from every worker thread; implementations MUST be safe under
 *   concurrent access. The in-tree `InMemoryPolicyCache` is
 *   mutex-guarded.
 * - **Exception behaviour.** A backend failure MUST surface as a miss
 *   from `lookup()` (see "Fail-open vs fail-closed" above). Adapters
 *   that throw from `lookup()` or `store()` compromise the "cache off
 *   is always safe" invariant — do not.
 * - **View lifetimes.** All digest / key views passed to `lookup()` and
 *   `store()` are valid for the duration of the call only. The cache
 *   copies bytes it needs to retain.
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
   *
   * @deprecated Prefer `lookup(PolicyCacheKey, now)`. Keying on
   *   `(token, resource)` alone is only safe when the decision depends
   *   on nothing else. Production relays whose decisions depend on
   *   request context or on a rotating policy / revocation feed MUST
   *   include those inputs in the key (FC-7 in
   *   `docs/security-invariants.md`).
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
   *
   * @deprecated See `lookup(std::string_view, now)`.
   */
  virtual void store(std::string_view digest,
                     const AuthorizationDecision& decision,
                     std::chrono::system_clock::time_point now) = 0;

  /**
   * @brief Fetch a fresh decision keyed on the full authorization
   *        identity.
   *
   * Same freshness contract as the string-view overload; the difference
   * is that the cache key includes every input the decision depended
   * on. Implementations MUST treat `(token_resource_digest,
   * decision_inputs_digest, policy_generation)` as three independent
   * dimensions of the key — hits that agree on any two but disagree on
   * the third are misses.
   *
   * The default implementation composes the components into a single
   * canonical byte string and delegates to the legacy `lookup`
   * overload; overrides SHOULD provide a native implementation.
   */
  virtual std::optional<AuthorizationDecision> lookup(
      const PolicyCacheKey& key,
      std::chrono::system_clock::time_point now);

  /**
   * @brief Record a decision keyed on the full authorization identity.
   *
   * `PolicyCache` never inspects the caller's inputs; the composed key
   * is opaque bytes. The default implementation delegates to the legacy
   * `store` overload after composing.
   */
  virtual void store(const PolicyCacheKey& key,
                     const AuthorizationDecision& decision,
                     std::chrono::system_clock::time_point now);

  /**
   * @brief Best-effort snapshot of the current number of tracked
   *        entries.
   */
  virtual std::size_t size() const = 0;
};

namespace policy_cache_detail {
/**
 * @brief Canonical byte-encoding of a `PolicyCacheKey`.
 *
 * Length-prefixed component digests followed by an 8-byte big-endian
 * `policy_generation`, so two distinct keys can never collide. Exposed
 * so out-of-tree backends that build their own string key agree with
 * the in-tree overloads.
 */
std::string encodeKey(const PolicyCacheKey& key);
}  // namespace policy_cache_detail

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

  using PolicyCache::lookup;
  using PolicyCache::store;

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
