/**
 * @file key_resolver.hpp
 * @brief Pluggable verification-key lookup for CWT / DPoP validation.
 *
 * `Cwt::validateCwt()` takes a fully-resolved `CryptographicAlgorithm` today
 * because catapult itself does not know which key material to trust — that
 * decision belongs to the deployment (a relay may resolve keys from a
 * hosted JWKS URL, a signed feed, a local file, or a preprovisioned map).
 *
 * `KeyResolver` is the seam. Given the routing metadata in a COSE protected
 * header (`kid`, `alg`), the resolver returns the verifier that catapult
 * should use, or throws to reject the token outright. The library ships
 * `StaticKeyResolver` as an in-tree default suitable for tests, examples,
 * and deployments where the key set is fixed at process start.
 *
 * ## Contract
 *
 * `resolve()` MUST be safe to call concurrently — a relay may validate
 * many tokens in parallel and each will call in.
 *
 * `resolve()` MUST return the same verifier for the same `(kid, alg)` pair
 * for the lifetime of a validated token: catapult calls it exactly once
 * per validation, but a resolver that rotates keys mid-request without
 * external coordination can produce inconsistent verification outcomes
 * against composite claims.
 *
 * On unknown `kid`, on unknown `alg`, or when the presented `alg` does not
 * match the algorithm bound to the resolved key, resolvers MUST throw
 * (typically `MissingKeyError` or `CryptoError`). Returning nullptr or a
 * mismatched algorithm is a fail-open bug.
 *
 * ## Fail-open vs fail-closed
 *
 * Every default implementation in this file fails closed: unknown kid,
 * empty resolver, or algorithm mismatch all throw. Deployments that need
 * a "trust anything with a kid" resolver must write their own — the
 * library will not ship a default that opens that hole.
 */

#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include "error.hpp"

namespace catapult {

class CryptographicAlgorithm;

/**
 * @brief Thrown when a KeyResolver cannot map (kid, alg) to a verifier.
 *
 * Distinct from generic CryptoError so relays can surface a specific
 * error code for "we don't recognize this signing key" separately from
 * "signature verification failed against a key we do recognize".
 */
class MissingKeyError : public CatError {
 public:
  explicit MissingKeyError(std::string_view details)
      : CatError(CatErrorCode::CRYPTO_OPERATION_FAILED,
                 std::string("Verification key not resolvable: ") +
                     std::string(details)) {}
};

/**
 * @brief Abstract verification-key lookup hook.
 *
 * Given the `kid` and `alg` extracted from a COSE protected header, return
 * the `CryptographicAlgorithm` catapult should use to verify the token.
 *
 * The returned reference must remain valid until the current validation
 * call returns; a resolver that owns its algorithms internally satisfies
 * this trivially. Resolvers that hand out algorithms owned elsewhere are
 * responsible for ensuring lifetime.
 */
class KeyResolver {
 public:
  virtual ~KeyResolver() = default;

  /**
   * @brief Resolve a verifier for the given routing metadata.
   *
   * @param kid Key ID from the COSE protected header (label 4). May be
   *   empty when the token omits `kid`; resolvers that require a kid MUST
   *   throw MissingKeyError in that case rather than silently picking
   *   a default.
   * @param alg COSE algorithm identifier from the protected header
   *   (label 1). Used both to route the lookup and to reject a token that
   *   presents an algorithm the resolved key was not issued for.
   * @return Reference to a CryptographicAlgorithm bound to the matching
   *   verification key.
   * @throws MissingKeyError if no key matches the routing metadata.
   * @throws CryptoError if the resolved key exists but is not usable for
   *   the presented algorithm.
   */
  virtual const CryptographicAlgorithm& resolve(std::string_view kid,
                                                int64_t alg) const = 0;
};

/**
 * @brief In-process static key set with lookup by (kid, alg).
 *
 * Suitable for tests, examples, and deployments where the trusted key set
 * is known at process start and does not rotate. Multi-process fleets or
 * setups that hot-load JWKS documents should write a resolver that owns a
 * refreshable index.
 *
 * ## Lifetime
 *
 * `add()` takes a shared_ptr so the resolver participates in ownership.
 * The stored algorithm outlives every `resolve()` call by construction —
 * callers do not need to keep the algorithm alive separately.
 *
 * ## Thread safety
 *
 * `resolve()` is safe to call concurrently once the resolver is populated;
 * the underlying map is read-only after `add()` calls stop. Callers must
 * not interleave `add()` with `resolve()` — build the resolver during
 * startup, then hand it out.
 *
 * ## Fail-closed semantics
 *
 * An empty resolver rejects every lookup. An unknown kid rejects. A known
 * kid presented with a mismatched alg rejects. There is no "if in doubt,
 * accept" path.
 */
class StaticKeyResolver final : public KeyResolver {
 public:
  /**
   * @brief Register a verifier for a (kid, alg) pair.
   *
   * @param kid Key identifier. Empty kids are permitted — a token that
   *   omits kid can still be routed if the resolver has an empty-kid
   *   entry — but they are not preferred; prefer explicit kids in
   *   production.
   * @param alg COSE algorithm identifier bound to this key. Registering
   *   the same kid under multiple algs is supported (some deployments
   *   rotate signing algorithms without changing key material).
   * @param algorithm Verifier. Ownership is shared with the resolver.
   */
  void add(std::string kid, int64_t alg,
           std::shared_ptr<const CryptographicAlgorithm> algorithm);

  const CryptographicAlgorithm& resolve(std::string_view kid,
                                        int64_t alg) const override;

  /**
   * @brief Number of registered (kid, alg) entries.
   *
   * Primarily for tests and diagnostics — a production resolver typically
   * does not need to expose its interior.
   */
  std::size_t size() const noexcept;

 private:
  struct Key {
    std::string kid;
    int64_t alg;
    bool operator==(const Key& other) const noexcept {
      return kid == other.kid && alg == other.alg;
    }
  };
  struct KeyHash {
    std::size_t operator()(const Key& k) const noexcept {
      // Boost-style hash combine. int64_t alg is folded in via the
      // fixed multiplicative constant used by the C++ standard's
      // "golden ratio" hash-mixing convention.
      auto h1 = std::hash<std::string>{}(k.kid);
      auto h2 = std::hash<int64_t>{}(k.alg);
      return h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6) + (h1 >> 2));
    }
  };

  std::unordered_map<Key, std::shared_ptr<const CryptographicAlgorithm>,
                     KeyHash>
      entries_;
};

}  // namespace catapult
