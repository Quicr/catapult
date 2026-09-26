/**
 * @file store_capabilities.hpp
 * @brief Backend capability reporting for replay and usage state stores.
 *
 * `catreplay` enforcement and DPoP `jti` freshness both rely on a
 * check-and-record primitive whose *scope of truth* is not visible from
 * the interface signatures alone. A `ReplayStore` that returns `Admitted`
 * on one relay replica but not another — because they use process-local
 * stores — silently downgrades the guarantee the token issuer requested.
 *
 * `StoreCapabilities` is the seam operators use to prevent that at
 * startup. Every `ReplayStore` and `UsageStateHook` reports what it
 * can promise; a fleet whose deployment plan requires cross-replica
 * atomicity refuses to boot against a backend that cannot deliver it.
 *
 * The default reported by both in-tree in-memory stores is deliberately
 * pessimistic — `atomicity == PerProcess`, `durability == Ephemeral`,
 * `scope == SingleNode`. Distributed adapters override.
 */

#pragma once

#include <string>

namespace catapult {

/**
 * @brief Atomicity domain of the `admit()` check-and-record primitive.
 */
enum class StoreAtomicity {
  /// `admit()` is atomic against every concurrent caller of this same
  /// store instance. Two threads racing on the same jti/cti observe
  /// exactly one `Admitted` and one `Replay`.
  PerProcess,
  /// `admit()` is atomic against every caller of every process that
  /// shares this backend. A distributed store (Redis with WATCH/MULTI,
  /// a database with SERIALIZABLE isolation, a coordination service
  /// like etcd) that guarantees cross-replica linearizability reports
  /// this level. The library never assumes this without an explicit
  /// declaration — the interface signature does not distinguish.
  ClusterWide,
};

/**
 * @brief Persistence guarantee across restarts.
 */
enum class StoreDurability {
  /// State does not survive process restart. Every `admit()` on a
  /// freshly-started process sees an empty store. Suitable for tests and
  /// short-lived single-node deployments where token TTLs are shorter
  /// than the mean uptime.
  Ephemeral,
  /// State survives restarts up to at least the maximum token exp used
  /// by the deployment. Required for `RevokeOnReplay` because a revoked
  /// `cti` must remain revoked across the entire lifetime an attacker
  /// could still present the token.
  Persistent,
};

/**
 * @brief Sharing scope of the store across relay instances.
 */
enum class StoreScope {
  /// Each relay process has its own private state. Suitable for a
  /// single-relay deployment; catastrophically weakens replay
  /// enforcement when a fleet of relays each answers the same token.
  SingleNode,
  /// The store is shared among every relay that talks to the same
  /// backend. A jti admitted on relay A is a replay on relay B.
  FleetWide,
};

/**
 * @brief Capabilities self-reported by a replay or usage-state backend.
 *
 * A caller uses `requireFleetCapable*` (see `replay_store.hpp` /
 * `usage_state.hpp`) at startup to enforce a deployment-wide minimum
 * before accepting the backend.
 */
struct StoreCapabilities {
  StoreAtomicity atomicity = StoreAtomicity::PerProcess;
  StoreDurability durability = StoreDurability::Ephemeral;
  StoreScope scope = StoreScope::SingleNode;
  /// Free-form identifier for operator logs (`"in-memory"`, `"redis"`).
  /// Not parsed by the library; surfaced verbatim in startup errors so
  /// an operator can diff the reported backend against the intended one.
  std::string backend_name;
};

/**
 * @brief The set of capabilities a fleet-wide replay/usage guarantee
 *        requires.
 *
 * Cross-replica atomicity, fleet-wide scope, and — for `RevokeOnReplay`
 * / stored revocations — durability across restarts. The in-tree
 * in-memory defaults satisfy none of these; a distributed adapter that
 * satisfies all three is what a production CDN configuration MUST wire
 * before enabling `catreplay` modes across replicas.
 */
struct FleetRequirements {
  bool require_cluster_atomicity = true;
  bool require_persistent = true;
  bool require_fleet_scope = true;
};

}  // namespace catapult
