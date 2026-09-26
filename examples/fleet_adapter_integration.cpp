/**
 * @file fleet_adapter_integration.cpp
 * @brief How to wire a fleet-capable ReplayStore, UsageStateHook, and
 *        PolicyCache into `CatTokenValidator` and `DpopProofValidator`
 *        for a multi-relay production deployment.
 *
 * This example does NOT ship a production adapter. It illustrates the
 * *integration seam* between catapult's fail-closed startup gate
 * (`requireFleetCapableReplayBackend` / `requireFleetCapableUsageBackend`)
 * and a hypothetical distributed backend (Redis, a database, an
 * SDN-provided KV, etc). A real deployment replaces the `Distributed*`
 * skeletons here with adapters that talk to the shared service.
 *
 * The three moving parts, in order:
 *
 *   1. `DistributedReplayStore`     — DPoP `jti` freshness, atomic across
 *                                     the fleet, ephemeral is fine.
 *   2. `DistributedUsageStore`      — CAT `cti` usage / revocation,
 *                                     atomic + persistent + fleet-scoped.
 *   3. `RelayPolicyCache`           — Decision cache keyed on the full
 *                                     `PolicyCacheKey` (token+resource,
 *                                     context digest, policy generation).
 *
 * The rest of the file is:
 *
 *   - `configureRelay()`  — how a relay wires all three at startup and
 *                           calls the fleet-capability startup gates.
 *   - `admitOneRequest()` — the FC-6-safe admission sequence: cache
 *                           lookup → validate on miss → cache store, with
 *                           replay commit ALWAYS running (never bypassed
 *                           by a cache hit).
 *
 * Read `docs/security-invariants.md` §3 alongside this file — the code
 * mirrors the numbered admission steps there.
 */

#include <atomic>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

#include "catapult/policy_cache.hpp"
#include "catapult/replay_store.hpp"
#include "catapult/usage_state.hpp"

using namespace catapult;
using Clock = std::chrono::system_clock;

// ---------------------------------------------------------------------------
// 1. DistributedReplayStore — DPoP jti freshness with cluster atomicity.
//
// A production adapter forwards `admit()` to a service whose primitive
// is atomic across every relay: Redis `SET NX PX`, a SERIALIZABLE
// database transaction, an etcd compare-and-swap, etc. The skeleton
// below stubs that call out — the important part is:
//
//   - `capabilities()` reports the truth. Under-report and the startup
//     gate rejects your relay. Over-report and the gate lets a
//     non-atomic backend through and your fleet silently accepts
//     replayed DPoP proofs.
//
//   - Transient backend errors surface as `StoreExhausted`, NOT as a
//     silent `Admitted`. Catapult treats `StoreExhausted` as
//     `ReplayAttackError` (FC-5).
// ---------------------------------------------------------------------------
class DistributedReplayStore final : public ReplayStore {
 public:
  // Wrap a real client: cluster_ owns the network connection, timeouts,
  // and retry policy. The example uses a local map to keep the file
  // self-contained; a real implementation would keep no local state.
  struct Backend {
    // Return true if `jti` was inserted freshly with the given TTL
    // (atomically); false if a live entry already exists; nullopt on
    // transient backend error (translated below to `StoreExhausted`).
    virtual std::optional<bool> checkAndSet(
        std::string_view jti, std::chrono::seconds ttl) = 0;
    virtual ~Backend() = default;
  };

  explicit DistributedReplayStore(std::shared_ptr<Backend> backend,
                                  std::string backend_name = "distributed")
      : backend_(std::move(backend)), backend_name_(std::move(backend_name)) {}

  ReplayAdmitResult admit(std::string_view jti, Clock::time_point /*now*/,
                          std::chrono::seconds window) override {
    auto result = backend_->checkAndSet(jti, window);
    if (!result.has_value()) {
      // Transient backend failure: fail closed. Do NOT translate to
      // `Admitted`. Catapult will surface this as `ReplayAttackError`.
      return ReplayAdmitResult::StoreExhausted;
    }
    return *result ? ReplayAdmitResult::Admitted
                   : ReplayAdmitResult::Replay;
  }

  void purgeExpired(Clock::time_point, std::chrono::seconds) override {
    // The distributed backend handles TTL expiry itself.
  }

  std::size_t size() const override { return 0; }

  // The whole point of this adapter. If the operator swapped in a
  // backend that in fact does NOT provide cluster atomicity, the honest
  // thing to do is downgrade the reported atomicity — the startup gate
  // will then refuse to boot the relay, which is exactly the failure
  // mode we want.
  StoreCapabilities capabilities() const override {
    return StoreCapabilities{StoreAtomicity::ClusterWide,
                             StoreDurability::Ephemeral,
                             StoreScope::FleetWide, backend_name_};
  }

 private:
  std::shared_ptr<Backend> backend_;
  std::string backend_name_;
};

// ---------------------------------------------------------------------------
// 2. DistributedUsageStore — CAT cti usage, atomic + persistent + shared.
//
// Same shape as the replay store, but semantics differ: `catreplay` mode
// determines whether a duplicate cti is `Replay` or `Revoked`, and an
// explicit `revoke()` marks a cti bad for the remainder of the token's
// lifetime (typically bounded by `exp`).
//
// For `RevokeOnReplay` you MUST report `Persistent`: a revocation that
// vanishes on process restart re-admits a token an operator has
// explicitly rejected.
// ---------------------------------------------------------------------------
class DistributedUsageStore final : public UsageStateHook {
 public:
  struct Backend {
    virtual std::optional<UsageAdmitResult> admit(
        std::string_view cti, CatReplayMode mode,
        std::optional<Clock::time_point> expiry) = 0;
    virtual std::optional<RevokeResult> revoke(std::string_view cti) = 0;
    virtual ~Backend() = default;
  };

  explicit DistributedUsageStore(std::shared_ptr<Backend> backend,
                                 std::string backend_name = "distributed")
      : backend_(std::move(backend)), backend_name_(std::move(backend_name)) {}

  UsageAdmitResult admit(
      std::string_view cti, CatReplayMode mode, Clock::time_point /*now*/,
      std::optional<Clock::time_point> expiry) override {
    auto r = backend_->admit(cti, mode, expiry);
    // Transient backend failure: fail closed as StoreExhausted, NOT as
    // Admitted. The validator will translate that into a rejection.
    return r.value_or(UsageAdmitResult::StoreExhausted);
  }

  RevokeResult revoke(std::string_view cti) override {
    auto r = backend_->revoke(cti);
    // Same fail-closed rule for revocation: refusing to record a
    // revocation is safer than silently claiming success and later
    // admitting the token.
    return r.value_or(RevokeResult::StoreExhausted);
  }

  void purgeExpired(Clock::time_point) override {
    // Backend-driven TTL cleanup.
  }
  std::size_t size() const override { return 0; }

  StoreCapabilities capabilities() const override {
    return StoreCapabilities{StoreAtomicity::ClusterWide,
                             StoreDurability::Persistent,
                             StoreScope::FleetWide, backend_name_};
  }

 private:
  std::shared_ptr<Backend> backend_;
  std::string backend_name_;
};

// ---------------------------------------------------------------------------
// 3. RelayPolicyCache — decision cache with FC-7 keying.
//
// `InMemoryPolicyCache` ships as an in-tree default; this class shows
// the *keying discipline* a relay MUST follow, regardless of whether it
// uses the in-tree cache or a shared one. Two rules:
//
//   - Use the `PolicyCacheKey` overload of `lookup`/`store`, not the
//     legacy `string_view` one. The composite key includes the context
//     digest and `policy_generation`.
//
//   - Bump `policy_generation` on ANY policy code, key-set, or
//     revocation-feed change so every prior decision becomes
//     unreachable in the map (FC-7).
//
// This class wraps an underlying PolicyCache and enforces those rules
// at the call site.
// ---------------------------------------------------------------------------
class RelayPolicyCache {
 public:
  explicit RelayPolicyCache(std::unique_ptr<PolicyCache> backing)
      : backing_(std::move(backing)) {}

  // Operators call this on any policy/revocation update. All prior
  // cached decisions become unreachable after the bump.
  void bumpPolicyGeneration() {
    policy_generation_.fetch_add(1, std::memory_order_release);
  }

  std::uint64_t policyGeneration() const {
    return policy_generation_.load(std::memory_order_acquire);
  }

  std::optional<AuthorizationDecision> lookup(
      std::string_view token_resource_digest,
      std::string_view context_digest, Clock::time_point now) {
    PolicyCacheKey key{token_resource_digest, context_digest,
                       policyGeneration()};
    return backing_->lookup(key, now);
  }

  void store(std::string_view token_resource_digest,
             std::string_view context_digest,
             const AuthorizationDecision& decision, Clock::time_point now) {
    PolicyCacheKey key{token_resource_digest, context_digest,
                       policyGeneration()};
    backing_->store(key, decision, now);
  }

 private:
  std::unique_ptr<PolicyCache> backing_;
  std::atomic<std::uint64_t> policy_generation_{1};
};

// ---------------------------------------------------------------------------
// Startup configuration. This is where the fleet-capability gate fires:
// if the operator wired the wrong adapter (or forgot to override
// `capabilities()` on a hand-rolled one), `requireFleetCapable*` throws
// and the relay refuses to boot.
// ---------------------------------------------------------------------------
struct RelayConfig {
  std::shared_ptr<ReplayStore> replay_store;
  std::unique_ptr<UsageStateHook> usage_state;
  std::unique_ptr<RelayPolicyCache> policy_cache;
};

RelayConfig configureRelay(
    std::shared_ptr<DistributedReplayStore::Backend> replay_backend,
    std::shared_ptr<DistributedUsageStore::Backend> usage_backend) {
  RelayConfig cfg;
  cfg.replay_store =
      std::make_shared<DistributedReplayStore>(std::move(replay_backend));
  cfg.usage_state = std::make_unique<DistributedUsageStore>(
      std::move(usage_backend));

  // Startup gate. If either backend under-reports its capabilities the
  // relay refuses to boot — this is FC-4 in `docs/security-invariants.md`
  // and by design.
  //
  // DPoP jti freshness runs against a short replay window; an ephemeral
  // backend is acceptable there as long as it is cluster-atomic and
  // fleet-scoped. Persistence is only mandatory for the usage-state
  // hook (revocations must survive restart). We spell out the relaxed
  // requirements at the call site so the decision is auditable.
  FleetRequirements dpop_requirements{
      /*require_cluster_atomicity=*/true,
      /*require_persistent=*/false,  // jti window is short; ephemeral ok
      /*require_fleet_scope=*/true,
  };
  requireFleetCapableReplayBackend(*cfg.replay_store, dpop_requirements);
  requireFleetCapableUsageBackend(*cfg.usage_state);  // full requirements

  // The policy cache itself does not need a fleet gate — it is an
  // optimization and `lookup()` on a cold cache is always safe (FC-6).
  // But keying discipline (FC-7) must be enforced at the call site;
  // `RelayPolicyCache` does that by construction.
  cfg.policy_cache = std::make_unique<RelayPolicyCache>(
      std::make_unique<InMemoryPolicyCache>(/*max_entries=*/100'000));

  return cfg;
}

// ---------------------------------------------------------------------------
// Per-request admission. Sketches the FC-6-safe order:
//
//   1. Compute cache key (token+resource digest, context digest).
//   2. Cache lookup. Hit ==> STILL run replay/usage admission.
//   3. Cache miss ==> run full validation. Then admit through replay/
//      usage stores. Then store the decision.
//
// A cache hit MUST NOT bypass replay-consuming operations; the cache
// remembers decisions, not nonce consumption. This example shows the
// pattern — a real relay plugs `CatTokenValidator::validate*` calls in
// where the comments say "full validation".
// ---------------------------------------------------------------------------
struct AdmitInputs {
  std::string_view token_resource_digest;  // caller-computed
  std::string_view context_digest;         // caller-computed
  std::string_view dpop_jti;               // from parsed DPoP proof
  std::string_view cat_cti;                // from parsed CAT token
  CatReplayMode catreplay = CatReplayMode::None;
  std::optional<Clock::time_point> cat_exp;
  std::chrono::seconds dpop_window{60};
};

bool admitOneRequest(RelayConfig& cfg, const AdmitInputs& in,
                     Clock::time_point now) {
  // Step 1+2: cache lookup keyed on the full authorization identity.
  //
  // Note: even on a cache HIT we still run the replay/usage admissions
  // below. Skipping them here would let an attacker replay a DPoP proof
  // whose jti was accepted on a prior request — the cache remembers the
  // *decision*, not that we already consumed the jti nonce.
  auto cached = cfg.policy_cache->lookup(in.token_resource_digest,
                                         in.context_digest, now);
  if (!cached.has_value()) {
    // Step 3a: full validation. In real code this is
    // `CatTokenValidator::validate(token, context)` and returns a
    // ValidatedCatToken via `intoValidated(context)`. Any rejection
    // here MUST be recorded so future identical requests short-circuit
    // rather than re-doing signature verification.
    // (Placeholder: pretend validation returned Allow.)
    AuthorizationDecision fresh{
        AuthorizationOutcome::Allow,
        in.cat_exp.value_or(now + std::chrono::minutes(5))};
    cfg.policy_cache->store(in.token_resource_digest, in.context_digest,
                            fresh, now);
    cached = fresh;
  } else if (cached->outcome == AuthorizationOutcome::Deny) {
    // Cached deny short-circuits: no replay admission (nothing to
    // consume) and no further work.
    return false;
  }

  // Step 3b: DPoP jti admission. Fires on every request, regardless of
  // cache hit/miss. `StoreExhausted` → fail closed.
  auto jti_result = cfg.replay_store->admit(in.dpop_jti, now, in.dpop_window);
  if (jti_result != ReplayAdmitResult::Admitted) {
    return false;
  }

  // Step 3c: cti usage admission for RejectOnReplay / RevokeOnReplay.
  // `None` skips this hook by contract.
  if (in.catreplay != CatReplayMode::None) {
    auto cti_result = cfg.usage_state->admit(in.cat_cti, in.catreplay, now,
                                             in.cat_exp);
    if (cti_result != UsageAdmitResult::Admitted) {
      return false;
    }
  }

  return cached->outcome == AuthorizationOutcome::Allow;
}

// ---------------------------------------------------------------------------
// A minimal harness that exercises the wiring. Real relays don't need
// this — it is here so the example compiles and demonstrates the
// startup gate firing.
// ---------------------------------------------------------------------------
namespace {

class FakeReplayBackend final : public DistributedReplayStore::Backend {
 public:
  std::optional<bool> checkAndSet(std::string_view jti,
                                  std::chrono::seconds) override {
    std::lock_guard<std::mutex> lock(mu_);
    auto [_, inserted] = seen_.emplace(std::string(jti));
    return inserted;
  }
 private:
  std::mutex mu_;
  std::unordered_set<std::string> seen_;
};

class FakeUsageBackend final : public DistributedUsageStore::Backend {
 public:
  std::optional<UsageAdmitResult> admit(
      std::string_view cti, CatReplayMode,
      std::optional<Clock::time_point>) override {
    std::lock_guard<std::mutex> lock(mu_);
    auto [_, inserted] = seen_.emplace(std::string(cti));
    return inserted ? UsageAdmitResult::Admitted
                    : UsageAdmitResult::Replay;
  }
  std::optional<RevokeResult> revoke(std::string_view cti) override {
    std::lock_guard<std::mutex> lock(mu_);
    revoked_.emplace(std::string(cti));
    return RevokeResult::Accepted;
  }
 private:
  std::mutex mu_;
  std::unordered_set<std::string> seen_;
  std::unordered_set<std::string> revoked_;
};

}  // namespace

int main() {
  auto cfg = configureRelay(std::make_shared<FakeReplayBackend>(),
                            std::make_shared<FakeUsageBackend>());
  std::cout << "Fleet-capable adapters passed the startup gate.\n";

  const auto now = Clock::now();
  const std::string token_digest(32, 'A');
  const std::string ctx_digest(16, 'B');
  const std::string jti("jti-1");
  const std::string cti("cti-1");

  AdmitInputs in{
      .token_resource_digest = token_digest,
      .context_digest = ctx_digest,
      .dpop_jti = jti,
      .cat_cti = cti,
      .catreplay = CatReplayMode::RejectOnReplay,
      .cat_exp = now + std::chrono::minutes(5),
      .dpop_window = std::chrono::seconds(60),
  };

  const bool first = admitOneRequest(cfg, in, now);
  const bool second = admitOneRequest(cfg, in, now);
  std::cout << "First admission:  " << (first ? "allow" : "deny") << "\n";
  std::cout << "Second admission: " << (second ? "allow" : "deny")
            << "  (must be deny — jti was consumed even on cache hit)\n";

  // Demonstrate the startup gate rejecting the in-tree default when
  // fleet-wide is required.
  try {
    InMemoryReplayStore in_memory;
    requireFleetCapableReplayBackend(in_memory);
    std::cout << "UNEXPECTED: in-memory default passed the fleet gate\n";
    return 1;
  } catch (const InsufficientBackendCapabilitiesError& e) {
    std::cout << "Startup gate refused the in-memory default (expected):\n  "
              << e.what() << "\n";
  }

  // Demonstrate policy-generation invalidation.
  cfg.policy_cache->bumpPolicyGeneration();
  std::cout << "Policy generation bumped; every prior cached decision is "
               "now unreachable by construction (FC-7).\n";

  return 0;
}
