#include "catapult/usage_state.hpp"

#include <sstream>

#include "catapult/replay_store.hpp"

namespace catapult {

namespace {

const char* atomicityLabel(StoreAtomicity a) {
  return a == StoreAtomicity::ClusterWide ? "cluster-wide" : "per-process";
}
const char* durabilityLabel(StoreDurability d) {
  return d == StoreDurability::Persistent ? "persistent" : "ephemeral";
}
const char* scopeLabel(StoreScope s) {
  return s == StoreScope::FleetWide ? "fleet-wide" : "single-node";
}

}  // namespace

void requireFleetCapableUsageBackend(const UsageStateHook& hook,
                                     FleetRequirements requirements) {
  const auto caps = hook.capabilities();
  const bool ok = (!requirements.require_cluster_atomicity ||
                   caps.atomicity == StoreAtomicity::ClusterWide) &&
                  (!requirements.require_persistent ||
                   caps.durability == StoreDurability::Persistent) &&
                  (!requirements.require_fleet_scope ||
                   caps.scope == StoreScope::FleetWide);
  if (!ok) {
    std::ostringstream os;
    os << "Usage-state backend '"
       << (caps.backend_name.empty() ? "unspecified" : caps.backend_name)
       << "' does not meet the deployment's declared fleet-wide "
          "requirements (atomicity="
       << atomicityLabel(caps.atomicity)
       << ", durability=" << durabilityLabel(caps.durability)
       << ", scope=" << scopeLabel(caps.scope)
       << "). Wire a distributed adapter or explicitly relax the "
          "requirement — see FC-4 in docs/security-invariants.md.";
    throw InsufficientBackendCapabilitiesError(os.str());
  }
}

InMemoryUsageState::InMemoryUsageState(std::size_t max_entries,
                                       std::size_t cleanup_every_n_admits,
                                       std::size_t max_cti_bytes)
    : cleanup_interval_(cleanup_every_n_admits == 0 ? 1
                                                    : cleanup_every_n_admits) {
  max_cti_bytes_ = max_cti_bytes == 0 ? 128 : max_cti_bytes;
  const std::size_t effective = max_entries == 0 ? 1 : max_entries;
  // See `InMemoryPolicyCache`: tiny caps fall back to one shard so the
  // combined cap is exactly `max_entries` and per-shard mechanics do
  // not diverge from a caller's mental model of a single bounded store.
  active_shards_ = effective < kShardCount ? 1 : kShardCount;
  const std::size_t per_shard = effective / active_shards_;
  const std::size_t remainder = effective % active_shards_;
  for (std::size_t i = 0; i < kShardCount; ++i) {
    if (i < active_shards_) {
      shards_[i].max_entries = per_shard + (i < remainder ? 1 : 0);
    } else {
      shards_[i].max_entries = 0;
    }
  }
}

std::size_t InMemoryUsageState::shardIndex(
    std::string_view cti) const noexcept {
  return std::hash<std::string_view>{}(cti) % active_shards_;
}

UsageAdmitResult InMemoryUsageState::admit(
    std::string_view cti, CatReplayMode mode,
    std::chrono::system_clock::time_point now,
    std::optional<std::chrono::system_clock::time_point> expiry) {
  // Fail closed on over-cap cti. The validator treats StoreExhausted as
  // a replay-attack signal, so refusing admits of oversize identifiers
  // both bounds memory and surfaces the anomaly.
  if (cti.size() > max_cti_bytes_) {
    return UsageAdmitResult::StoreExhausted;
  }
  Shard& shard = shards_[shardIndex(cti)];
  std::lock_guard<std::mutex> lock(shard.mu);

  const std::string key(cti);

  // Revoked entries take precedence over the admitted map — a cti moved
  // to the revoked set must never round-trip back to `Admitted`, even if
  // an `admit()` from a stale path arrives with a still-valid expiry.
  if (shard.revoked.find(key) != shard.revoked.end()) {
    return UsageAdmitResult::Revoked;
  }

  if (auto it = shard.admitted.find(key); it != shard.admitted.end()) {
    // Prior sighting exists. If its expiry is set and has passed, we may
    // reclaim the slot and readmit — the earlier grant is no longer live,
    // so a new presentation of the same cti after `exp` is not a replay
    // *of a currently valid grant*. If expiry is unset (or in the
    // future), it IS a replay.
    if (it->second.expiry.has_value() && now >= *it->second.expiry) {
      it->second.expiry = expiry;
      return UsageAdmitResult::Admitted;
    }

    // `RevokeOnReplay`: sighting the same cti a second time promotes the
    // entry from "admitted" to "revoked" so any future presentation
    // fails regardless of its declared `catreplay` mode. This preserves
    // the CTA-5007-B §4.6.9 mode-2 invariant across a token's remaining
    // lifetime. Because we're transferring one entry across sets, no
    // net capacity change happens.
    if (mode == CatReplayMode::RevokeOnReplay) {
      shard.admitted.erase(it);
      // Slot transfer: we just freed one admitted slot, so insert cannot
      // exhaust unless another thread raced in between — impossible while
      // we hold the shard's mutex. Return is always `Accepted`.
      (void)shard.insertRevokedLocked(key);
      return UsageAdmitResult::Revoked;
    }
    return UsageAdmitResult::Replay;
  }

  // Fresh cti. Enforce the per-shard cap BEFORE inserting so an
  // exhausted shard cannot be tricked into overshooting by a single
  // slot on the mutating path. Cap covers both admitted + revoked
  // entries within the shard.
  auto shard_total = [&]() {
    return shard.admitted.size() + shard.revoked.size();
  };
  if (shard_total() >= shard.max_entries) {
    shard.purgeExpiredLocked(now);
    if (shard_total() >= shard.max_entries) {
      ++shard.exhaustion_events;
      return UsageAdmitResult::StoreExhausted;
    }
  }

  shard.admitted.emplace(key, Entry{expiry});
  ++shard.admits_since_cleanup;
  if (shard.admits_since_cleanup >= cleanup_interval_) {
    shard.admits_since_cleanup = 0;
    // Opportunistic housekeeping: bounded so a large shard cannot cost
    // one admit call an O(N) sweep. Cap-recovery above still uses the
    // exhaustive `purgeExpiredLocked`.
    static constexpr std::size_t kOpportunisticBudget = 64;
    shard.purgeIncrementalLocked(now, kOpportunisticBudget);
  }
  return UsageAdmitResult::Admitted;
}

RevokeResult InMemoryUsageState::revoke(std::string_view cti) {
  // Refuse over-cap revocations: an operator explicitly recording bad
  // ctis should not be able to blow memory by looping oversize inputs
  // through this path. `StoreExhausted` surfaces the refusal.
  if (cti.size() > max_cti_bytes_) {
    return RevokeResult::StoreExhausted;
  }
  Shard& shard = shards_[shardIndex(cti)];
  std::lock_guard<std::mutex> lock(shard.mu);
  const std::string key(cti);
  // Erase any prior admission first: doing so releases one slot before
  // insertRevokedLocked runs the cap check, which is what allows an
  // already-admitted cti to always be revokable regardless of store fill.
  shard.admitted.erase(key);
  return shard.insertRevokedLocked(key);
}

void InMemoryUsageState::purgeExpired(
    std::chrono::system_clock::time_point now) {
  for (auto& shard : shards_) {
    std::lock_guard<std::mutex> lock(shard.mu);
    shard.purgeExpiredLocked(now);
  }
}

std::size_t InMemoryUsageState::size() const {
  std::size_t total = 0;
  for (const auto& shard : shards_) {
    std::lock_guard<std::mutex> lock(shard.mu);
    total += shard.admitted.size() + shard.revoked.size();
  }
  return total;
}

std::size_t InMemoryUsageState::exhaustion_events() const {
  std::size_t total = 0;
  for (const auto& shard : shards_) {
    std::lock_guard<std::mutex> lock(shard.mu);
    total += shard.exhaustion_events;
  }
  return total;
}

void InMemoryUsageState::Shard::purgeExpiredLocked(
    std::chrono::system_clock::time_point now) {
  for (auto it = admitted.begin(); it != admitted.end();) {
    if (it->second.expiry.has_value() && now >= *it->second.expiry) {
      it = admitted.erase(it);
    } else {
      ++it;
    }
  }
}

void InMemoryUsageState::Shard::purgeIncrementalLocked(
    std::chrono::system_clock::time_point now, std::size_t budget) {
  auto it = admitted.begin();
  for (std::size_t i = 0; i < budget && it != admitted.end(); ++i) {
    if (it->second.expiry.has_value() && now >= *it->second.expiry) {
      it = admitted.erase(it);
    } else {
      ++it;
    }
  }
}

RevokeResult InMemoryUsageState::Shard::insertRevokedLocked(
    const std::string& key) {
  // Idempotent: re-revoking an already-revoked cti is a no-op that reports
  // success. The cti is (still) recorded as revoked, which is the outcome
  // the caller asked for.
  if (revoked.find(key) != revoked.end()) {
    return RevokeResult::Accepted;
  }

  // Enforce the shard cap. When we cannot fit the new revocation we
  // refuse it and leave the shard untouched: silently evicting an older
  // revocation would forget operator intent that was already committed,
  // which is a more dangerous failure than surfacing exhaustion.
  if (admitted.size() + revoked.size() >= max_entries) {
    ++exhaustion_events;
    return RevokeResult::StoreExhausted;
  }

  revoked.insert(key);
  return RevokeResult::Accepted;
}

}  // namespace catapult
