#include "catapult/replay_store.hpp"

#include <sstream>

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

std::string capabilitiesMessage(const char* subject,
                                const StoreCapabilities& caps) {
  std::ostringstream os;
  os << subject << " backend '"
     << (caps.backend_name.empty() ? "unspecified" : caps.backend_name)
     << "' does not meet the deployment's declared fleet-wide "
        "requirements (atomicity="
     << atomicityLabel(caps.atomicity)
     << ", durability=" << durabilityLabel(caps.durability)
     << ", scope=" << scopeLabel(caps.scope)
     << "). Wire a distributed adapter or explicitly relax the "
        "requirement — see FC-4 in docs/security-invariants.md.";
  return os.str();
}

}  // namespace

void requireFleetCapableReplayBackend(const ReplayStore& store,
                                      FleetRequirements requirements) {
  const auto caps = store.capabilities();
  const bool ok = (!requirements.require_cluster_atomicity ||
                   caps.atomicity == StoreAtomicity::ClusterWide) &&
                  (!requirements.require_persistent ||
                   caps.durability == StoreDurability::Persistent) &&
                  (!requirements.require_fleet_scope ||
                   caps.scope == StoreScope::FleetWide);
  if (!ok) {
    throw InsufficientBackendCapabilitiesError(
        capabilitiesMessage("Replay", caps));
  }
}

InMemoryReplayStore::InMemoryReplayStore(std::size_t max_entries,
                                         std::size_t cleanup_every_n_admits,
                                         std::size_t max_jti_bytes)
    : cleanup_interval_(cleanup_every_n_admits == 0 ? 1
                                                    : cleanup_every_n_admits) {
  max_jti_bytes_ = max_jti_bytes == 0 ? 128 : max_jti_bytes;
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

std::size_t InMemoryReplayStore::shardIndex(
    std::string_view jti) const noexcept {
  return std::hash<std::string_view>{}(jti) % active_shards_;
}

ReplayAdmitResult InMemoryReplayStore::admit(
    std::string_view jti, std::chrono::system_clock::time_point now,
    std::chrono::seconds window) {
  // Fail closed on over-cap inputs. Admitting adversarial multi-KB
  // jtis would grow per-entry memory unboundedly; refusing forces the
  // caller to surface the anomaly (which is not a legitimate DPoP
  // proof) rather than the store silently absorbing it.
  if (jti.size() > max_jti_bytes_) {
    return ReplayAdmitResult::StoreExhausted;
  }
  Shard& shard = shards_[shardIndex(jti)];
  std::lock_guard<std::mutex> lock(shard.mu);

  if (auto it = shard.entries.find(std::string(jti));
      it != shard.entries.end()) {
    if (now - it->second < window) {
      return ReplayAdmitResult::Replay;
    }
    // Prior sighting is outside the window — refresh the timestamp in
    // place and admit. This keeps the entry alive as a live record of
    // the current use rather than adding a second one.
    it->second = now;
    return ReplayAdmitResult::Admitted;
  }

  // Fresh jti. Enforce the per-shard cap BEFORE inserting so an
  // exhausted shard cannot be tricked into overshooting by a single
  // slot on the mutating path. Cap-recovery must be exhaustive here —
  // we cannot admit an entry when the sharded cap is genuinely full,
  // and the incremental sweep might miss a reclaimable slot.
  if (shard.entries.size() >= shard.max_entries) {
    shard.purgeExpiredLocked(now, window);
    if (shard.entries.size() >= shard.max_entries) {
      return ReplayAdmitResult::StoreExhausted;
    }
  }

  shard.entries.emplace(std::string(jti), now);
  ++shard.admits_since_cleanup;
  if (shard.admits_since_cleanup >= cleanup_interval_) {
    shard.admits_since_cleanup = 0;
    // Opportunistic housekeeping: bounded so a giant shard cannot cost
    // a single admit call an O(N) sweep. Operators who want a hard
    // drain drive `purgeExpired()` from a scheduler.
    static constexpr std::size_t kOpportunisticBudget = 64;
    shard.purgeIncrementalLocked(now, window, kOpportunisticBudget);
  }
  return ReplayAdmitResult::Admitted;
}

void InMemoryReplayStore::purgeExpired(
    std::chrono::system_clock::time_point now,
    std::chrono::seconds window) {
  for (auto& shard : shards_) {
    std::lock_guard<std::mutex> lock(shard.mu);
    shard.purgeExpiredLocked(now, window);
  }
}

std::size_t InMemoryReplayStore::size() const {
  std::size_t total = 0;
  for (const auto& shard : shards_) {
    std::lock_guard<std::mutex> lock(shard.mu);
    total += shard.entries.size();
  }
  return total;
}

void InMemoryReplayStore::Shard::purgeExpiredLocked(
    std::chrono::system_clock::time_point now,
    std::chrono::seconds window) {
  for (auto it = entries.begin(); it != entries.end();) {
    if (now - it->second > window) {
      it = entries.erase(it);
    } else {
      ++it;
    }
  }
}

void InMemoryReplayStore::Shard::purgeIncrementalLocked(
    std::chrono::system_clock::time_point now, std::chrono::seconds window,
    std::size_t budget) {
  // Bounded sweep. `unordered_map` iteration order is unspecified, so
  // this is a probabilistic drain — over many admits the whole shard
  // gets visited. Since each admit walks at most `budget` entries the
  // per-call cost is O(1). Cap-recovery, where we MUST reclaim if any
  // slot is reclaimable, still uses the full sweep.
  auto it = entries.begin();
  for (std::size_t i = 0; i < budget && it != entries.end(); ++i) {
    if (now - it->second > window) {
      it = entries.erase(it);
    } else {
      ++it;
    }
  }
}

}  // namespace catapult
