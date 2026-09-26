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
                                         std::size_t cleanup_every_n_admits)
    : max_entries_(max_entries == 0 ? 1 : max_entries),
      cleanup_interval_(
          cleanup_every_n_admits == 0 ? 1 : cleanup_every_n_admits) {}

ReplayAdmitResult InMemoryReplayStore::admit(
    std::string_view jti, std::chrono::system_clock::time_point now,
    std::chrono::seconds window) {
  std::lock_guard<std::mutex> lock(mu_);

  if (auto it = entries_.find(std::string(jti)); it != entries_.end()) {
    if (now - it->second < window) {
      return ReplayAdmitResult::Replay;
    }
    // Prior sighting is outside the window — refresh the timestamp in
    // place and admit. This keeps the entry alive as a live record of
    // the current use rather than adding a second one.
    it->second = now;
    return ReplayAdmitResult::Admitted;
  }

  // Fresh jti. Enforce the size cap BEFORE inserting so an exhausted
  // store cannot be tricked into overshooting `max_entries_` by a single
  // slot on the mutating path.
  if (entries_.size() >= max_entries_) {
    purgeExpiredLocked(now, window);
    if (entries_.size() >= max_entries_) {
      return ReplayAdmitResult::StoreExhausted;
    }
  }

  entries_.emplace(std::string(jti), now);
  ++admits_since_cleanup_;
  if (admits_since_cleanup_ >= cleanup_interval_) {
    admits_since_cleanup_ = 0;
    purgeExpiredLocked(now, window);
  }
  return ReplayAdmitResult::Admitted;
}

void InMemoryReplayStore::purgeExpired(
    std::chrono::system_clock::time_point now,
    std::chrono::seconds window) {
  std::lock_guard<std::mutex> lock(mu_);
  purgeExpiredLocked(now, window);
}

std::size_t InMemoryReplayStore::size() const {
  std::lock_guard<std::mutex> lock(mu_);
  return entries_.size();
}

void InMemoryReplayStore::purgeExpiredLocked(
    std::chrono::system_clock::time_point now,
    std::chrono::seconds window) {
  for (auto it = entries_.begin(); it != entries_.end();) {
    if (now - it->second > window) {
      it = entries_.erase(it);
    } else {
      ++it;
    }
  }
}

}  // namespace catapult
