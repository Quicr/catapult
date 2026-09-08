#include "catapult/usage_state.hpp"

namespace catapult {

InMemoryUsageState::InMemoryUsageState(std::size_t max_entries,
                                       std::size_t cleanup_every_n_admits)
    : max_entries_(max_entries == 0 ? 1 : max_entries),
      cleanup_interval_(
          cleanup_every_n_admits == 0 ? 1 : cleanup_every_n_admits) {}

UsageAdmitResult InMemoryUsageState::admit(
    std::string_view cti, CatReplayMode mode,
    std::chrono::system_clock::time_point now,
    std::optional<std::chrono::system_clock::time_point> expiry) {
  std::lock_guard<std::mutex> lock(mu_);

  const std::string key(cti);

  // Revoked entries take precedence over the admitted map — a cti moved
  // to the revoked set must never round-trip back to `Admitted`, even if
  // an `admit()` from a stale path arrives with a still-valid expiry.
  if (revoked_.find(key) != revoked_.end()) {
    return UsageAdmitResult::Revoked;
  }

  if (auto it = admitted_.find(key); it != admitted_.end()) {
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
      admitted_.erase(it);
      insertRevokedLocked(key);
      return UsageAdmitResult::Revoked;
    }
    return UsageAdmitResult::Replay;
  }

  // Fresh cti. Enforce the total-store cap BEFORE inserting so an
  // exhausted store cannot be tricked into overshooting `max_entries_`
  // by a single slot on the mutating path. Cap covers both admitted +
  // revoked entries: a revocation-heavy workload must not silently
  // starve admissions or vice-versa.
  auto total = [&]() { return admitted_.size() + revoked_.size(); };
  if (total() >= max_entries_) {
    purgeExpiredLocked(now);
    if (total() >= max_entries_) {
      return UsageAdmitResult::StoreExhausted;
    }
  }

  admitted_.emplace(key, Entry{expiry});
  ++admits_since_cleanup_;
  if (admits_since_cleanup_ >= cleanup_interval_) {
    admits_since_cleanup_ = 0;
    purgeExpiredLocked(now);
  }
  return UsageAdmitResult::Admitted;
}

void InMemoryUsageState::revoke(std::string_view cti) {
  std::lock_guard<std::mutex> lock(mu_);
  const std::string key(cti);
  admitted_.erase(key);
  insertRevokedLocked(key);
}

void InMemoryUsageState::purgeExpired(
    std::chrono::system_clock::time_point now) {
  std::lock_guard<std::mutex> lock(mu_);
  purgeExpiredLocked(now);
}

std::size_t InMemoryUsageState::size() const {
  std::lock_guard<std::mutex> lock(mu_);
  return admitted_.size() + revoked_.size();
}

void InMemoryUsageState::purgeExpiredLocked(
    std::chrono::system_clock::time_point now) {
  for (auto it = admitted_.begin(); it != admitted_.end();) {
    if (it->second.expiry.has_value() && now >= *it->second.expiry) {
      it = admitted_.erase(it);
    } else {
      ++it;
    }
  }
}

void InMemoryUsageState::insertRevokedLocked(const std::string& key) {
  // Idempotent: re-revoking an already-revoked cti is a no-op. We do NOT
  // touch the FIFO position — a repeat revoke() call is a duplicate, not
  // a refresh of intent.
  if (revoked_.find(key) != revoked_.end()) {
    return;
  }

  // Enforce the combined cap. revoke() has no failure channel and the
  // caller has already decided the cti MUST be blocked, so if we are at
  // capacity we evict the oldest revocation to make room. Prefer evicting
  // an expired admitted entry first — that is a cheaper source of a slot
  // and preserves older revocation intent for as long as possible.
  if (admitted_.size() + revoked_.size() >= max_entries_) {
    // Try to reclaim a slot from an expired admitted entry. We do not have
    // `now` here (revoke has no time input), so we cannot purge by expiry;
    // fall back directly to FIFO revocation eviction.
    if (!revoked_order_.empty()) {
      const std::string& oldest = revoked_order_.front();
      revoked_.erase(oldest);
      revoked_order_.pop_front();
    } else if (!admitted_.empty()) {
      // No revocations to evict but admitted is at cap. Drop an admitted
      // entry to make room; revocation MUST succeed. The evicted cti loses
      // its replay-tracking sighting, which is strictly safer than leaving
      // the revocation unrecorded.
      admitted_.erase(admitted_.begin());
    }
  }

  revoked_.insert(key);
  revoked_order_.push_back(key);
}

}  // namespace catapult
