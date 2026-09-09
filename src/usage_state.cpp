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
      // Slot transfer: we just freed one admitted slot, so insert cannot
      // exhaust unless another thread raced in between — impossible while
      // we hold `mu_`. The return value is therefore always `Accepted`.
      (void)insertRevokedLocked(key);
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
      ++exhaustion_events_;
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

RevokeResult InMemoryUsageState::revoke(std::string_view cti) {
  std::lock_guard<std::mutex> lock(mu_);
  const std::string key(cti);
  // Erase any prior admission first: doing so releases one slot before
  // insertRevokedLocked runs the cap check, which is what allows an
  // already-admitted cti to always be revokable regardless of store fill.
  admitted_.erase(key);
  return insertRevokedLocked(key);
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

std::size_t InMemoryUsageState::exhaustion_events() const {
  std::lock_guard<std::mutex> lock(mu_);
  return exhaustion_events_;
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

RevokeResult InMemoryUsageState::insertRevokedLocked(const std::string& key) {
  // Idempotent: re-revoking an already-revoked cti is a no-op that reports
  // success. The cti is (still) recorded as revoked, which is the outcome
  // the caller asked for.
  if (revoked_.find(key) != revoked_.end()) {
    return RevokeResult::Accepted;
  }

  // Enforce the combined cap. When we cannot fit the new revocation we
  // refuse it and leave the store untouched: silently evicting an older
  // revocation would forget operator intent that was already committed,
  // which is a more dangerous failure than surfacing exhaustion. Callers
  // are documented to treat StoreExhausted as a hard failure.
  if (admitted_.size() + revoked_.size() >= max_entries_) {
    ++exhaustion_events_;
    return RevokeResult::StoreExhausted;
  }

  revoked_.insert(key);
  return RevokeResult::Accepted;
}

}  // namespace catapult
