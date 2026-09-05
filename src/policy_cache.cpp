#include "catapult/policy_cache.hpp"

#include <stdexcept>

namespace catapult {

InMemoryPolicyCache::InMemoryPolicyCache(std::size_t max_entries)
    : max_entries_(max_entries) {
  if (max_entries_ == 0) {
    throw std::invalid_argument(
        "InMemoryPolicyCache: max_entries must be positive; an unbounded "
        "cache is a memory-exhaustion vector");
  }
}

std::optional<AuthorizationDecision> InMemoryPolicyCache::lookup(
    std::string_view digest, std::chrono::system_clock::time_point now) {
  std::lock_guard<std::mutex> lock(mu_);
  auto index_it = index_.find(std::string(digest));
  if (index_it == index_.end()) {
    return std::nullopt;
  }
  auto entry_it = index_it->second;
  if (entry_it->decision.expires_at <= now) {
    // Stale — evict eagerly so it does not linger and inflate the size
    // reported by observability without adding lookup value.
    entries_.erase(entry_it);
    index_.erase(index_it);
    return std::nullopt;
  }
  touchLocked(entry_it);
  return entry_it->decision;
}

void InMemoryPolicyCache::store(std::string_view digest,
                                const AuthorizationDecision& decision,
                                std::chrono::system_clock::time_point now) {
  std::lock_guard<std::mutex> lock(mu_);
  // Refuse to record an already-stale entry: nothing downstream would
  // ever hit it, and the write would only crowd out fresh state.
  if (decision.expires_at <= now) {
    return;
  }

  std::string key(digest);
  auto index_it = index_.find(key);
  if (index_it != index_.end()) {
    // Overwrite in place; move to MRU. `expires_at` is authoritative from
    // the caller — no cache-side TTL substitution.
    index_it->second->decision = decision;
    touchLocked(index_it->second);
    return;
  }

  evictExpiredLocked(now);

  if (entries_.size() >= max_entries_) {
    // Drop LRU. `back()` is the least recently touched entry per the
    // invariant maintained by `touchLocked()`.
    if (!entries_.empty()) {
      index_.erase(entries_.back().digest);
      entries_.pop_back();
    }
  }

  entries_.push_front(Entry{std::move(key), decision});
  index_[entries_.front().digest] = entries_.begin();
}

std::size_t InMemoryPolicyCache::size() const {
  std::lock_guard<std::mutex> lock(mu_);
  return entries_.size();
}

void InMemoryPolicyCache::touchLocked(EntryList::iterator it) {
  if (it == entries_.begin()) {
    return;
  }
  entries_.splice(entries_.begin(), entries_, it);
}

void InMemoryPolicyCache::evictExpiredLocked(
    std::chrono::system_clock::time_point now) {
  // Sweep in one pass. We do not do this on every lookup because the
  // typical hot set is small and reads dominate; run on write when we
  // have to touch the LRU list anyway.
  for (auto it = entries_.begin(); it != entries_.end();) {
    if (it->decision.expires_at <= now) {
      index_.erase(it->digest);
      it = entries_.erase(it);
    } else {
      ++it;
    }
  }
}

}  // namespace catapult
