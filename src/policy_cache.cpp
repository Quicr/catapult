#include "catapult/policy_cache.hpp"

#include <cstdint>
#include <cstring>
#include <stdexcept>

namespace catapult {

namespace policy_cache_detail {

namespace {

void appendLengthPrefixed(std::string& out, std::string_view bytes) {
  const std::uint32_t len = static_cast<std::uint32_t>(bytes.size());
  // 4-byte big-endian length prefix so component boundaries are
  // unambiguous and two distinct (a, b) splits can never produce the
  // same encoded byte string.
  const unsigned char len_be[4] = {
      static_cast<unsigned char>((len >> 24) & 0xFF),
      static_cast<unsigned char>((len >> 16) & 0xFF),
      static_cast<unsigned char>((len >> 8) & 0xFF),
      static_cast<unsigned char>(len & 0xFF),
  };
  out.append(reinterpret_cast<const char*>(len_be), sizeof(len_be));
  out.append(bytes.data(), bytes.size());
}

}  // namespace

std::string encodeKey(const PolicyCacheKey& key) {
  std::string out;
  out.reserve(4 + key.token_resource_digest.size() + 4 +
              key.decision_inputs_digest.size() + 8);
  appendLengthPrefixed(out, key.token_resource_digest);
  appendLengthPrefixed(out, key.decision_inputs_digest);
  const std::uint64_t gen = key.policy_generation;
  const unsigned char gen_be[8] = {
      static_cast<unsigned char>((gen >> 56) & 0xFF),
      static_cast<unsigned char>((gen >> 48) & 0xFF),
      static_cast<unsigned char>((gen >> 40) & 0xFF),
      static_cast<unsigned char>((gen >> 32) & 0xFF),
      static_cast<unsigned char>((gen >> 24) & 0xFF),
      static_cast<unsigned char>((gen >> 16) & 0xFF),
      static_cast<unsigned char>((gen >> 8) & 0xFF),
      static_cast<unsigned char>(gen & 0xFF),
  };
  out.append(reinterpret_cast<const char*>(gen_be), sizeof(gen_be));
  return out;
}

}  // namespace policy_cache_detail

std::optional<AuthorizationDecision> PolicyCache::lookup(
    const PolicyCacheKey& key, std::chrono::system_clock::time_point now) {
  const std::string composed = policy_cache_detail::encodeKey(key);
  return lookup(std::string_view(composed), now);
}

void PolicyCache::store(const PolicyCacheKey& key,
                        const AuthorizationDecision& decision,
                        std::chrono::system_clock::time_point now) {
  const std::string composed = policy_cache_detail::encodeKey(key);
  store(std::string_view(composed), decision, now);
}

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
