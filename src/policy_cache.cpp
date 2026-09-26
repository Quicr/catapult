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

std::optional<AuthorizationDecision> PolicyCache::lookup(
    const PolicyCacheDigest& digest,
    std::chrono::system_clock::time_point now) {
  // Base default: wrap the array bytes as a view and forward. The view
  // stays valid for the duration of the call. Derived classes that own
  // a native hash-table path override this; the wrapping here exists
  // so an out-of-tree adapter that inherits `PolicyCache` without
  // overriding the fixed-digest overload still works.
  return lookup(
      std::string_view(reinterpret_cast<const char*>(digest.data()),
                       digest.size()),
      now);
}

void PolicyCache::store(const PolicyCacheDigest& digest,
                        const AuthorizationDecision& decision,
                        std::chrono::system_clock::time_point now) {
  store(std::string_view(reinterpret_cast<const char*>(digest.data()),
                         digest.size()),
        decision, now);
}

InMemoryPolicyCache::InMemoryPolicyCache(std::size_t max_entries) {
  if (max_entries == 0) {
    throw std::invalid_argument(
        "InMemoryPolicyCache: max_entries must be positive; an unbounded "
        "cache is a memory-exhaustion vector");
  }
  // When `max_entries` is smaller than `kShardCount`, fall back to a
  // single shard. Splitting a tiny cap across many shards means each
  // shard would hold at most one entry, which turns per-shard LRU into
  // near-random eviction and turns the combined admitted+revoked cap
  // into a per-shard cap (which is a strictly weaker invariant). Below
  // the shard count the concurrency win is negligible anyway, so the
  // cleaner semantics dominate.
  active_shards_ = max_entries < kShardCount ? 1 : kShardCount;
  const std::size_t per_shard = max_entries / active_shards_;
  const std::size_t remainder = max_entries % active_shards_;
  for (std::size_t i = 0; i < kShardCount; ++i) {
    if (i < active_shards_) {
      shards_[i].max_entries = per_shard + (i < remainder ? 1 : 0);
    } else {
      shards_[i].max_entries = 0;
    }
  }
}

std::size_t InMemoryPolicyCache::shardIndex(
    std::string_view digest) const noexcept {
  // std::hash<string_view> is fine for shard selection; we do not need
  // cryptographic uniformity here — the digest is already caller-hashed
  // upstream.
  return std::hash<std::string_view>{}(digest) % active_shards_;
}

std::optional<AuthorizationDecision> InMemoryPolicyCache::lookup(
    std::string_view digest, std::chrono::system_clock::time_point now) {
  Shard& shard = shards_[shardIndex(digest)];
  std::lock_guard<std::mutex> lock(shard.mu);
  // Transparent `find`: no `std::string` construction for the lookup
  // key. Under load this is the difference between one heap allocation
  // per lookup and zero.
  auto index_it = shard.index.find(digest);
  if (index_it == shard.index.end()) {
    return std::nullopt;
  }
  auto entry_it = index_it->second;
  if (entry_it->decision.expires_at <= now) {
    // Stale — evict eagerly so it does not linger and inflate the size
    // reported by observability without adding lookup value.
    shard.entries.erase(entry_it);
    shard.index.erase(index_it);
    return std::nullopt;
  }
  shard.touchLocked(entry_it);
  return entry_it->decision;
}

void InMemoryPolicyCache::store(std::string_view digest,
                                const AuthorizationDecision& decision,
                                std::chrono::system_clock::time_point now) {
  Shard& shard = shards_[shardIndex(digest)];
  std::lock_guard<std::mutex> lock(shard.mu);
  // Refuse to record an already-stale entry: nothing downstream would
  // ever hit it, and the write would only crowd out fresh state.
  if (decision.expires_at <= now) {
    return;
  }

  // Fast-path check first, without allocating: if the key exists we
  // update in place and never construct a `std::string`.
  auto index_it = shard.index.find(digest);
  if (index_it != shard.index.end()) {
    // Overwrite in place; move to MRU. `expires_at` is authoritative from
    // the caller — no cache-side TTL substitution.
    index_it->second->decision = decision;
    shard.touchLocked(index_it->second);
    return;
  }

  shard.evictExpiredLocked(now);

  if (shard.entries.size() >= shard.max_entries) {
    // Drop LRU within this shard. LRU is per-shard by design: a global
    // LRU with sharding requires cross-shard bookkeeping under a shared
    // mutex, which reintroduces the contention we are eliminating.
    if (!shard.entries.empty()) {
      shard.index.erase(shard.entries.back().digest);
      shard.entries.pop_back();
    }
  }

  // Insertion path must materialize the key — the map node owns it.
  shard.entries.push_front(Entry{std::string(digest), decision});
  shard.index[shard.entries.front().digest] = shard.entries.begin();
}

std::optional<AuthorizationDecision> InMemoryPolicyCache::lookup(
    const PolicyCacheDigest& digest,
    std::chrono::system_clock::time_point now) {
  // Bytes reinterpreted as a `string_view`; the view lives only for
  // this call so aliasing is safe. Delegating to the `string_view`
  // overload keeps the digest-driven and view-driven APIs pointed at
  // the same shard/entry — a `store(digest)` followed by
  // `lookup(string_view over the same bytes)` still hits.
  return lookup(
      std::string_view(reinterpret_cast<const char*>(digest.data()),
                       digest.size()),
      now);
}

void InMemoryPolicyCache::store(const PolicyCacheDigest& digest,
                                const AuthorizationDecision& decision,
                                std::chrono::system_clock::time_point now) {
  store(std::string_view(reinterpret_cast<const char*>(digest.data()),
                         digest.size()),
        decision, now);
}

std::size_t InMemoryPolicyCache::size() const {
  std::size_t total = 0;
  for (const auto& shard : shards_) {
    std::lock_guard<std::mutex> lock(shard.mu);
    total += shard.entries.size();
  }
  return total;
}

void InMemoryPolicyCache::Shard::touchLocked(EntryList::iterator it) {
  if (it == entries.begin()) {
    return;
  }
  entries.splice(entries.begin(), entries, it);
}

void InMemoryPolicyCache::Shard::evictExpiredLocked(
    std::chrono::system_clock::time_point now) {
  // Sweep in one pass within the shard. Because each shard holds only
  // ~1/16 of the entries, this is bounded to O(N / kShardCount).
  for (auto it = entries.begin(); it != entries.end();) {
    if (it->decision.expires_at <= now) {
      index.erase(it->digest);
      it = entries.erase(it);
    } else {
      ++it;
    }
  }
}

}  // namespace catapult
