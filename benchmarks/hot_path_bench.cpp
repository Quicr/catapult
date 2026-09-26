/**
 * Hot-path microbenchmarks for the pluggable stores that gate every
 * authorization decision:
 *
 *   - `InMemoryPolicyCache::{lookup,store}`
 *   - `InMemoryReplayStore::admit`
 *   - `InMemoryUsageState::admit`
 *
 * These are the shared-mutex data structures the audit called out
 * (P2 §Shared in-memory hot paths). Baselines here answer:
 *
 *   1. What is the single-threaded per-op cost today?
 *   2. How much does that cost degrade under N threads competing on
 *      the same global mutex?
 *   3. What is the difference between the hit path (cheap read) and
 *      the miss path (cheap read + write + potential eviction)?
 *
 * Optimizations MUST be measured against these baselines before landing;
 * the audit's guidance is "measure then optimize" (Phase 4).
 */

#include <benchmark/benchmark.h>

#include <chrono>
#include <cstdint>
#include <optional>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "catapult/policy_cache.hpp"
#include "catapult/replay_store.hpp"
#include "catapult/usage_state.hpp"

using namespace catapult;
using namespace std::chrono_literals;

namespace {

std::vector<std::string> makeKeys(std::size_t n, std::uint32_t seed) {
  std::mt19937 gen(seed);
  std::uniform_int_distribution<int> dis('a', 'z');
  std::vector<std::string> out;
  out.reserve(n);
  for (std::size_t i = 0; i < n; ++i) {
    // 32-byte pseudo-random key mimicking a SHA-256 digest.
    std::string key(32, '\0');
    for (char& c : key) c = static_cast<char>(dis(gen));
    out.push_back(std::move(key));
  }
  return out;
}

AuthorizationDecision allowFor(std::chrono::seconds ttl,
                               std::chrono::system_clock::time_point now) {
  return AuthorizationDecision{AuthorizationOutcome::Allow, now + ttl};
}

}  // namespace

// ---------------------------------------------------------------------------
// PolicyCache

static void BM_PolicyCache_Lookup_Hit(benchmark::State& state) {
  const std::size_t working_set = static_cast<std::size_t>(state.range(0));
  InMemoryPolicyCache cache(working_set * 2);
  const auto keys = makeKeys(working_set, 1);
  const auto now = std::chrono::system_clock::now();
  for (const auto& k : keys) {
    cache.store(k, allowFor(3600s, now), now);
  }
  std::size_t idx = 0;
  for (auto _ : state) {
    auto got = cache.lookup(keys[idx], now);
    benchmark::DoNotOptimize(got);
    idx = (idx + 1) % keys.size();
  }
  state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_PolicyCache_Lookup_Hit)->Arg(64)->Arg(1024)->Arg(16'384);

static void BM_PolicyCache_Lookup_Miss(benchmark::State& state) {
  InMemoryPolicyCache cache(1024);
  const auto now = std::chrono::system_clock::now();
  const auto keys = makeKeys(4096, 2);
  std::size_t idx = 0;
  for (auto _ : state) {
    auto got = cache.lookup(keys[idx], now);
    benchmark::DoNotOptimize(got);
    idx = (idx + 1) % keys.size();
  }
  state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_PolicyCache_Lookup_Miss);

static void BM_PolicyCache_Store_Turnover(benchmark::State& state) {
  // Every store call is a new insertion — exercises the LRU-eviction
  // path once the cache is at capacity.
  const std::size_t cap = 1024;
  InMemoryPolicyCache cache(cap);
  const auto now = std::chrono::system_clock::now();
  const auto keys = makeKeys(cap * 4, 3);
  std::size_t idx = 0;
  for (auto _ : state) {
    cache.store(keys[idx], allowFor(3600s, now), now);
    idx = (idx + 1) % keys.size();
  }
  state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_PolicyCache_Store_Turnover);

static void BM_PolicyCache_Lookup_Hit_Concurrent(benchmark::State& state) {
  // Every thread is reading the same shared instance. Under the current
  // single-mutex design this is the workload most likely to expose
  // contention; a future sharded implementation should show measured
  // gains against this baseline.
  static InMemoryPolicyCache* cache = nullptr;
  static std::vector<std::string>* keys = nullptr;
  static std::chrono::system_clock::time_point* now = nullptr;
  if (state.thread_index() == 0) {
    cache = new InMemoryPolicyCache(4096);
    keys = new std::vector<std::string>(makeKeys(2048, 4));
    now = new std::chrono::system_clock::time_point(
        std::chrono::system_clock::now());
    for (const auto& k : *keys) {
      cache->store(k, allowFor(3600s, *now), *now);
    }
  }
  std::size_t idx = state.thread_index();
  for (auto _ : state) {
    auto got = cache->lookup((*keys)[idx % keys->size()], *now);
    benchmark::DoNotOptimize(got);
    idx += state.threads();
  }
  if (state.thread_index() == 0) {
    delete cache;
    delete keys;
    delete now;
    cache = nullptr;
    keys = nullptr;
    now = nullptr;
  }
  state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_PolicyCache_Lookup_Hit_Concurrent)
    ->Threads(1)
    ->Threads(2)
    ->Threads(4)
    ->Threads(8);

// ---------------------------------------------------------------------------
// ReplayStore

static void BM_ReplayStore_Admit_Fresh(benchmark::State& state) {
  InMemoryReplayStore store(state.range(0));
  const auto keys = makeKeys(static_cast<std::size_t>(state.range(0)), 5);
  const auto now = std::chrono::system_clock::now();
  std::size_t idx = 0;
  for (auto _ : state) {
    auto r = store.admit(keys[idx], now, 300s);
    benchmark::DoNotOptimize(r);
    idx = (idx + 1) % keys.size();
    if (idx == 0) {
      state.PauseTiming();
      store.purgeExpired(now + 3600s, 300s);
      state.ResumeTiming();
    }
  }
  state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_ReplayStore_Admit_Fresh)->Arg(1024)->Arg(16'384);

static void BM_ReplayStore_Admit_Replay(benchmark::State& state) {
  // Every admit is a replay hit — the map lookup succeeds and no
  // insertion happens. Cheaper than the fresh path.
  InMemoryReplayStore store;
  const auto keys = makeKeys(1024, 6);
  const auto now = std::chrono::system_clock::now();
  for (const auto& k : keys) {
    store.admit(k, now, 300s);
  }
  std::size_t idx = 0;
  for (auto _ : state) {
    auto r = store.admit(keys[idx], now + 1s, 300s);
    benchmark::DoNotOptimize(r);
    idx = (idx + 1) % keys.size();
  }
  state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_ReplayStore_Admit_Replay);

// ---------------------------------------------------------------------------
// UsageStateHook

static void BM_UsageState_Admit_Fresh(benchmark::State& state) {
  InMemoryUsageState store(state.range(0));
  const auto keys = makeKeys(static_cast<std::size_t>(state.range(0)), 7);
  const auto now = std::chrono::system_clock::now();
  std::size_t idx = 0;
  for (auto _ : state) {
    auto r = store.admit(keys[idx], CatReplayMode::RejectOnReplay, now,
                         now + 1h);
    benchmark::DoNotOptimize(r);
    idx = (idx + 1) % keys.size();
    if (idx == 0) {
      state.PauseTiming();
      store.purgeExpired(now + 2h);
      state.ResumeTiming();
    }
  }
  state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_UsageState_Admit_Fresh)->Arg(1024)->Arg(16'384);

static void BM_UsageState_Admit_Replay(benchmark::State& state) {
  InMemoryUsageState store;
  const auto keys = makeKeys(1024, 8);
  const auto now = std::chrono::system_clock::now();
  for (const auto& k : keys) {
    store.admit(k, CatReplayMode::RejectOnReplay, now, now + 1h);
  }
  std::size_t idx = 0;
  for (auto _ : state) {
    auto r = store.admit(keys[idx], CatReplayMode::RejectOnReplay, now + 1s,
                         now + 1h);
    benchmark::DoNotOptimize(r);
    idx = (idx + 1) % keys.size();
  }
  state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_UsageState_Admit_Replay);
