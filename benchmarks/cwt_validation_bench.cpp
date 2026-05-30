#include <benchmark/benchmark.h>

#include <algorithm>
#include <chrono>
#include <random>
#include <string>
#include <vector>

#include "catapult/crypto.hpp"
#include "catapult/cwt.hpp"

using namespace catapult;

struct HmacKeyEntry {
  std::string id;
  std::vector<uint8_t> secret;
};

static std::vector<HmacKeyEntry> generateKeySet(size_t count) {
  std::vector<HmacKeyEntry> keys;
  keys.reserve(count);
  for (size_t i = 0; i < count; i++) {
    auto secret = secure_utils::to_regular_vector(
        HmacSha256Algorithm::generateSecureKey());
    keys.push_back({"key-" + std::to_string(i), std::move(secret)});
  }
  return keys;
}

static std::vector<uint8_t> createTestCwt(const HmacKeyEntry& key) {
  CatToken token;
  token.core.iss = "bench-issuer";
  token.core.aud = std::vector<std::string>{"bench-audience"};
  auto now = std::chrono::system_clock::now();
  token.core.exp = std::chrono::system_clock::to_time_t(
      now + std::chrono::hours(1));

  Cwt cwt(ALG_HMAC256_256, token);
  cwt.withKeyId(key.id);

  HmacSha256Algorithm hmac(key.secret);
  return cwt.createCwt(CwtMode::MACed, hmac);
}

// Simulates the trial-loop approach: try each key until MAC succeeds
static void BM_ValidateCwt_TrialLoop(benchmark::State& state) {
  const int numKeys = state.range(0);
  const int signingKeyIndex = state.range(1);

  auto keys = generateKeySet(numKeys);
  auto cwtBytes = createTestCwt(keys[signingKeyIndex]);
  auto span = std::span<const uint8_t>(cwtBytes.data(), cwtBytes.size());

  for (auto _ : state) {
    for (int i = 0; i < numKeys; i++) {
      try {
        HmacSha256Algorithm hmac(keys[i].secret);
        auto cwt = Cwt::validateCwt(span, hmac);
        if (cwt.header.kid.has_value() && *cwt.header.kid != keys[i].id) {
          continue;
        }
        benchmark::DoNotOptimize(cwt);
        break;
      } catch (const CryptoError&) {
        continue;
      }
    }
  }
}

// Simulates the decodeHeader-first approach: extract kid, then validate once
static void BM_ValidateCwt_DecodeHeaderFirst(benchmark::State& state) {
  const int numKeys = state.range(0);
  const int signingKeyIndex = state.range(1);

  auto keys = generateKeySet(numKeys);
  auto cwtBytes = createTestCwt(keys[signingKeyIndex]);
  auto span = std::span<const uint8_t>(cwtBytes.data(), cwtBytes.size());

  for (auto _ : state) {
    auto header = Cwt::decodeHeader(span);
    if (header.kid.has_value()) {
      auto it = std::find_if(keys.begin(), keys.end(),
          [&](const auto& k) { return k.id == *header.kid; });
      if (it != keys.end()) {
        HmacSha256Algorithm hmac(it->secret);
        auto cwt = Cwt::validateCwt(span, hmac);
        benchmark::DoNotOptimize(cwt);
      }
    }
  }
}

// Args: {numKeys, signingKeyIndex}
// Best case for trial loop: signing key is first
BENCHMARK(BM_ValidateCwt_TrialLoop)
    ->Args({2, 0})
    ->Args({5, 0})
    ->Args({10, 0})
    ->Args({50, 0})
    ->Args({100, 0});

// Worst case for trial loop: signing key is last
BENCHMARK(BM_ValidateCwt_TrialLoop)
    ->Args({2, 1})
    ->Args({5, 4})
    ->Args({10, 9})
    ->Args({50, 49})
    ->Args({100, 99});

// decodeHeader-first: constant time regardless of key position
BENCHMARK(BM_ValidateCwt_DecodeHeaderFirst)
    ->Args({2, 0})
    ->Args({5, 0})
    ->Args({10, 0})
    ->Args({50, 0})
    ->Args({100, 0})
    ->Args({2, 1})
    ->Args({5, 4})
    ->Args({10, 9})
    ->Args({50, 49})
    ->Args({100, 99});

// End-to-end throughput: 1M validations with decodeHeader approach
static void BM_ValidateCwt_Throughput_HMAC(benchmark::State& state) {
  const int numKeys = state.range(0);
  auto keys = generateKeySet(numKeys);

  // Pre-create tokens signed by random keys
  std::mt19937 rng(42);
  std::uniform_int_distribution<int> dist(0, numKeys - 1);

  constexpr int kBatchSize = 1000;
  std::vector<std::vector<uint8_t>> tokens;
  tokens.reserve(kBatchSize);
  for (int i = 0; i < kBatchSize; i++) {
    tokens.push_back(createTestCwt(keys[dist(rng)]));
  }

  int idx = 0;
  for (auto _ : state) {
    auto& cwtBytes = tokens[idx % kBatchSize];
    auto span = std::span<const uint8_t>(cwtBytes.data(), cwtBytes.size());

    auto header = Cwt::decodeHeader(span);
    if (header.kid.has_value()) {
      auto it = std::find_if(keys.begin(), keys.end(),
          [&](const auto& k) { return k.id == *header.kid; });
      if (it != keys.end()) {
        HmacSha256Algorithm hmac(it->secret);
        auto cwt = Cwt::validateCwt(span, hmac);
        benchmark::DoNotOptimize(cwt);
      }
    }
    idx++;
  }

  state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_ValidateCwt_Throughput_HMAC)
    ->Args({1})
    ->Args({3})
    ->Args({10})
    ->Args({50})
    ->Args({100})
    ->Unit(benchmark::kMicrosecond);

// ES256 CWT validation throughput for comparison
static void BM_ValidateCwt_Throughput_ES256(benchmark::State& state) {
  auto keyPair = Es256Algorithm::generateSecureKeyPair();
  Es256Algorithm signer(keyPair.first, keyPair.second);
  Es256Algorithm verifier(keyPair.second);

  CatToken token;
  token.core.iss = "bench-issuer";
  token.core.aud = std::vector<std::string>{"bench-audience"};
  auto now = std::chrono::system_clock::now();
  token.core.exp = std::chrono::system_clock::to_time_t(
      now + std::chrono::hours(1));

  Cwt cwt(ALG_ES256, token);
  cwt.withKeyId("es256-key");
  auto cwtBytes = cwt.createCwt(CwtMode::Signed, signer);
  auto span = std::span<const uint8_t>(cwtBytes.data(), cwtBytes.size());

  for (auto _ : state) {
    auto validated = Cwt::validateCwt(span, verifier);
    benchmark::DoNotOptimize(validated);
  }

  state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_ValidateCwt_Throughput_ES256)
    ->Unit(benchmark::kMicrosecond);

// Benchmark decodeHeader alone (the overhead of the optimization)
static void BM_DecodeHeader_Only(benchmark::State& state) {
  auto keys = generateKeySet(10);
  auto cwtBytes = createTestCwt(keys[5]);
  auto span = std::span<const uint8_t>(cwtBytes.data(), cwtBytes.size());

  for (auto _ : state) {
    auto header = Cwt::decodeHeader(span);
    benchmark::DoNotOptimize(header);
  }

  state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_DecodeHeader_Only)->Unit(benchmark::kNanosecond);

// Token without kid — measures the trial-loop fallback cost
static void BM_ValidateCwt_NoKid_TrialLoop(benchmark::State& state) {
  const int numKeys = state.range(0);
  const int signingKeyIndex = numKeys / 2;

  auto keys = generateKeySet(numKeys);

  // Create token WITHOUT kid
  CatToken token;
  token.core.iss = "bench-issuer";
  token.core.exp = std::chrono::system_clock::to_time_t(
      std::chrono::system_clock::now() + std::chrono::hours(1));

  Cwt cwt(ALG_HMAC256_256, token);
  // Intentionally no withKeyId()

  HmacSha256Algorithm hmac(keys[signingKeyIndex].secret);
  auto cwtBytes = cwt.createCwt(CwtMode::MACed, hmac);
  auto span = std::span<const uint8_t>(cwtBytes.data(), cwtBytes.size());

  for (auto _ : state) {
    auto header = Cwt::decodeHeader(span);
    if (header.kid.has_value()) {
      // Direct lookup — won't happen here
    } else {
      for (int i = 0; i < numKeys; i++) {
        try {
          HmacSha256Algorithm h(keys[i].secret);
          auto validated = Cwt::validateCwt(span, h);
          benchmark::DoNotOptimize(validated);
          break;
        } catch (const CryptoError&) {
          continue;
        }
      }
    }
  }

  state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_ValidateCwt_NoKid_TrialLoop)
    ->Args({2})
    ->Args({5})
    ->Args({10})
    ->Args({50})
    ->Unit(benchmark::kMicrosecond);
