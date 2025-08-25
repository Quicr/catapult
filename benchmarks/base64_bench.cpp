#include <benchmark/benchmark.h>
#include "catapult/cat_base64.hpp"
#include <vector>
#include <string>
#include <random>

using namespace catapult;

// Test data of different sizes
static const std::vector<uint8_t> SMALL_DATA = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21}; // "Hello, World!"

static std::vector<uint8_t> CreateMediumData() {
    std::string data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris.";
    return std::vector<uint8_t>(data.begin(), data.end());
}

static std::vector<uint8_t> CreateLargeData() {
    std::vector<uint8_t> data(10240); // 10KB
    std::mt19937 gen(42); // Fixed seed for reproducible benchmarks
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    for (auto& byte : data) {
        byte = dis(gen);
    }
    return data;
}

static std::vector<uint8_t> CreateExtraLargeData() {
    std::vector<uint8_t> data(102400); // 100KB
    std::mt19937 gen(42);
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    for (auto& byte : data) {
        byte = dis(gen);
    }
    return data;
}

// Base64 URL Encoding Benchmarks
static void BM_Base64_Encode_Small(benchmark::State& state) {
    for (auto _ : state) {
        std::string encoded = base64UrlEncode(SMALL_DATA);
        benchmark::DoNotOptimize(encoded);
    }
}
BENCHMARK(BM_Base64_Encode_Small);

static void BM_Base64_Encode_Medium(benchmark::State& state) {
    auto medium_data = CreateMediumData();
    for (auto _ : state) {
        std::string encoded = base64UrlEncode(medium_data);
        benchmark::DoNotOptimize(encoded);
    }
}
BENCHMARK(BM_Base64_Encode_Medium);

static void BM_Base64_Encode_Large(benchmark::State& state) {
    auto large_data = CreateLargeData();
    for (auto _ : state) {
        std::string encoded = base64UrlEncode(large_data);
        benchmark::DoNotOptimize(encoded);
    }
}
BENCHMARK(BM_Base64_Encode_Large);

static void BM_Base64_Encode_ExtraLarge(benchmark::State& state) {
    auto extra_large_data = CreateExtraLargeData();
    for (auto _ : state) {
        std::string encoded = base64UrlEncode(extra_large_data);
        benchmark::DoNotOptimize(encoded);
    }
}
BENCHMARK(BM_Base64_Encode_ExtraLarge);

// Base64 URL Decoding Benchmarks
static void BM_Base64_Decode_Small(benchmark::State& state) {
    std::string encoded = base64UrlEncode(SMALL_DATA);
    for (auto _ : state) {
        std::vector<uint8_t> decoded = base64UrlDecode(encoded);
        benchmark::DoNotOptimize(decoded);
    }
}
BENCHMARK(BM_Base64_Decode_Small);

static void BM_Base64_Decode_Medium(benchmark::State& state) {
    auto medium_data = CreateMediumData();
    std::string encoded = base64UrlEncode(medium_data);
    for (auto _ : state) {
        std::vector<uint8_t> decoded = base64UrlDecode(encoded);
        benchmark::DoNotOptimize(decoded);
    }
}
BENCHMARK(BM_Base64_Decode_Medium);

static void BM_Base64_Decode_Large(benchmark::State& state) {
    auto large_data = CreateLargeData();
    std::string encoded = base64UrlEncode(large_data);
    for (auto _ : state) {
        std::vector<uint8_t> decoded = base64UrlDecode(encoded);
        benchmark::DoNotOptimize(decoded);
    }
}
BENCHMARK(BM_Base64_Decode_Large);

static void BM_Base64_Decode_ExtraLarge(benchmark::State& state) {
    auto extra_large_data = CreateExtraLargeData();
    std::string encoded = base64UrlEncode(extra_large_data);
    for (auto _ : state) {
        std::vector<uint8_t> decoded = base64UrlDecode(encoded);
        benchmark::DoNotOptimize(decoded);
    }
}
BENCHMARK(BM_Base64_Decode_ExtraLarge);

// Round-trip Benchmarks (encode then decode)
static void BM_Base64_RoundTrip_Small(benchmark::State& state) {
    for (auto _ : state) {
        std::string encoded = base64UrlEncode(SMALL_DATA);
        std::vector<uint8_t> decoded = base64UrlDecode(encoded);
        benchmark::DoNotOptimize(decoded);
    }
}
BENCHMARK(BM_Base64_RoundTrip_Small);

static void BM_Base64_RoundTrip_Medium(benchmark::State& state) {
    auto medium_data = CreateMediumData();
    for (auto _ : state) {
        std::string encoded = base64UrlEncode(medium_data);
        std::vector<uint8_t> decoded = base64UrlDecode(encoded);
        benchmark::DoNotOptimize(decoded);
    }
}
BENCHMARK(BM_Base64_RoundTrip_Medium);

static void BM_Base64_RoundTrip_Large(benchmark::State& state) {
    auto large_data = CreateLargeData();
    for (auto _ : state) {
        std::string encoded = base64UrlEncode(large_data);
        std::vector<uint8_t> decoded = base64UrlDecode(encoded);
        benchmark::DoNotOptimize(decoded);
    }
}
BENCHMARK(BM_Base64_RoundTrip_Large);

// Parameterized benchmark for different data sizes
static void BM_Base64_Encode_ParameterizedSize(benchmark::State& state) {
    const size_t size = static_cast<size_t>(state.range(0));
    std::vector<uint8_t> data(size, 0x42);
    
    for (auto _ : state) {
        std::string encoded = base64UrlEncode(data);
        benchmark::DoNotOptimize(encoded);
    }
    
    state.SetBytesProcessed(static_cast<int64_t>(state.iterations() * size));
}
BENCHMARK(BM_Base64_Encode_ParameterizedSize)->Range(8, 8<<10)->Complexity(benchmark::oN);

static void BM_Base64_Decode_ParameterizedSize(benchmark::State& state) {
    const size_t size = static_cast<size_t>(state.range(0));
    std::vector<uint8_t> data(size, 0x42);
    std::string encoded = base64UrlEncode(data);
    
    for (auto _ : state) {
        std::vector<uint8_t> decoded = base64UrlDecode(encoded);
        benchmark::DoNotOptimize(decoded);
    }
    
    state.SetBytesProcessed(static_cast<int64_t>(state.iterations() * size));
}
BENCHMARK(BM_Base64_Decode_ParameterizedSize)->Range(8, 8<<10)->Complexity(benchmark::oN);