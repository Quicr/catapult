#include <benchmark/benchmark.h>
#include <vector>
#include <random>
#include "catapult/secure_vector.hpp"

using namespace catapult;

// Benchmark allocation performance
static void BM_SecureVector_Allocation(benchmark::State& state) {
    const size_t size = state.range(0);
    
    for (auto _ : state) {
        SecureVector<uint8_t> vec(size);
        benchmark::DoNotOptimize(vec.data());
        benchmark::ClobberMemory();
    }
    
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(size));
}

static void BM_RegularVector_Allocation(benchmark::State& state) {
    const size_t size = state.range(0);
    
    for (auto _ : state) {
        std::vector<uint8_t> vec(size);
        benchmark::DoNotOptimize(vec.data());
        benchmark::ClobberMemory();
    }
    
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(size));
}

// Benchmark data copying performance
static void BM_SecureVector_Copy(benchmark::State& state) {
    const size_t size = state.range(0);
    SecureVector<uint8_t> source(size, 0xAA);
    
    for (auto _ : state) {
        SecureVector<uint8_t> copy = source;
        benchmark::DoNotOptimize(copy.data());
        benchmark::ClobberMemory();
    }
    
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(size));
}

static void BM_RegularVector_Copy(benchmark::State& state) {
    const size_t size = state.range(0);
    std::vector<uint8_t> source(size, 0xAA);
    
    for (auto _ : state) {
        std::vector<uint8_t> copy = source;
        benchmark::DoNotOptimize(copy.data());
        benchmark::ClobberMemory();
    }
    
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(size));
}

// Benchmark secure utils constant-time comparison
static void BM_ConstantTimeCompare(benchmark::State& state) {
    const size_t size = state.range(0);
    std::vector<uint8_t> data1(size, 0xAA);
    std::vector<uint8_t> data2(size, 0xAA);
    
    for (auto _ : state) {
        int result = secure_utils::constantTimeCompare(data1.data(), data2.data(), size);
        benchmark::DoNotOptimize(result);
    }
    
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(size));
}

static void BM_RegularMemcmp(benchmark::State& state) {
    const size_t size = state.range(0);
    std::vector<uint8_t> data1(size, 0xAA);
    std::vector<uint8_t> data2(size, 0xAA);
    
    for (auto _ : state) {
        int result = std::memcmp(data1.data(), data2.data(), size);
        benchmark::DoNotOptimize(result);
    }
    
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(size));
}

// Benchmark vector conversion utilities
static void BM_ToSecureVector(benchmark::State& state) {
    const size_t size = state.range(0);
    std::vector<uint8_t> regular_vec(size, 0xBB);
    
    for (auto _ : state) {
        auto secure_vec = secure_utils::to_secure_vector(regular_vec);
        benchmark::DoNotOptimize(secure_vec.data());
        benchmark::ClobberMemory();
    }
    
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(size));
}

static void BM_ToRegularVector(benchmark::State& state) {
    const size_t size = state.range(0);
    SecureVector<uint8_t> secure_vec(size, 0xCC);
    
    for (auto _ : state) {
        auto regular_vec = secure_utils::to_regular_vector(secure_vec);
        benchmark::DoNotOptimize(regular_vec.data());
        benchmark::ClobberMemory();
    }
    
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(size));
}

// Benchmark push_back operations
static void BM_SecureVector_PushBack(benchmark::State& state) {
    const size_t size = state.range(0);
    
    for (auto _ : state) {
        SecureVector<uint8_t> vec;
        vec.reserve(size);
        
        for (size_t i = 0; i < size; ++i) {
            vec.push_back(static_cast<uint8_t>(i & 0xFF));
        }
        
        benchmark::DoNotOptimize(vec.data());
        benchmark::ClobberMemory();
    }
    
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(size));
}

static void BM_RegularVector_PushBack(benchmark::State& state) {
    const size_t size = state.range(0);
    
    for (auto _ : state) {
        std::vector<uint8_t> vec;
        vec.reserve(size);
        
        for (size_t i = 0; i < size; ++i) {
            vec.push_back(static_cast<uint8_t>(i & 0xFF));
        }
        
        benchmark::DoNotOptimize(vec.data());
        benchmark::ClobberMemory();
    }
    
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(size));
}

// Register benchmarks with different sizes
BENCHMARK(BM_SecureVector_Allocation)->Range(1024, 1024*1024)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_RegularVector_Allocation)->Range(1024, 1024*1024)->Unit(benchmark::kMicrosecond);

BENCHMARK(BM_SecureVector_Copy)->Range(1024, 1024*1024)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_RegularVector_Copy)->Range(1024, 1024*1024)->Unit(benchmark::kMicrosecond);

BENCHMARK(BM_ConstantTimeCompare)->Range(32, 1024*16)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_RegularMemcmp)->Range(32, 1024*16)->Unit(benchmark::kNanosecond);

BENCHMARK(BM_ToSecureVector)->Range(1024, 1024*1024)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_ToRegularVector)->Range(1024, 1024*1024)->Unit(benchmark::kMicrosecond);

BENCHMARK(BM_SecureVector_PushBack)->Range(1024, 1024*64)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_RegularVector_PushBack)->Range(1024, 1024*64)->Unit(benchmark::kMicrosecond);