#include <benchmark/benchmark.h>
#include <memory>
#include <vector>
#include <thread>
#include <random>
#include "catapult/memory_pool.hpp"

using namespace catapult;

// Test objects for benchmarking
struct SmallObject {
    uint32_t id;
    double value;
    
    SmallObject(uint32_t i = 0, double v = 0.0) : id(i), value(v) {}
};

struct MediumObject {
    std::array<uint64_t, 16> data;
    uint32_t id;
    
    MediumObject(uint32_t i = 0) : id(i) {
        data.fill(i);
    }
};

struct LargeObject {
    std::array<uint64_t, 256> data;
    uint32_t id;
    
    LargeObject(uint32_t i = 0) : id(i) {
        data.fill(i);
    }
};

// Benchmark pool allocation vs standard allocation
static void BM_PoolAllocation_Small(benchmark::State& state) {
    LockFreeMemoryPool<SmallObject, 1024> pool;
    
    for (auto _ : state) {
        auto ptr = pool.make(42, 3.14);
        benchmark::DoNotOptimize(ptr);
    }
    
    auto stats = pool.get_stats();
    state.counters["HitRate"] = stats.hit_rate();
    state.counters["PoolHits"] = stats.pool_hits;
    state.counters["PoolMisses"] = stats.pool_misses;
}
BENCHMARK(BM_PoolAllocation_Small);

static void BM_StandardAllocation_Small(benchmark::State& state) {
    for (auto _ : state) {
        auto ptr = std::make_unique<SmallObject>(42, 3.14);
        benchmark::DoNotOptimize(ptr);
    }
}
BENCHMARK(BM_StandardAllocation_Small);

static void BM_PoolAllocation_Medium(benchmark::State& state) {
    LockFreeMemoryPool<MediumObject, 1024> pool;
    
    for (auto _ : state) {
        auto ptr = pool.make(42);
        benchmark::DoNotOptimize(ptr);
    }
    
    auto stats = pool.get_stats();
    state.counters["HitRate"] = stats.hit_rate();
}
BENCHMARK(BM_PoolAllocation_Medium);

static void BM_StandardAllocation_Medium(benchmark::State& state) {
    for (auto _ : state) {
        auto ptr = std::make_unique<MediumObject>(42);
        benchmark::DoNotOptimize(ptr);
    }
}
BENCHMARK(BM_StandardAllocation_Medium);

static void BM_PoolAllocation_Large(benchmark::State& state) {
    LockFreeMemoryPool<LargeObject, 512> pool;
    
    for (auto _ : state) {
        auto ptr = pool.make(42);
        benchmark::DoNotOptimize(ptr);
    }
    
    auto stats = pool.get_stats();
    state.counters["HitRate"] = stats.hit_rate();
}
BENCHMARK(BM_PoolAllocation_Large);

static void BM_StandardAllocation_Large(benchmark::State& state) {
    for (auto _ : state) {
        auto ptr = std::make_unique<LargeObject>(42);
        benchmark::DoNotOptimize(ptr);
    }
}
BENCHMARK(BM_StandardAllocation_Large);

// Benchmark allocation/deallocation patterns
static void BM_Pool_AllocDealloc_Pattern(benchmark::State& state) {
    LockFreeMemoryPool<SmallObject, 1024> pool;
    std::vector<typename LockFreeMemoryPool<SmallObject, 1024>::PoolPtr> ptrs;
    ptrs.reserve(100);
    
    std::mt19937 rng(42);
    std::uniform_int_distribution<int> dist(0, 99);
    
    for (auto _ : state) {
        // Allocate
        if (ptrs.size() < 100) {
            auto ptr = pool.make(static_cast<uint32_t>(ptrs.size()), 3.14);
            ptrs.push_back(std::move(ptr));
        }
        
        // Randomly deallocate
        if (!ptrs.empty() && dist(rng) < 30) {
            ptrs.erase(ptrs.begin() + (dist(rng) % ptrs.size()));
        }
    }
    
    auto stats = pool.get_stats();
    state.counters["HitRate"] = stats.hit_rate();
}
BENCHMARK(BM_Pool_AllocDealloc_Pattern);

static void BM_Standard_AllocDealloc_Pattern(benchmark::State& state) {
    std::vector<std::unique_ptr<SmallObject>> ptrs;
    ptrs.reserve(100);
    
    std::mt19937 rng(42);
    std::uniform_int_distribution<int> dist(0, 99);
    
    for (auto _ : state) {
        // Allocate
        if (ptrs.size() < 100) {
            ptrs.push_back(std::make_unique<SmallObject>(
                static_cast<uint32_t>(ptrs.size()), 3.14));
        }
        
        // Randomly deallocate
        if (!ptrs.empty() && dist(rng) < 30) {
            ptrs.erase(ptrs.begin() + (dist(rng) % ptrs.size()));
        }
    }
}
BENCHMARK(BM_Standard_AllocDealloc_Pattern);

// Multithreaded benchmarks
static void BM_Pool_Multithreaded(benchmark::State& state) {
    LockFreeMemoryPool<SmallObject, 2048> pool;
    
    if (state.thread_index() == 0) {
        // Setup code here if needed
    }
    
    for (auto _ : state) {
        std::vector<typename LockFreeMemoryPool<SmallObject, 2048>::PoolPtr> ptrs;
        ptrs.reserve(50);
        
        // Allocate batch
        for (int i = 0; i < 50; ++i) {
            auto ptr = pool.make(state.thread_index() * 1000 + i, 3.14);
            if (ptr) {
                ptrs.push_back(std::move(ptr));
            }
        }
        
        // Keep some objects alive longer
        if (!ptrs.empty()) {
            ptrs.resize(ptrs.size() / 2);
        }
    }
    
    if (state.thread_index() == 0) {
        auto stats = pool.get_stats();
        state.counters["HitRate"] = stats.hit_rate();
        state.counters["TotalAllocations"] = stats.pool_hits + stats.pool_misses;
    }
}
BENCHMARK(BM_Pool_Multithreaded)->ThreadRange(1, std::thread::hardware_concurrency());

static void BM_Standard_Multithreaded(benchmark::State& state) {
    for (auto _ : state) {
        std::vector<std::unique_ptr<SmallObject>> ptrs;
        ptrs.reserve(50);
        
        // Allocate batch
        for (int i = 0; i < 50; ++i) {
            ptrs.push_back(std::make_unique<SmallObject>(
                state.thread_index() * 1000 + i, 3.14));
        }
        
        // Keep some objects alive longer
        if (!ptrs.empty()) {
            ptrs.resize(ptrs.size() / 2);
        }
    }
}
BENCHMARK(BM_Standard_Multithreaded)->ThreadRange(1, std::thread::hardware_concurrency());

// Thread-local pool benchmarks
static void BM_ThreadLocal_Pool(benchmark::State& state) {
    for (auto _ : state) {
        auto ptr = ThreadLocalMemoryPool<SmallObject, 1024>::make(42, 3.14);
        benchmark::DoNotOptimize(ptr);
    }
    
    auto stats = ThreadLocalMemoryPool<SmallObject, 1024>::get_stats();
    state.counters["HitRate"] = stats.hit_rate();
}
BENCHMARK(BM_ThreadLocal_Pool)->ThreadRange(1, std::thread::hardware_concurrency());

// Cache behavior benchmarks
static void BM_Pool_Cache_Friendly(benchmark::State& state) {
    LockFreeMemoryPool<SmallObject, 1024> pool;
    std::vector<typename LockFreeMemoryPool<SmallObject, 1024>::PoolPtr> ptrs;
    
    // Pre-allocate and deallocate to warm up pool
    for (int i = 0; i < 100; ++i) {
        ptrs.push_back(pool.make(i, i * 1.1));
    }
    ptrs.clear();
    
    for (auto _ : state) {
        // Allocate objects that will likely reuse recently freed memory
        std::vector<typename LockFreeMemoryPool<SmallObject, 1024>::PoolPtr> batch;
        for (int i = 0; i < 10; ++i) {
            batch.push_back(pool.make(i, i * 2.2));
        }
        
        // Access all objects to measure cache performance
        double sum = 0;
        for (auto& ptr : batch) {
            sum += ptr->value;
        }
        benchmark::DoNotOptimize(sum);
    }
    
    auto stats = pool.get_stats();
    state.counters["HitRate"] = stats.hit_rate();
}
BENCHMARK(BM_Pool_Cache_Friendly);

static void BM_Standard_Cache_Test(benchmark::State& state) {
    for (auto _ : state) {
        // Allocate objects that will be scattered in memory
        std::vector<std::unique_ptr<SmallObject>> batch;
        for (int i = 0; i < 10; ++i) {
            batch.push_back(std::make_unique<SmallObject>(i, i * 2.2));
        }
        
        // Access all objects to measure cache performance
        double sum = 0;
        for (auto& ptr : batch) {
            sum += ptr->value;
        }
        benchmark::DoNotOptimize(sum);
    }
}
BENCHMARK(BM_Standard_Cache_Test);

// Pool exhaustion behavior
static void BM_Pool_Exhaustion(benchmark::State& state) {
    LockFreeMemoryPool<SmallObject, 64> pool;  // Small pool size
    std::vector<typename LockFreeMemoryPool<SmallObject, 64>::PoolPtr> ptrs;
    
    for (auto _ : state) {
        // Fill pool completely
        ptrs.clear();
        for (int i = 0; i < 100; ++i) {  // More than pool size
            auto ptr = pool.make(i, i * 1.5);
            if (ptr) {
                ptrs.push_back(std::move(ptr));
            }
        }
        
        // Release half
        ptrs.resize(ptrs.size() / 2);
    }
    
    auto stats = pool.get_stats();
    state.counters["HitRate"] = stats.hit_rate();
    state.counters["PoolHits"] = stats.pool_hits;
    state.counters["PoolMisses"] = stats.pool_misses;
}
BENCHMARK(BM_Pool_Exhaustion);

// Fragmentation resistance test
static void BM_Pool_Fragmentation_Resistance(benchmark::State& state) {
    LockFreeMemoryPool<SmallObject, 1024> pool;
    std::vector<typename LockFreeMemoryPool<SmallObject, 1024>::PoolPtr> ptrs;
    
    std::mt19937 rng(42);
    std::uniform_int_distribution<int> dist(0, 9);
    
    for (auto _ : state) {
        // Create fragmentation pattern
        for (int i = 0; i < 100; ++i) {
            auto ptr = pool.make(i, i * 1.1);
            if (ptr && dist(rng) < 7) {  // Keep 70% of allocations
                ptrs.push_back(std::move(ptr));
            }
        }
        
        // Allocate new objects (should reuse freed slots)
        for (int i = 0; i < 30; ++i) {
            auto ptr = pool.make(1000 + i, (1000 + i) * 1.1);
            benchmark::DoNotOptimize(ptr);
        }
        
        ptrs.clear();
    }
    
    auto stats = pool.get_stats();
    state.counters["HitRate"] = stats.hit_rate();
}
BENCHMARK(BM_Pool_Fragmentation_Resistance);

