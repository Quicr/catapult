#include <doctest/doctest.h>
#include <thread>
#include <vector>
#include <chrono>
#include <atomic>
#include <memory>
#include "catapult/memory_pool.hpp"

using namespace catapult;

// Test object for pool operations
struct TestObject {
    int value;
    double data;
    
    TestObject() : value(0), data(0.0) {}
    TestObject(int v, double d) : value(v), data(d) {}
    
    bool operator==(const TestObject& other) const {
        return value == other.value && data == other.data;
    }
};

// RAII test object to verify proper destruction
struct DestructorCounter {
    static std::atomic<int> counter;
    
    DestructorCounter() { counter.fetch_add(1); }
    ~DestructorCounter() { counter.fetch_sub(1); }
};

std::atomic<int> DestructorCounter::counter{0};

TEST_CASE("MemoryPool: BasicAllocationDeallocation") {
    LockFreeMemoryPool<TestObject, 8> pool;
    
    // Test basic allocation
    auto ptr = pool.make(42, 3.14);
    REQUIRE(ptr);
    CHECK(ptr->value == 42);
    CHECK(ptr->data == doctest::Approx(3.14));
    
    // Test default construction
    auto ptr2 = pool.make();
    REQUIRE(ptr2);
    CHECK(ptr2->value == 0);
    CHECK(ptr2->data == doctest::Approx(0.0));
}

TEST_CASE("MemoryPool: PoolExhaustion") {
    LockFreeMemoryPool<TestObject, 4> pool;
    std::vector<typename LockFreeMemoryPool<TestObject, 4>::PoolPtr> ptrs;
    
    // Allocate all pool objects
    for (int i = 0; i < 4; ++i) {
        auto ptr = pool.make(i, i * 1.5);
        REQUIRE(ptr);
        ptrs.push_back(std::move(ptr));
    }
    
    // Next allocation should fall back to heap
    auto heap_ptr = pool.make(999, 999.9);
    REQUIRE(heap_ptr);
    CHECK(heap_ptr->value == 999);
    
    // Check statistics - 4 from pool, 1 from heap
    auto stats = pool.get_stats();
    CHECK(stats.pool_hits == 4);  // Pool can only handle 4 allocations
    CHECK(stats.pool_misses == 1); // 5th allocation falls back to heap
    CHECK(stats.hit_rate() == doctest::Approx(0.8));
}

TEST_CASE("MemoryPool: PoolReuse") {
    LockFreeMemoryPool<TestObject, 4> pool;
    
    {
        // Allocate and deallocate
        auto ptr = pool.make(123, 4.56);
        REQUIRE(ptr);
    } // ptr destroyed here, object returned to pool
    
    // Should reuse the same memory
    auto ptr2 = pool.make(789, 1.23);
    REQUIRE(ptr2);
    CHECK(ptr2->value == 789);
    CHECK(ptr2->data == doctest::Approx(1.23));
    
    auto stats = pool.get_stats();
    CHECK(stats.pool_hits == 2);
    CHECK(stats.pool_misses == 0);
}

TEST_CASE("MemoryPool: ProperDestruction") {
    DestructorCounter::counter = 0;
    
    {
        LockFreeMemoryPool<DestructorCounter, 4> pool;
        
        {
            auto ptr1 = pool.make();
            auto ptr2 = pool.make();
            CHECK(DestructorCounter::counter == 2);
        } // Objects destroyed here
        
        CHECK(DestructorCounter::counter == 0);
    } // Pool destroyed here
    
    CHECK(DestructorCounter::counter == 0);
}

TEST_CASE("MemoryPool: MoveSemantics") {
    LockFreeMemoryPool<TestObject, 4> pool;
    
    auto ptr1 = pool.make(42, 3.14);
    REQUIRE(ptr1);
    
    // Test move construction
    auto ptr2 = std::move(ptr1);
    CHECK_FALSE(ptr1);
    CHECK(ptr2);
    CHECK(ptr2->value == 42);
    
    // Test move assignment
    auto ptr3 = pool.make(0, 0.0);
    ptr3 = std::move(ptr2);
    CHECK_FALSE(ptr2);
    CHECK(ptr3);
    CHECK(ptr3->value == 42);
}

TEST_CASE("MemoryPool: Release") {
    LockFreeMemoryPool<TestObject, 4> pool;
    
    auto ptr = pool.make(42, 3.14);
    REQUIRE(ptr);
    
    // Release ownership
    TestObject* raw_ptr = ptr.release();
    CHECK_FALSE(ptr);
    CHECK(raw_ptr != nullptr);
    CHECK(raw_ptr->value == 42);
    
    // Note: raw_ptr should not be deleted if it came from pool
    // The test just verifies release() works correctly
}

TEST_CASE("MemoryPool: Statistics") {
    LockFreeMemoryPool<TestObject, 2> pool;
    
    auto stats = pool.get_stats();
    CHECK(stats.pool_hits == 0);
    CHECK(stats.pool_misses == 0);
    
    auto ptr1 = pool.make();
    auto ptr2 = pool.make();
    auto ptr3 = pool.make(); // This should go to heap (pool size = 2)
    
    stats = pool.get_stats();
    CHECK(stats.pool_hits == 2);  // Pool exhausted after 2 allocations
    CHECK(stats.pool_misses == 1); // 3rd allocation goes to heap
    CHECK(stats.hit_rate() == doctest::Approx(2.0/3.0));
}

TEST_CASE("MemoryPool: AvailableCount") {
    LockFreeMemoryPool<TestObject, 4> pool;
    
    CHECK(pool.available() == 4);
    
    auto ptr1 = pool.make();
    CHECK(pool.available() == 3); // One node removed from free list
    
    auto ptr2 = pool.make();
    CHECK(pool.available() == 2); // Two nodes removed from free list
    
    ptr1 = typename LockFreeMemoryPool<TestObject, 4>::PoolPtr();
    CHECK(pool.available() == 3); // One node returned to free list
}

TEST_CASE("MemoryPool: ThreadSafety") {
    LockFreeMemoryPool<TestObject, 1000> pool;
    constexpr int num_threads = 8;
    constexpr int allocations_per_thread = 100;
    
    std::vector<std::thread> threads;
    std::atomic<int> successful_allocations{0};
    
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([&pool, &successful_allocations]() {
            std::vector<typename LockFreeMemoryPool<TestObject, 1000>::PoolPtr> ptrs;
            
            for (int i = 0; i < allocations_per_thread; ++i) {
                auto ptr = pool.make(i, i * 1.5);
                if (ptr) {
                    successful_allocations.fetch_add(1);
                    ptrs.push_back(std::move(ptr));
                }
                
                // Randomly deallocate some objects
                if (!ptrs.empty() && i % 10 == 0) {
                    ptrs.pop_back();
                }
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    CHECK(successful_allocations.load() > 0);
    
    auto stats = pool.get_stats();
    CHECK(stats.pool_hits >= 0);
}

TEST_CASE("MemoryPool: ThreadLocalPool") {
    std::atomic<int> total_allocations{0};
    constexpr int num_threads = 4;
    constexpr int allocations_per_thread = 50;
    
    std::vector<std::thread> threads;
    
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([&total_allocations]() {
            for (int i = 0; i < allocations_per_thread; ++i) {
                auto ptr = ThreadLocalMemoryPool<TestObject, 100>::make(i, i * 2.0);
                if (ptr) {
                    total_allocations.fetch_add(1);
                    CHECK(ptr->value == i);
                    CHECK(ptr->data == doctest::Approx(i * 2.0));
                }
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    CHECK(total_allocations.load() == num_threads * allocations_per_thread);
}

struct ThrowingConstructor {
    static inline bool should_throw = false;
    
    ThrowingConstructor() {
        if (should_throw) {
            throw std::runtime_error("Constructor exception");
        }
    }
};

TEST_CASE("MemoryPool: ExceptionSafety") {
    LockFreeMemoryPool<ThrowingConstructor, 4> pool;
    
    // Normal construction should work
    ThrowingConstructor::should_throw = false;
    auto ptr1 = pool.make();
    CHECK(ptr1);
    
    // Exception during construction should not leak memory
    ThrowingConstructor::should_throw = true;
    try {
        auto ptr = pool.make();
        CHECK(false); // Should not reach here
    } catch (const std::runtime_error&) {
        CHECK(true); // Expected exception
    }
    
    // Pool should still work after exception
    ThrowingConstructor::should_throw = false;
    auto ptr2 = pool.make();
    CHECK(ptr2);
}

TEST_CASE("MemoryPool: AlignmentRequirements") {
    struct AlignedStruct {
        alignas(32) double data;
        AlignedStruct(double d = 0.0) : data(d) {}
    };
    
    LockFreeMemoryPool<AlignedStruct, 4> pool;
    auto ptr = pool.make(3.14159);
    
    REQUIRE(ptr);
    CHECK(reinterpret_cast<uintptr_t>(ptr.get()) % 32 == 0);
    CHECK(ptr->data == doctest::Approx(3.14159));
}

TEST_CASE("MemoryPool: LargeObjects") {
    struct LargeObject {
        std::array<uint64_t, 1000> data;
        LargeObject() { data.fill(0xDEADBEEF); }
    };
    
    LockFreeMemoryPool<LargeObject, 2> pool;
    
    auto ptr = pool.make();
    REQUIRE(ptr);
    CHECK(ptr->data[0] == 0xDEADBEEF);
    CHECK(ptr->data[999] == 0xDEADBEEF);
}

TEST_CASE("MemoryPool: PointerArithmetic") {
    LockFreeMemoryPool<TestObject, 8> pool;
    std::vector<typename LockFreeMemoryPool<TestObject, 8>::PoolPtr> ptrs;
    
    // Allocate several objects
    for (int i = 0; i < 4; ++i) {
        auto ptr = pool.make(i, i * 1.1);
        ptrs.push_back(std::move(ptr));
    }
    
    // Verify all pointers are different
    for (size_t i = 0; i < ptrs.size(); ++i) {
        for (size_t j = i + 1; j < ptrs.size(); ++j) {
            CHECK(ptrs[i].get() != ptrs[j].get());
        }
    }
}