#include <doctest/doctest.h>
#include <thread>
#include <vector>
#include <chrono>
#include <atomic>
#include <memory>
#include <algorithm>
#include "catapult/secure_vector.hpp"

using namespace catapult;

TEST_CASE("SecureAllocator: BasicAllocation") {
    SecureAllocator<uint8_t> allocator;
    
    // Test allocation
    auto ptr = allocator.allocate(1024);
    REQUIRE(ptr != nullptr);
    
    // Test writing to allocated memory
    std::memset(ptr, 0xAA, 1024);
    CHECK(ptr[0] == 0xAA);
    CHECK(ptr[1023] == 0xAA);
    
    // Test deallocation
    allocator.deallocate(ptr, 1024);
}

TEST_CASE("SecureAllocator: ZeroAllocation") {
    SecureAllocator<uint8_t> allocator;
    
    // Test zero allocation returns nullptr
    auto ptr = allocator.allocate(0);
    CHECK(ptr == nullptr);
    
    // Deallocating nullptr should be safe
    allocator.deallocate(nullptr, 0);
}

TEST_CASE("SecureVector: BasicOperations") {
    SecureVector<uint8_t> vec;
    
    // Test empty vector
    CHECK(vec.empty());
    CHECK(vec.size() == 0);
    
    // Test push_back
    vec.push_back(0x42);
    CHECK(vec.size() == 1);
    CHECK(vec[0] == 0x42);
    
    // Test resize
    vec.resize(10, 0xFF);
    CHECK(vec.size() == 10);
    CHECK(vec[0] == 0x42);
    CHECK(vec[9] == 0xFF);
    
    // Test clear
    vec.clear();
    CHECK(vec.empty());
}

TEST_CASE("SecureVector: ConstructorWithData") {
    std::vector<uint8_t> source = {0x01, 0x02, 0x03, 0x04, 0x05};
    
    // Test construction from regular vector
    SecureVector<uint8_t> secure_vec(source.begin(), source.end());
    REQUIRE(secure_vec.size() == 5);
    CHECK(secure_vec[0] == 0x01);
    CHECK(secure_vec[4] == 0x05);
}

TEST_CASE("SecureVector: LargeAllocation") {
    const size_t large_size = 1024 * 1024; // 1MB
    SecureVector<uint8_t> vec(large_size, 0x55);
    
    REQUIRE(vec.size() == large_size);
    CHECK(vec[0] == 0x55);
    CHECK(vec[large_size - 1] == 0x55);
    
    // Test that memory is properly accessible
    for (size_t i = 0; i < std::min(size_t(100), large_size); ++i) {
        vec[i] = static_cast<uint8_t>(i & 0xFF);
        CHECK(vec[i] == static_cast<uint8_t>(i & 0xFF));
    }
}

TEST_CASE("SecureUtils: ConstantTimeCompare") {
    uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t data2[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t data3[] = {0x01, 0x02, 0x03, 0x05};
    
    // Test equal data
    CHECK(secure_utils::constantTimeCompare(data1, data2, 4) == 0);
    
    // Test different data
    CHECK(secure_utils::constantTimeCompare(data1, data3, 4) != 0);
    
    // Test zero-length comparison
    CHECK(secure_utils::constantTimeCompare(data1, data2, 0) == 0);
}

TEST_CASE("SecureUtils: ConstantTimeEqual") {
    std::vector<uint8_t> vec1 = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> vec2 = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> vec3 = {0x01, 0x02, 0x03, 0x05};
    std::vector<uint8_t> vec4 = {0x01, 0x02, 0x03}; // Different size
    
    // Test equal vectors
    CHECK(secure_utils::constantTimeEqual(vec1, vec2));
    
    // Test different content
    CHECK_FALSE(secure_utils::constantTimeEqual(vec1, vec3));
    
    // Test different sizes
    CHECK_FALSE(secure_utils::constantTimeEqual(vec1, vec4));
    
    // Test empty vectors
    std::vector<uint8_t> empty1, empty2;
    CHECK(secure_utils::constantTimeEqual(empty1, empty2));
}

TEST_CASE("SecureUtils: VectorConversion") {
    std::vector<uint8_t> regular = {0x01, 0x02, 0x03, 0x04, 0x05};
    
    // Convert to secure vector
    auto secure_vec = secure_utils::to_secure_vector(regular);
    REQUIRE(secure_vec.size() == 5);
    CHECK(secure_vec[0] == 0x01);
    CHECK(secure_vec[4] == 0x05);
    
    // Convert back to regular vector
    auto converted_back = secure_utils::to_regular_vector(secure_vec);
    REQUIRE(converted_back.size() == 5);
    CHECK(converted_back == regular);
}


TEST_CASE("SecureVector: MoveSemanticsAndSwap") {
    SecureVector<uint8_t> vec1 = {0x01, 0x02, 0x03};
    SecureVector<uint8_t> vec2 = {0x04, 0x05, 0x06, 0x07};
    
    auto original_size1 = vec1.size();
    auto original_size2 = vec2.size();
    
    // Test move constructor
    SecureVector<uint8_t> vec3 = std::move(vec1);
    CHECK(vec3.size() == original_size1);
    CHECK(vec3[0] == 0x01);
    
    // Test move assignment
    vec3 = std::move(vec2);
    CHECK(vec3.size() == original_size2);
    CHECK(vec3[0] == 0x04);
    
    // Test swap
    SecureVector<uint8_t> vec4 = {0x10, 0x20};
    SecureVector<uint8_t> vec5 = {0x30, 0x40, 0x50};
    
    vec4.swap(vec5);
    CHECK(vec4.size() == 3);
    CHECK(vec4[0] == 0x30);
    CHECK(vec5.size() == 2);
    CHECK(vec5[0] == 0x10);
}

TEST_CASE("SecureVector: IteratorOperations") {
    SecureVector<uint8_t> vec = {0x10, 0x20, 0x30, 0x40, 0x50};
    
    // Test range-based loop
    uint8_t expected = 0x10;
    for (const auto& byte : vec) {
        CHECK(byte == expected);
        expected += 0x10;
    }
    
    // Test STL algorithms
    auto it = std::find(vec.begin(), vec.end(), 0x30);
    CHECK(it != vec.end());
    CHECK(*it == 0x30);
    
    // Test modification through iterators
    for (auto& byte : vec) {
        byte += 1;
    }
    CHECK(vec[0] == 0x11);
    CHECK(vec[4] == 0x51);
}

TEST_CASE("SecureAllocator: AllocatorTraits") {
    using allocator_type = SecureAllocator<int>;
    using traits = std::allocator_traits<allocator_type>;
    
    // Test allocator traits
    CHECK(std::is_same_v<traits::value_type, int>);
    CHECK(std::is_same_v<traits::pointer, int*>);
    CHECK(std::is_same_v<traits::const_pointer, const int*>);
    
    // Test rebind
    using char_allocator = traits::rebind_alloc<char>;
    CHECK(std::is_same_v<char_allocator, SecureAllocator<char>>);
}