/**
 * @file secure_vector.hpp
 * @brief Secure memory allocator and vector for sensitive cryptographic data
 */

#pragma once

#include <concepts>
#include <memory>
#include <span>
#include <vector>
#include <cstring>
#include <cstdlib>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace catapult {

/**
 * @brief Secure memory allocator for sensitive cryptographic data
 * 
 * - Memory locking to prevent swapping to disk
 * - Secure zeroing before deallocation
 * - Protection against memory analysis attacks
 */
template<typename T>
class SecureAllocator {
public:
  using value_type = T;
  using size_type = std::size_t;
  using pointer = T*;
  using const_pointer = const T*;
  
  template<typename U>
  struct rebind {
    using other = SecureAllocator<U>;
  };
  
  SecureAllocator() = default;
  
  template<typename U>
  SecureAllocator(const SecureAllocator<U>&) noexcept {}
  
  /**
   * @brief Allocate and lock memory to prevent swapping
   * @param n Number of elements to allocate
   * @return Pointer to locked memory
   * @throws std::bad_alloc if allocation or locking fails
   */
  T* allocate(size_t n) {
    if (n == 0) return nullptr;
    
    // Calculate aligned size for better performance and security
    size_t size = n * sizeof(T);
    size_t page_size = getPageSize();
    size_t aligned_size = ((size + page_size - 1) / page_size) * page_size;
    
    // Allocate memory with proper alignment
    T* ptr = static_cast<T*>(std::aligned_alloc(page_size, aligned_size));
    if (!ptr) throw std::bad_alloc();
    
    // Lock memory to prevent swapping (best effort - failure is not fatal)
    lockMemory(ptr, aligned_size);
    
    return ptr;
  }
  
  /**
   * @brief Securely deallocate memory with zeroing and unlocking
   * @param ptr Pointer to memory to deallocate
   * @param n Number of elements (used for size calculation)
   */
  void deallocate(T* ptr, size_t n) noexcept {
    if (ptr) {
      size_t size = n * sizeof(T);
      
      // Secure zeroing using volatile to prevent compiler optimization
      secureZero(ptr, size);
      
      // Unlock memory before freeing
      unlockMemory(ptr, size);
      
      std::free(ptr);
    }
  }
  
  template<typename U>
  bool operator==(const SecureAllocator<U>&) const noexcept { return true; }
  
  template<typename U>
  bool operator!=(const SecureAllocator<U>&) const noexcept { return false; }

private:
  /**
   * @brief Get system page size for memory alignment
   * @return Page size in bytes
   */
  static size_t getPageSize() noexcept {
#ifdef _WIN32
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwPageSize;
#else
    return static_cast<size_t>(sysconf(_SC_PAGESIZE));
#endif
  }
  
  /**
   * @brief Lock memory to prevent swapping (best effort)
   * @param ptr Pointer to memory to lock
   * @param size Size of memory region
   */
  static void lockMemory(void* ptr, size_t size) noexcept {
#ifdef _WIN32
    VirtualLock(ptr, size);  // Ignore failures - best effort
#else
    mlock(ptr, size);  // Ignore failures - best effort
#endif
  }
  
  /**
   * @brief Unlock previously locked memory
   * @param ptr Pointer to memory to unlock
   * @param size Size of memory region
   */
  static void unlockMemory(void* ptr, size_t size) noexcept {
#ifdef _WIN32
    VirtualUnlock(ptr, size);
#else
    munlock(ptr, size);
#endif
  }
  
  /**
   * @brief Securely zero memory using volatile to prevent optimization
   * @param ptr Pointer to memory to zero
   * @param size Size of memory region
   */
  static void secureZero(void* ptr, size_t size) noexcept {
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    for (size_t i = 0; i < size; ++i) {
      p[i] = 0;
    }
  }
};

/**
 * @brief Secure vector type for sensitive data
 */
template<typename T>
using SecureVector = std::vector<T, SecureAllocator<T>>;

/**
 * @brief Utility functions for secure memory operations and timing-attack resistance
 */
namespace secure_utils {
  /**
   * @brief Constant-time memory comparison to prevent timing attacks
   * @param a First memory region
   * @param b Second memory region  
   * @param size Size of regions to compare
   * @return 0 if equal, non-zero if different (timing independent)
   */
  inline int constantTimeCompare(const void* a, const void* b, size_t size) noexcept {
    const volatile unsigned char* va = static_cast<const volatile unsigned char*>(a);
    const volatile unsigned char* vb = static_cast<const volatile unsigned char*>(b);
    unsigned char result = 0;
    
    // Use volatile to prevent compiler optimization
    for (size_t i = 0; i < size; ++i) {
      result |= va[i] ^ vb[i];
    }
    
    return result;
  }
  
  /**
   * @brief Constant-time comparison for vectors
   * @param a First vector
   * @param b Second vector
   * @return true if equal, false otherwise (timing independent)
   */
  template<typename T>
  inline bool constantTimeEqual(const std::vector<T>& a, const std::vector<T>& b) noexcept {
    if (a.size() != b.size()) {
      return false;
    }
    
    return constantTimeCompare(a.data(), b.data(), a.size() * sizeof(T)) == 0;
  }
  /**
   * @brief Convert SecureVector to regular vector (for API compatibility)
   * @param secure_vec SecureVector to convert
   * @return Regular vector with copied data
   */
  template<typename T>
  std::vector<T> to_regular_vector(const SecureVector<T>& secure_vec) {
    return std::vector<T>(secure_vec.begin(), secure_vec.end());
  }
  
  /**
   * @brief Convert regular vector to SecureVector
   * @param regular_vec Regular vector to convert
   * @return SecureVector with copied data
   */
  template<typename T>
  SecureVector<T> to_secure_vector(const std::vector<T>& regular_vec) {
    return SecureVector<T>(regular_vec.begin(), regular_vec.end());
  }
}

}  // namespace catapult