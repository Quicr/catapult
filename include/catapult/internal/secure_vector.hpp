/**
 * @file secure_vector.hpp
 * @brief Secure memory allocator and vector for sensitive cryptographic data
 */

#pragma once

#include <openssl/crypto.h>

#include <atomic>
#include <concepts>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <span>
#include <vector>

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
template <typename T>
class SecureAllocator {
 public:
  using value_type = T;
  using size_type = std::size_t;
  using pointer = T*;
  using const_pointer = const T*;

  template <typename U>
  struct rebind {
    using other = SecureAllocator<U>;
  };

  SecureAllocator() = default;

  template <typename U>
  SecureAllocator(const SecureAllocator<U>&) noexcept {}

  /**
   * @brief Allocate and lock memory to prevent swapping
   * @param n Number of elements to allocate
   * @return Pointer to locked memory
   * @throws std::bad_alloc if allocation or locking fails
   */
  T* allocate(size_t n) {
    if (n == 0) return nullptr;

    if (n > std::numeric_limits<size_t>::max() / sizeof(T)) {
      throw std::bad_alloc();
    }

    size_t size = n * sizeof(T);
    size_t page_size = getPageSize();

    // Small-allocation fast path: an HMAC key is 32 bytes; page-rounding it
    // to 4 KiB inflates the footprint of every issuer key ~128x. When the
    // request already fits inside a page we allocate at the value's natural
    // alignment. mlock() on POSIX rounds to page boundaries internally, so
    // the secret is still resident even without a page-aligned base.
    if (size < page_size) {
      size_t alloc_align = alignof(T) < alignof(std::max_align_t)
                               ? alignof(std::max_align_t)
                               : alignof(T);
      size_t alloc_size = ((size + alloc_align - 1) / alloc_align) * alloc_align;
      T* ptr = static_cast<T*>(std::aligned_alloc(alloc_align, alloc_size));
      if (!ptr) throw std::bad_alloc();
      lockMemory(ptr, size);
      return ptr;
    }

    if (size > SIZE_MAX - page_size) {
      throw std::bad_alloc();
    }
    size_t aligned_size = ((size + page_size - 1) / page_size) * page_size;

    T* ptr = static_cast<T*>(std::aligned_alloc(page_size, aligned_size));
    if (!ptr) throw std::bad_alloc();

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
      size_t page_size = getPageSize();

      if (size < page_size) {
        // Small-alloc path: unlock and zero exactly the requested bytes; the
        // kernel handles page-granular mlock/munlock rounding internally.
        secureZero(ptr, size);
        unlockMemory(ptr, size);
        std::free(ptr);
        return;
      }

      size_t aligned_size = ((size + page_size - 1) / page_size) * page_size;

      secureZero(ptr, aligned_size);
      unlockMemory(ptr, aligned_size);

      std::free(ptr);
    }
  }

  template <typename U>
  bool operator==(const SecureAllocator<U>&) const noexcept {
    return true;
  }

  template <typename U>
  bool operator!=(const SecureAllocator<U>&) const noexcept {
    return false;
  }

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
   * @brief Lock memory to prevent swapping.
   *
   * Best-effort: on hardened kernels or under an RLIMIT_MEMLOCK cap the
   * syscall fails and the region will still be pageable. Callers relying on
   * out-of-swap semantics should check `mlockAvailable()`.
   */
  static void lockMemory(void* ptr, size_t size) noexcept {
#ifdef _WIN32
    if (VirtualLock(ptr, size) == 0) {
      recordLockFailure();
    }
#else
    if (mlock(ptr, size) != 0) {
      recordLockFailure();
    }
#endif
  }

 public:
  /**
   * @brief Report whether every prior `mlock`/`VirtualLock` call succeeded.
   *
   * Callers can query this at startup to decide whether to trust the
   * allocator for key material. It becomes `false` on the first failure and
   * stays `false` for the process lifetime.
   */
  static bool mlockAvailable() noexcept {
    return !mlockFailed().load(std::memory_order_acquire);
  }

 private:
  static std::atomic<bool>& mlockFailed() noexcept {
    static std::atomic<bool> flag{false};
    return flag;
  }

  static void recordLockFailure() noexcept {
    mlockFailed().store(true, std::memory_order_release);
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
template <typename T>
using SecureVector = std::vector<T, SecureAllocator<T>>;

/**
 * @brief Utility functions for secure memory operations and timing-attack
 * resistance
 */
namespace secure_utils {
/**
 * @brief Constant-time comparison of two equal-length byte regions.
 *
 * Backed by OpenSSL's `CRYPTO_memcmp`, which is the vetted primitive for
 * comparing secrets of a fixed public length. Not constant-time in the
 * *length* of the inputs — callers must ensure `size` is not a secret.
 *
 * @return 0 if the regions are byte-for-byte equal, non-zero otherwise.
 */
inline int constantTimeCompare(const void* a, const void* b,
                               size_t size) noexcept {
  if (size == 0) return 0;
  return CRYPTO_memcmp(a, b, size);
}

/**
 * @brief Compare two vectors for equality without leaking content timing.
 *
 * Uses `CRYPTO_memcmp` on the shared prefix. The lengths themselves are
 * treated as public: a caller receiving a variable-length secret should
 * arrange for it to be padded to a fixed public size before comparison, or
 * accept that length information may be revealed.
 */
template <typename T>
inline bool constantTimeEqual(const std::vector<T>& a,
                              const std::vector<T>& b) noexcept {
  // Constant-time size comparison to prevent length oracle
  volatile size_t size_a = a.size();
  volatile size_t size_b = b.size();
  volatile bool sizes_equal = (size_a == size_b);

  // Compare up to the smaller size, then factor in size equality
  // Use volatile variables consistently for timing safety
  size_t min_size = (size_a < size_b) ? size_a : size_b;
  int content_equal =
      (min_size == 0)
          ? 0
          : constantTimeCompare(a.data(), b.data(), min_size * sizeof(T));

  return sizes_equal && (content_equal == 0);
}

/**
 * @brief Compare two spans for equality without leaking content timing.
 *
 * See `constantTimeEqual(vector, vector)` for the length-oracle caveat.
 */
template <typename T>
inline bool constantTimeEqual(std::span<const T> a,
                              std::span<const T> b) noexcept {
  // Constant-time size comparison to prevent length oracle
  volatile size_t size_a = a.size();
  volatile size_t size_b = b.size();
  volatile bool sizes_equal = (size_a == size_b);

  // Compare up to the smaller size, then factor in size equality
  // Use volatile variables consistently for timing safety
  size_t min_size = (size_a < size_b) ? size_a : size_b;
  int content_equal =
      (min_size == 0)
          ? 0
          : constantTimeCompare(a.data(), b.data(), min_size * sizeof(T));

  return sizes_equal && (content_equal == 0);
}
/**
 * @brief Convert SecureVector to regular vector (for API compatibility)
 * @param secure_vec SecureVector to convert
 * @return Regular vector with copied data
 */
template <typename T>
std::vector<T> to_regular_vector(const SecureVector<T>& secure_vec) {
  return std::vector<T>(secure_vec.begin(), secure_vec.end());
}

/**
 * @brief Convert regular vector to SecureVector
 * @param regular_vec Regular vector to convert
 * @return SecureVector with copied data
 */
template <typename T>
SecureVector<T> to_secure_vector(const std::vector<T>& regular_vec) {
  return SecureVector<T>(regular_vec.begin(), regular_vec.end());
}
}  // namespace secure_utils

}  // namespace catapult