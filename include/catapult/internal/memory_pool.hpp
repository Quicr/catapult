/**
 * @file memory_pool.hpp
 * @brief Bounded object pool for hot-path allocations.
 *
 * The pool serves TrieNode allocations during URI-matcher construction. It is
 * intentionally simple: a mutex-guarded singly linked free list of pre-allocated
 * cache-line-aligned slots, with heap fallback when exhausted. Ownership on
 * release is resolved by an exact `offsetof` conversion from the returned slot
 * back to its enclosing node, so the pool never has to infer membership from a
 * pointer-in-range comparison.
 */

#pragma once

#ifdef _MSC_VER
#pragma warning(push)
// clang-format off
#pragma warning(disable : 4324)  // structure was padded due to alignment specifier
// clang-format on
#endif

#include <array>
#include <atomic>
#include <bit>
#include <concepts>
#include <memory>
#include <mutex>
#include <new>
#include <span>
#include <utility>

namespace catapult {

template <typename T, size_t PoolSize = 1024>
class BoundedObjectPool {
  static_assert(PoolSize > 0, "PoolSize must be positive");

 private:
  static constexpr size_t CACHE_LINE_SIZE = 64;

  struct alignas(CACHE_LINE_SIZE) PoolNode {
    alignas(T) std::byte storage[sizeof(T)];
    PoolNode* next = nullptr;
    bool in_use = false;
  };

  mutable std::mutex mu_;
  PoolNode* free_head_ = nullptr;
  std::array<PoolNode, PoolSize> pool_{};

  alignas(CACHE_LINE_SIZE) mutable std::atomic<size_t> pool_hits_{0};
  alignas(CACHE_LINE_SIZE) mutable std::atomic<size_t> pool_misses_{0};

 public:
  class PoolPtr {
   private:
    T* ptr_ = nullptr;
    BoundedObjectPool* pool_ = nullptr;

   public:
    PoolPtr() = default;

    PoolPtr(T* ptr, BoundedObjectPool* pool) noexcept
        : ptr_(ptr), pool_(pool) {}

    ~PoolPtr() {
      if (ptr_) {
        if (pool_) {
          pool_->deallocate(ptr_);
        } else {
          delete ptr_;
        }
      }
    }

    PoolPtr(PoolPtr&& other) noexcept
        : ptr_(std::exchange(other.ptr_, nullptr)),
          pool_(std::exchange(other.pool_, nullptr)) {}

    PoolPtr& operator=(PoolPtr&& other) noexcept {
      if (this != &other) {
        if (ptr_) {
          if (pool_) {
            pool_->deallocate(ptr_);
          } else {
            delete ptr_;
          }
        }
        ptr_ = std::exchange(other.ptr_, nullptr);
        pool_ = std::exchange(other.pool_, nullptr);
      }
      return *this;
    }

    PoolPtr(const PoolPtr&) = delete;
    PoolPtr& operator=(const PoolPtr&) = delete;

    T* get() const noexcept { return ptr_; }
    T* operator->() const noexcept { return ptr_; }
    T& operator*() const noexcept { return *ptr_; }
    explicit operator bool() const noexcept { return ptr_ != nullptr; }

    T* release() noexcept {
      pool_ = nullptr;
      return std::exchange(ptr_, nullptr);
    }
  };

  BoundedObjectPool() {
    for (size_t i = 0; i + 1 < PoolSize; ++i) {
      pool_[i].next = &pool_[i + 1];
    }
    pool_[PoolSize - 1].next = nullptr;
    free_head_ = &pool_[0];
  }

  ~BoundedObjectPool() {
    for (auto& node : pool_) {
      if (node.in_use) {
        std::destroy_at(reinterpret_cast<T*>(node.storage));
      }
    }
  }

  BoundedObjectPool(const BoundedObjectPool&) = delete;
  BoundedObjectPool& operator=(const BoundedObjectPool&) = delete;
  BoundedObjectPool(BoundedObjectPool&&) = delete;
  BoundedObjectPool& operator=(BoundedObjectPool&&) = delete;

  template <typename... Args>
  [[nodiscard]] PoolPtr make(Args&&... args) noexcept(
      std::is_nothrow_constructible_v<T, Args...>) {
    static_assert(std::is_constructible_v<T, Args...>,
                  "T must be constructible from Args...");
    if (auto* ptr = allocate_raw()) {
      if constexpr (std::is_nothrow_constructible_v<T, Args...>) {
        std::construct_at(ptr, std::forward<Args>(args)...);
        return PoolPtr(ptr, this);
      } else {
        try {
          std::construct_at(ptr, std::forward<Args>(args)...);
          return PoolPtr(ptr, this);
        } catch (...) {
          release_slot(ptr);
          throw;
        }
      }
    }

    pool_misses_.fetch_add(1, std::memory_order_relaxed);
    if constexpr (std::is_nothrow_constructible_v<T, Args...>) {
      return PoolPtr(new T(std::forward<Args>(args)...), nullptr);
    } else {
      try {
        return PoolPtr(new T(std::forward<Args>(args)...), nullptr);
      } catch (...) {
        return PoolPtr();
      }
    }
  }

  [[nodiscard]] PoolPtr make() noexcept(
      std::is_nothrow_default_constructible_v<T>) {
    return make<>();
  }

  struct Stats {
    size_t pool_hits;
    size_t pool_misses;
    double hit_rate() const noexcept {
      auto total = pool_hits + pool_misses;
      return total > 0 ? static_cast<double>(pool_hits) / total : 0.0;
    }
  };

  Stats get_stats() const noexcept {
    return {pool_hits_.load(std::memory_order_relaxed),
            pool_misses_.load(std::memory_order_relaxed)};
  }

  size_t available() const noexcept {
    std::lock_guard<std::mutex> lock(mu_);
    size_t count = 0;
    for (auto* n = free_head_; n; n = n->next) {
      ++count;
      if (count > PoolSize) {
        break;
      }
    }
    return count;
  }

  bool is_pool_memory(T* ptr) const noexcept {
    if (!ptr) return false;
    const auto* pool_start =
        reinterpret_cast<const std::byte*>(&pool_[0].storage);
    const auto* pool_end =
        reinterpret_cast<const std::byte*>(&pool_[PoolSize - 1].storage) +
        sizeof(T);
    const auto* ptr_addr = reinterpret_cast<const std::byte*>(ptr);
    return ptr_addr >= pool_start && ptr_addr < pool_end;
  }

  void deallocate_pool_memory_only(T* ptr) noexcept {
    if (!ptr) return;
    auto* node_ptr = reinterpret_cast<PoolNode*>(
        reinterpret_cast<std::byte*>(ptr) - offsetof(PoolNode, storage));
    std::lock_guard<std::mutex> lock(mu_);
    if (!node_ptr->in_use) return;
    node_ptr->in_use = false;
    node_ptr->next = free_head_;
    free_head_ = node_ptr;
  }

 private:
  T* allocate_raw() noexcept {
    std::lock_guard<std::mutex> lock(mu_);
    if (!free_head_) {
      return nullptr;
    }
    auto* node = free_head_;
    free_head_ = node->next;
    node->next = nullptr;
    node->in_use = true;
    pool_hits_.fetch_add(1, std::memory_order_relaxed);
    return reinterpret_cast<T*>(node->storage);
  }

  void release_slot(T* ptr) noexcept {
    auto* node_ptr = reinterpret_cast<PoolNode*>(
        reinterpret_cast<std::byte*>(ptr) - offsetof(PoolNode, storage));
    std::lock_guard<std::mutex> lock(mu_);
    node_ptr->in_use = false;
    node_ptr->next = free_head_;
    free_head_ = node_ptr;
  }

  friend class PoolPtr;
  friend struct TrieNodePoolDeleter;

  void deallocate(T* ptr) noexcept {
    if (!ptr) return;
    if (!is_pool_memory(ptr)) {
      delete ptr;
      return;
    }
    auto* node_ptr = reinterpret_cast<PoolNode*>(
        reinterpret_cast<std::byte*>(ptr) - offsetof(PoolNode, storage));
    bool was_in_use = false;
    {
      std::lock_guard<std::mutex> lock(mu_);
      if (node_ptr->in_use) {
        node_ptr->in_use = false;
        was_in_use = true;
      }
    }
    if (!was_in_use) {
      return;
    }
    std::destroy_at(ptr);
    std::lock_guard<std::mutex> lock(mu_);
    node_ptr->next = free_head_;
    free_head_ = node_ptr;
  }
};

}  // namespace catapult

#ifdef _MSC_VER
#pragma warning(pop)
#endif
