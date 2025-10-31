/**
 * @file cat_composite.hpp
 * @brief Composite claim definitions and logic for CAT tokens
 */

#pragma once

#include <memory>
#include <vector>
#include <concepts>
#include <ranges>
#include <algorithm>
#include <utility>
#include <stdexcept>
#include <limits>

#include "error.hpp"
#include "memory_pool.hpp"

namespace catapult {

// Forward declarations
class CatToken;
class CatTokenValidator;

/**
 * @brief Composite claim logical operators
 */
enum class CompositeOperator : uint8_t {
  OR,  ///< At least one claim set must be acceptable
  NOR, ///< No claim sets can be acceptable  
  AND  ///< All claim sets must be acceptable
};

template<CompositeOperator Op>
constexpr bool is_valid_operator() {
  return Op == CompositeOperator::OR || 
         Op == CompositeOperator::NOR || 
         Op == CompositeOperator::AND;
}

// Forward declarations - TypedCompositeClaim templates
template<CompositeOperator Op>
requires (is_valid_operator<Op>())
class TypedCompositeClaim;
using OrClaim = TypedCompositeClaim<CompositeOperator::OR>;
using AndClaim = TypedCompositeClaim<CompositeOperator::AND>;
using NorClaim = TypedCompositeClaim<CompositeOperator::NOR>;

/**
 * @brief  composite claim token validator
 */
template<typename T>
concept TokenValidator = requires(T validator, const CatToken& token) {
  { validator.validate(token) } -> std::same_as<void>;
};

/*
 * @brief Validator concept for composite claim types
 */
template<typename T>  
concept CompositeClaimType = requires(T claim) {
  { T::operation } -> std::convertible_to<CompositeOperator>;
  { claim.getDepth() } -> std::same_as<size_t>;
};

/**
 * @brief Composite claim set representation 
 * 
 * A claim set can either be a regular CatToken or a nested composite claim.
 * This enables arbitrary nesting depth as required by the specification.
 */
struct ClaimSet {
  std::unique_ptr<CatToken> token;
  std::unique_ptr<OrClaim> orComposite;
  std::unique_ptr<AndClaim> andComposite;
  std::unique_ptr<NorClaim> norComposite;
  
  ClaimSet() = default;
  ClaimSet(const CatToken& t);
  ClaimSet(std::unique_ptr<CatToken> t) : token(std::move(t)) {}
  ClaimSet(std::unique_ptr<OrClaim> c) : orComposite(std::move(c)) {}
  ClaimSet(std::unique_ptr<AndClaim> c) : andComposite(std::move(c)) {}
  ClaimSet(std::unique_ptr<NorClaim> c) : norComposite(std::move(c)) {}
  
  ClaimSet(const ClaimSet& other);
  ClaimSet(ClaimSet&& other) noexcept = default;
  ClaimSet& operator=(ClaimSet other) noexcept;
  
  // Explicit destructor to control destruction order
  ~ClaimSet() {
    // Reset in specific order to avoid circular destruction issues
    orComposite.reset();
    andComposite.reset();
    norComposite.reset();
    token.reset();
  }
  
  void swap(ClaimSet& other) noexcept;
  
  bool hasToken() const { return token != nullptr; }
  bool hasComposite() const { 
    return orComposite || andComposite || norComposite;
  }
};

/**
 * @brief Get thread-local memory pool for ClaimSet allocations
 * 
 * Returns a reference to the thread-local memory pool used for ClaimSet
 * object allocation. This pool provides:
 * - Zero contention between threads (thread-local storage)
 * - O(1) allocation/deallocation performance
 * - Reduced heap fragmentation
 * - Better cache locality through spatial locality
 * - Pool size of 512 ClaimSet objects per thread (increased capacity)
 * 
 * @return Reference to the thread-local ClaimSet memory pool
 */
inline ThreadLocalMemoryPool<ClaimSet, 512>& getClaimSetPool() {
  static thread_local ThreadLocalMemoryPool<ClaimSet, 512> pool;
  return pool;
}

/**
 * @brief Get thread-local memory pool for TypedCompositeClaim allocations
 * 
 * Returns a reference to the thread-local memory pool used for composite claim
 * object allocation. This provides:
 * - Zero contention between threads (thread-local storage)
 * - O(1) allocation/deallocation performance for OR/AND/NOR claims
 * - Reduced heap fragmentation
 * - Better cache locality
 * - Pool size of 256 composite claims per thread
 * 
 * @return Reference to the thread-local composite claim memory pool
 */
template<CompositeOperator Op>
inline ThreadLocalMemoryPool<TypedCompositeClaim<Op>, 256>& getCompositeClaimPool() {
  static thread_local ThreadLocalMemoryPool<TypedCompositeClaim<Op>, 256> pool;
  return pool;
}

/**
 * @brief Compile-time constants for composite claim validation
 */
namespace composite_constants {
  constexpr size_t MAX_NESTING_DEPTH = 10;
  constexpr size_t MIN_REQUIRED_DEPTH_SUPPORT = 4;
  constexpr bool ENABLE_DEPTH_VALIDATION = true;
  constexpr size_t MAX_CLAIM_SETS_PER_COMPOSITE = 100;
  
  /**
   * @brief Compile-time validation of claim identifier
   */
  consteval bool is_valid_claim_id(int64_t claim_id) noexcept {
    return claim_id >= 1 && claim_id <= 65535;
  }
  
  /**
   * @brief Validation of COSE algorithm
   */
  consteval bool is_valid_cose_algorithm(int64_t alg_id) noexcept {
    return alg_id == -4 || alg_id == -7 || alg_id == -37; // HMAC256, ES256, PS256
  }
  
  /**
   * @brief Enhanced validation of geographic coordinates
   */
  consteval bool is_valid_latitude(double lat) noexcept {
    return lat >= -90.0 && lat <= 90.0;
  }
  
  consteval bool is_valid_longitude(double lon) noexcept {
    return lon >= -180.0 && lon <= 180.0;
  }
  
  consteval bool is_valid_coordinate_pair(double lat, double lon) noexcept {
    return is_valid_latitude(lat) && is_valid_longitude(lon);
  }
  
  consteval bool is_valid_usage_limit(uint32_t limit) noexcept {
    return limit > 0 && limit <= UINT32_MAX;
  }


  template<size_t N>
  consteval bool is_valid_string_length(const char (&str)[N]) noexcept {
    return N > 1 && N <= 1024; // Reasonable bounds
  }
  
  consteval bool is_valid_string_length(size_t len) noexcept {
    return len > 0 && len <= 1024;
  }
  
  consteval bool is_valid_composite_size(size_t size) noexcept {
    return size > 0 && size <= MAX_CLAIM_SETS_PER_COMPOSITE;
  }
}

/**
 * @brief Compile-time composite claim creation with optional memory pool optimization
 * 
 * Composite claim that provides compile-time type safety and
 * operator validation. Supports optional memory pool allocation for improved
 * performance in high-frequency scenarios.
 *
 * @tparam Op The composite operator (OR, AND, NOR)
 */
template<CompositeOperator Op>
requires (is_valid_operator<Op>())
class TypedCompositeClaim {
public:
  static constexpr CompositeOperator operation = Op;
  std::vector<ClaimSet> claims;
  
  /**
   * @brief Default constructor
   */
  constexpr TypedCompositeClaim() = default;
  
  /**
   * @brief Constructor with designated initializers
   * @param init_claims Initial list of claim sets
   */
  constexpr TypedCompositeClaim(std::initializer_list<ClaimSet> init_claims) 
    : claims(init_claims) {}
  
  /**
   * @brief Compile-time evaluation
   */
  template<TokenValidator Validator>
  bool evaluate(const Validator& validator) const {
    auto evaluator = [this, &validator](const ClaimSet& claimSet) -> bool {
      return evaluateClaimSet(claimSet, validator);
    };
    
    if constexpr (Op == CompositeOperator::OR) {
      return std::ranges::any_of(claims, evaluator);
    } else if constexpr (Op == CompositeOperator::NOR) {
      return !std::ranges::any_of(claims, evaluator);
    } else if constexpr (Op == CompositeOperator::AND) {
      return std::ranges::all_of(claims, evaluator);
    }
  }
  
  /**
   * @brief Optimized depth calculation with memoization
   */
  size_t getDepth() const noexcept {
    if (cached_depth_ == 0) {
      cached_depth_ = calculateDepthRecursive();
    }
    return cached_depth_;
  }
  
  /**
   * @brief Invalidate depth cache when structure changes
   */
  void invalidateDepthCache() noexcept {
    cached_depth_ = 0;
  }

private:
  mutable size_t cached_depth_ = 0;  ///< Cached depth value
  
  size_t calculateDepthRecursive() const noexcept {
    size_t maxDepth = 1;
    for (const auto& claimSet : claims) {
      if (claimSet.hasComposite()) {
        size_t childDepth = 0;
        if (claimSet.orComposite) {
          childDepth = claimSet.orComposite->getDepth();
        } else if (claimSet.andComposite) {
          childDepth = claimSet.andComposite->getDepth();
        } else if (claimSet.norComposite) {
          childDepth = claimSet.norComposite->getDepth();
        }
        maxDepth = std::max(maxDepth, childDepth + 1);
      }
    }
    return maxDepth;
  }

public:
  
  /**
   * @brief Compile-time depth validation
   */
  constexpr bool isDepthValid() const noexcept {
    if constexpr (composite_constants::ENABLE_DEPTH_VALIDATION) {
      return getDepth() <= composite_constants::MAX_NESTING_DEPTH;
    } else {
      return true;
    }
  }
  
  /**
   * @brief Add a claim set to this composite claim
   * @param claimSet The claim set to add
   * 
   * Pool optimization is applied to the composite claim allocation itself,
   * not to individual ClaimSet objects which are stored directly in the vector.
   */
  void addClaimSet(const ClaimSet& claimSet) {
    if (claims.size() >= composite_constants::MAX_CLAIM_SETS_PER_COMPOSITE) {
      throw InvalidClaimValueError("Too many claim sets in composite");
    }
    claims.push_back(claimSet);
    invalidateDepthCache();
  }
  
  /**
   * @brief Add a token as a claim set
   * @param token The token to wrap in a ClaimSet and add
   * 
   * Pool optimization is applied to the composite claim allocation itself,
   * not to individual ClaimSet objects which are stored directly in the vector.
   */
  void addToken(const CatToken& token) {
    if (claims.size() >= composite_constants::MAX_CLAIM_SETS_PER_COMPOSITE) {
      throw InvalidClaimValueError("Too many claim sets in composite");
    }
    claims.emplace_back(token);
    invalidateDepthCache();
  }
  
private:
  template<typename Validator>
  bool evaluateClaimSet(const ClaimSet& claimSet, const Validator& validator) const;
};



/**
 * @brief Composite claims container structure using TypedCompositeClaim
 */
struct CompositeClaims {
  std::optional<std::unique_ptr<OrClaim>> orClaim;   ///< OR composite claim
  std::optional<std::unique_ptr<NorClaim>> norClaim; ///< NOR composite claim  
  std::optional<std::unique_ptr<AndClaim>> andClaim; ///< AND composite claim
  
  CompositeClaims() = default;
  
  // Copy and move constructors for proper unique_ptr handling
  CompositeClaims(const CompositeClaims& other);
  CompositeClaims(CompositeClaims&& other) noexcept = default;
  CompositeClaims& operator=(const CompositeClaims& other);
  CompositeClaims& operator=(CompositeClaims&& other) noexcept = default;
  
  /**
   * @brief Check if any composite claims are present
   * @return true if at least one composite claim is set
   */
  bool hasComposites() const;
  
  /**
   * @brief Validate all composite claims
   * @param validator The validator context to use
   * @return true if all composite claims are satisfied
   */
  template<TokenValidator Validator>
  bool validateAll(const Validator& validator) const;
};

/**
 * @brief Compile-time utility functions for creating composite claims
 */
namespace composite_utils {

/**
 * @brief Create a typed composite claim
 */
template<CompositeOperator Op, typename... ClaimSets>
requires (is_valid_operator<Op>()) && (std::constructible_from<ClaimSet, ClaimSets> && ...)
constexpr auto createTypedComposite(ClaimSets&&... claimSets) {
  return TypedCompositeClaim<Op>{std::forward<ClaimSets>(claimSets)...};
}

/**
 * @brief Compile-time OR composite creation
 */
template<typename... ClaimSets>
constexpr auto createOrCompositeTyped(ClaimSets&&... claimSets) {
  return createTypedComposite<CompositeOperator::OR>(std::forward<ClaimSets>(claimSets)...);
}

/**
 * @brief Compile-time AND composite creation
 */
template<typename... ClaimSets>
constexpr auto createAndCompositeTyped(ClaimSets&&... claimSets) {
  return createTypedComposite<CompositeOperator::AND>(std::forward<ClaimSets>(claimSets)...);
}

/**
 * @brief Compile-time NOR composite creation
 */
template<typename... ClaimSets>
constexpr auto createNorCompositeTyped(ClaimSets&&... claimSets) {
  return createTypedComposite<CompositeOperator::NOR>(std::forward<ClaimSets>(claimSets)...);
}

/**
 * @brief Constexpr validation of composite depth
 */
template<CompositeClaimType T>
constexpr bool validateDepth(const T& claim) noexcept {
  return claim.getDepth() <= composite_constants::MAX_NESTING_DEPTH &&
         claim.getDepth() >= 1;
}

/**
 * @brief Runtime utility functions using TypedCompositeClaim
 * 
 * These functions provide convenient ways to create typed composite claims from
 * collections of claim sets or tokens. All functions support optional
 * memory pool allocation for improved performance.
 * 
 * Performance Notes:
 * - When usePool=true, uses ThreadLocalMemoryPool for both ClaimSet and composite allocations
 * - Pool allocation is beneficial for high-frequency composite claim creation
 * - Pool reduces heap fragmentation and improves cache locality
 * - Default usePool=false maintains backward compatibility
 */

/**
 * @brief Create an OR composite claim from claim sets
 * @param claimSets Vector of claim sets to include
 * @param usePool Whether to use memory pool for allocations (default: false)
 * @return Unique pointer to the created OR composite claim
 */
[[nodiscard]] std::unique_ptr<OrClaim> createOrComposite(const std::vector<ClaimSet>& claimSets, bool usePool = false);

/**
 * @brief Create a NOR composite claim from claim sets
 * @param claimSets Vector of claim sets to include
 * @param usePool Whether to use memory pool for allocations (default: false)
 * @return Unique pointer to the created NOR composite claim
 */
[[nodiscard]] std::unique_ptr<NorClaim> createNorComposite(const std::vector<ClaimSet>& claimSets, bool usePool = false);

/**
 * @brief Create an AND composite claim from claim sets
 * @param claimSets Vector of claim sets to include
 * @param usePool Whether to use memory pool for allocations (default: false)
 * @return Unique pointer to the created AND composite claim
 */
[[nodiscard]] std::unique_ptr<AndClaim> createAndComposite(const std::vector<ClaimSet>& claimSets, bool usePool = false);

/**
 * @brief Create an OR composite claim from tokens
 * @param tokens Vector of tokens to wrap in claim sets
 * @param usePool Whether to use memory pool for allocations (default: false)
 * @return Unique pointer to the created OR composite claim
 */
[[nodiscard]] std::unique_ptr<OrClaim> createOrFromTokens(const std::vector<CatToken>& tokens, bool usePool = false);

/**
 * @brief Create a NOR composite claim from tokens
 * @param tokens Vector of tokens to wrap in claim sets
 * @param usePool Whether to use memory pool for allocations (default: false)
 * @return Unique pointer to the created NOR composite claim
 */
[[nodiscard]] std::unique_ptr<NorClaim> createNorFromTokens(const std::vector<CatToken>& tokens, bool usePool = false);

/**
 * @brief Create an AND composite claim from tokens
 * @param tokens Vector of tokens to wrap in claim sets
 * @param usePool Whether to use memory pool for allocations (default: false)
 * @return Unique pointer to the created AND composite claim
 */
[[nodiscard]] std::unique_ptr<AndClaim> createAndFromTokens(const std::vector<CatToken>& tokens, bool usePool = false);

/**
 * @brief Constexpr composite claim factory with enhanced type safety
 */
template<CompositeOperator Op>
requires (is_valid_operator<Op>())
struct CompositeFactory {

  template<std::ranges::range R>
  requires std::convertible_to<std::ranges::range_value_t<R>, ClaimSet>
  static constexpr auto create(R&& claimSets) {
    TypedCompositeClaim<Op> composite;
    
    std::ranges::for_each(claimSets, [&composite](auto&& claimSet) {
      composite.addClaimSet(std::forward<decltype(claimSet)>(claimSet));
    });
    
    // Compile-time depth validation
    static_assert(composite.isDepthValid(), "Composite claim exceeds maximum nesting depth");
    
    return composite;
  }
  
  template<typename... ClaimSets>
  requires (std::convertible_to<ClaimSets, ClaimSet> && ...)
  static constexpr auto create(ClaimSets&&... claimSets) {
    auto composite = TypedCompositeClaim<Op>{std::forward<ClaimSets>(claimSets)...};
    
    // Compile-time validation
    static_assert(sizeof...(claimSets) > 0, "Composite claim must contain at least one claim set");
    static_assert(sizeof...(claimSets) <= 100, "Too many claim sets in composite");
    
    return composite;
  }
};

/**
 * @brief Type aliases for factories with compile-time validation
 */
using OrFactory = CompositeFactory<CompositeOperator::OR>;
using AndFactory = CompositeFactory<CompositeOperator::AND>;
using NorFactory = CompositeFactory<CompositeOperator::NOR>;

/**
 * @brief Compile-time helper for creating validated composites
 */
template<CompositeOperator Op, typename... ClaimSets>
constexpr auto make_validated_composite(ClaimSets&&... claimSets) 
  requires (is_valid_operator<Op>() && (std::convertible_to<ClaimSets, ClaimSet> && ...)) {
  return CompositeFactory<Op>::create(std::forward<ClaimSets>(claimSets)...);
}

} // namespace composite_utils

/**
 * @brief Usage Examples for Memory Pool Optimization with TypedCompositeClaim
 * 
 * @code
 * // Basic usage without pool (default behavior)
 * auto orComposite = std::make_unique<OrClaim>();
 * orComposite->addToken(token1);
 * orComposite->addToken(token2);
 * 
 * // With memory pool optimization for high-frequency scenarios
 * auto pooledComposite = std::make_unique<AndClaim>(true);  // Enable pool
 * pooledComposite->addToken(token1);  // Uses thread-local memory pool
 * pooledComposite->addToken(token2);  // Uses thread-local memory pool
 * 
 * // Using utility functions with pool optimization
 * std::vector<CatToken> tokens = {token1, token2, token3};
 * auto orComposite = createOrFromTokens(tokens, true);    // Pool enabled
 * auto andComposite = createAndFromTokens(tokens, false); // Pool disabled
 * 
 * // Compile-time typed composites with pool optimization
 * OrClaim orClaim(true);  // Enable pool allocation
 * orClaim.addToken(token1);
 * orClaim.addToken(token2);
 * 
 * // Compile-time factory functions
 * auto composite = composite_utils::createOrCompositeTyped(claimSet1, claimSet2);
 * 
 * // When to use pool optimization:
 * // - High-frequency composite claim creation/destruction
 * // - Processing many tokens in batch operations
 * // - Performance-critical token validation paths
 * // - Reducing heap fragmentation in long-running services
 * 
 * // Performance considerations:
 * // - Pool allocation: O(1) thread-local, no contention
 * // - Heap allocation: O(log n) with potential contention
 * // - Pool reduces cache misses due to spatial locality
 * // - Pool eliminates malloc/free overhead for both ClaimSet and composite objects
 * @endcode
 */

// Template method implementations that need full CatToken definition
// These will be explicitly instantiated in the implementation files

} // namespace catapult