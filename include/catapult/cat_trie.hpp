/**
 * @file cat_trie.hpp
 * @brief Trie data structures for efficient string matching
 */

#pragma once

#include <algorithm>
#include <memory>
#include <ranges>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include "cat_memory_pool.hpp"

namespace catapult {

// Forward declarations
struct TrieNode;

/**
 * @brief Optimized node structure for trie data structures
 * Uses flat array for all 8-bit characters for maximum performance
 */
struct TrieNode {
  static constexpr size_t BYTE_SIZE = 256;
  
  // Optimized storage for all 8-bit characters (0-255)
  std::array<std::unique_ptr<TrieNode>, BYTE_SIZE> children{};
  
  bool isTerminal = false;                                       ///< Terminal node flag
  std::string value;                                             ///< Stored value
  
  /**
   * @brief Get child node for character
   *  @param c Character to lookup child for
   * @return Non-owning raw pointer to child node, or nullptr if no child exists.
   *         Caller does not own the returned pointer - it remains owned by this node.
   *         The returned pointer is only valid as long as this node exists and
   *         the child is not removed.
   */
  TrieNode* getChild(char c) const noexcept {
    return children[static_cast<unsigned char>(c)].get();
  }
  
  /**
   * @brief Set child node for character (optimized for all byte values)
   */
  void setChild(char c, std::unique_ptr<TrieNode> child) {
      children[static_cast<unsigned char>(c)] = std::move(child);
  }
  
  /**
   * @brief Remove child node for character (optimized for all byte values)
   */
  std::unique_ptr<TrieNode> removeChild(char c) {
    return std::move(children[static_cast<unsigned char>(c)]);
  }
  
  /**
   * @brief Check if node has any children (optimized for full byte array)
   */
  bool hasChildren() const noexcept {
    for (const auto& child : children) {
      if (child) return true;
    }
    return false;
  }
  
  /**
   * @brief Get all child characters (optimized with pre-allocation)
   */
  std::vector<char> getChildChars() const {
    std::vector<char> chars;
    chars.reserve(32);  // Reserve space for common case
    
    for (size_t i = 0; i < BYTE_SIZE; ++i) {
      if (children[i]) {
        chars.push_back(static_cast<char>(i));
      }
    }
    
    return chars;
  }
};

/**
 * @brief Get shared MemoryPool for TrieNode allocations
 */
inline LockFreeMemoryPool<TrieNode, 1024>& getTrieNodePool() {
  static LockFreeMemoryPool<TrieNode, 1024> pool;  // RAII - properly destroyed at program exit
  return pool;
}

/**
 * @brief Optimized trie for efficient prefix matching with memory pooling
 */

class PrefixTrie {
 public:
  std::unique_ptr<TrieNode> root;  ///< Root node
  size_t size = 0;      ///< Number of patterns stored

  /**
   * @brief Construct an empty prefix trie with optional capacity hint
   */
  explicit PrefixTrie(size_t expected_size = 0);
  
  /**
   * @brief Insert a pattern with associated value
   * @param pattern Pattern to insert
   * @param value Associated value
   */
  void insert(std::string_view pattern, std::string_view value);
  
  /**
   * @brief Batch insert multiple patterns for better performance
   * @param patterns Vector of pattern-value pairs
   */
  void insertBatch(const std::vector<std::pair<std::string_view, std::string_view>>& patterns);
  
  /**
   * @brief Optimized batch search for multiple text strings
   * @param texts Vector of texts to search against
   * @return Vector of results, each containing matches for corresponding text
   */
  std::vector<std::vector<std::string>> searchPrefixBatch(const std::vector<std::string_view>& texts) const;
  
  /**
   * @brief Search for patterns that are prefixes of the given text
   * @param text Text to search against
   * @return Vector of matching pattern values (pre-reserved for performance)
   */
  std::vector<std::string> searchPrefix(std::string_view text) const;
  
  /**
   * @brief Check if any stored pattern is a prefix of the given text
   * @param text Text to check
   * @return True if a prefix match exists
   */
  bool containsPrefix(std::string_view text) const;
  
  /**
   * @brief Get all patterns stored in the trie
   * @return Vector of all patterns (pre-reserved for performance)
   */
  std::vector<std::string> getAllPatterns() const;
  
  /**
   * @brief Remove a pattern from the trie
   * @param pattern Pattern to remove
   * @return True if pattern was found and removed
   */
  bool remove(std::string_view pattern);
  
  /**
   * @brief Batch remove multiple patterns for better performance
   * @param patterns Vector of patterns to remove
   * @return Number of patterns successfully removed
   */
  size_t removeBatch(const std::vector<std::string_view>& patterns);
  
  /**
   * @brief Get memory usage statistics
   */
  size_t getMemoryUsage() const noexcept;
  
  /**
   * @brief Clear all patterns and reset trie
   */
  void clear() noexcept;

 private:
  size_t expected_capacity_;
  
  std::unique_ptr<TrieNode> createNode() const {
    // For now, just use regular allocation to ensure stability
    return std::make_unique<TrieNode>();
  }
  
  void collectPatterns(const TrieNode* node, const std::string& prefix,
                       std::vector<std::string>& patterns) const;
  bool removeRecursive(TrieNode* node, const std::string& pattern,
                       size_t index);
  size_t calculateNodeMemory(const TrieNode* node) const noexcept;
};

/**
 * @brief Trie for efficient suffix matching
 */
class SuffixTrie {
 public:
  std::unique_ptr<TrieNode> root;  ///< Root node
  size_t size = 0;      ///< Number of patterns stored

  /**
   * @brief Construct an empty suffix trie
   */
  SuffixTrie();
  
  /**
   * @brief Insert a pattern with associated value
   * @param pattern Pattern to insert
   * @param value Associated value
   */
  void insert(std::string_view pattern, std::string_view value);
  
  /**
   * @brief Batch insert multiple patterns for better performance
   * @param patterns Vector of pattern-value pairs
   */
  void insertBatch(const std::vector<std::pair<std::string_view, std::string_view>>& patterns);
  
  /**
   * @brief Search for patterns that are suffixes of the given text
   * @param text Text to search against
   * @return Vector of matching pattern values
   */
  std::vector<std::string> searchSuffix(std::string_view text) const;
  
  /**
   * @brief Optimized batch search for multiple text strings
   * @param texts Vector of texts to search against
   * @return Vector of results, each containing matches for corresponding text
   */
  std::vector<std::vector<std::string>> searchSuffixBatch(const std::vector<std::string_view>& texts) const;
  
  /**
   * @brief Check if any stored pattern is a suffix of the given text
   * @param text Text to check
   * @return True if a suffix match exists
   */
  bool containsSuffix(std::string_view text) const;
  
  /**
   * @brief Get all patterns stored in the trie
   * @return Vector of all patterns
   */
  std::vector<std::string> getAllPatterns() const;
  
  /**
   * @brief Remove a pattern from the trie
   * @param pattern Pattern to remove
   * @return True if pattern was found and removed
   */
  bool remove(std::string_view pattern);

 private:
  std::unique_ptr<TrieNode> createNode() const {
    // For now, just use regular allocation to ensure stability
    return std::make_unique<TrieNode>();
  }
  
  std::string reverse(std::string_view str) const;
  void collectPatterns(const TrieNode* node, const std::string& prefix,
                       std::vector<std::string>& patterns) const;
  bool removeRecursive(TrieNode* node, const std::string& pattern,
                       size_t index);
};

}  // namespace catapult