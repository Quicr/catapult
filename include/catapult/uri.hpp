/**
 * @file cat_uri.hpp
 * @brief URI pattern matching and validation functionality
 */

#pragma once

#include <regex>
#include <string>
#include <unordered_map>
#include <vector>

#include "memory_pool.hpp"
#include "trie.hpp"

namespace catapult {

// Forward declarations
struct UriPattern;
class UriMatcher;

/**
 * @brief Types of URI pattern matching
 */
enum class UriPatternType {
  Exact,   ///< Exact string match
  Prefix,  ///< Prefix match
  Suffix,  ///< Suffix match
  Regex,   ///< Regular expression match
  Hash     ///< Hash-based match
};

/**
 * @brief URI pattern structure for flexible matching
 */
struct UriPattern {
  UriPatternType type;  ///< Type of pattern matching
  std::string pattern;  ///< Pattern string

  /**
   * @brief Construct a URI pattern
   * @param t Pattern type
   * @param p Pattern string
   */
  UriPattern(UriPatternType t, const std::string& p) : type(t), pattern(p) {}

  static UriPattern exact(const std::string& uri) {
    return UriPattern(UriPatternType::Exact, uri);
  }

  static UriPattern prefix(const std::string& prefix) {
    return UriPattern(UriPatternType::Prefix, prefix);
  }

  static UriPattern suffix(const std::string& suffix) {
    return UriPattern(UriPatternType::Suffix, suffix);
  }

  static UriPattern regex(const std::string& pattern) {
    return UriPattern(UriPatternType::Regex, pattern);
  }

  static UriPattern hash(const std::string& hash) {
    return UriPattern(UriPatternType::Hash, hash);
  }

  bool operator==(const UriPattern& other) const {
    return type == other.type && pattern == other.pattern;
  }

  bool operator==(const std::string& str) const { return pattern == str; }
};

/**
 * @brief Efficient URI pattern matcher supporting multiple pattern types
 */
class UriMatcher {
 public:
  PrefixTrie prefixTrie;  ///< Trie for prefix patterns
  SuffixTrie suffixTrie;  ///< Trie for suffix patterns
  std::unordered_map<std::string, std::string>
      exactPatterns;  ///< Exact match patterns
  std::vector<std::pair<std::regex, std::string>>
      regexPatterns;  ///< Regex patterns
  std::unordered_map<std::string, std::string>
      hashPatterns;  ///< Hash-based patterns

  /**
   * @brief Add a pattern to the matcher
   * @param pattern URI pattern to add
   */
  void addPattern(const UriPattern& pattern);

  /**
   * @brief Check if a URI matches any stored patterns
   * @param uri URI to test
   * @return True if the URI matches any pattern
   */
  bool matches(const std::string& uri) const;

  /**
   * @brief Get all patterns that match the given URI
   * @param uri URI to test
   * @return Vector of matching pattern strings
   */
  std::vector<std::string> getMatchingPatterns(const std::string& uri) const;
};

/**
 * @brief Get memory pools for URI processing
 */
inline ThreadLocalMemoryPool<UriPattern, 256>& getUriPatternPool() {
  static thread_local ThreadLocalMemoryPool<UriPattern, 256> pool;
  return pool;
}

inline ThreadLocalMemoryPool<std::vector<std::string>, 128>&
getUriResultPool() {
  static thread_local ThreadLocalMemoryPool<std::vector<std::string>, 128> pool;
  return pool;
}

inline ThreadLocalMemoryPool<UriMatcher, 64>& getUriMatcherPool() {
  static thread_local ThreadLocalMemoryPool<UriMatcher, 64> pool;
  return pool;
}

}  // namespace catapult