/**
 * @file uri.hpp
 * @brief URI parsing, pattern matching, and CTA-5007-B `catu` evaluation.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "claims.hpp"
#include "internal/trie.hpp"

namespace catapult {

// ---------------------------------------------------------------------------
// URI parsing
// ---------------------------------------------------------------------------

/// CTA-5007-B §4.6.10 URI component labels used as `catu` map keys.
enum class UriComponentLabel : int64_t {
  Scheme = 0,
  Host = 1,
  Port = 2,
  Path = 3,
  Query = 4,
  ParentPath = 5,
  Filename = 6,
  Stem = 7,
  Extension = 8,
};

/**
 * @brief Parsed URI in the components used by `catu` matching.
 *
 * All components are stored in normalized form:
 *   - `scheme` lowercased
 *   - `host` lowercased with `[]` stripped from IPv6 literals
 *   - `port` decimal string with leading zeros removed
 *   - `path`/`parent_path`/`filename`/`stem`/`extension` derived after
 *     percent-decoding-safe segment normalization (dot-segment removal)
 */
struct ParsedUri {
  std::string scheme;
  std::string host;
  std::string port;
  std::string path;
  std::string query;
  std::string parent_path;
  std::string filename;
  std::string stem;
  std::string extension;
};

/**
 * @brief Parse a URI reference into `ParsedUri` components.
 *
 * Rejects oversized inputs and returns `std::nullopt` when the input cannot
 * be split into a scheme + hier-part per RFC 3986.
 */
std::optional<ParsedUri> parseUri(std::string_view uri);

/**
 * @brief Extract the value of a single labeled component from a `ParsedUri`.
 */
const std::string* componentValue(const ParsedUri& parsed,
                                  UriComponentLabel label);

// ---------------------------------------------------------------------------
// catu evaluation
// ---------------------------------------------------------------------------

/**
 * @brief Match a `catu` map against a request URI.
 *
 * All components present in the map must independently match the
 * corresponding parsed component of `uri`. An unknown component label or a
 * regex that fails to compile is treated as a match failure.
 */
bool matchesCatu(const CatUriMatchMap& catu, std::string_view uri);

/// @overload
bool matchesCatu(const CatUriMatchMap& catu, const ParsedUri& parsed);

// ---------------------------------------------------------------------------
// Legacy string-oriented pattern matcher
// ---------------------------------------------------------------------------

/**
 * @brief Types of URI pattern matching (legacy string-oriented matcher).
 */
enum class UriPatternType {
  Exact,   ///< Exact string match
  Prefix,  ///< Prefix match
  Suffix,  ///< Suffix match
  Regex,   ///< Regular expression match
  Hash     ///< Hash-based match
};

/**
 * @brief URI pattern used with the legacy `UriMatcher`.
 */
struct UriPattern {
  UriPatternType type;
  std::string pattern;

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
 * @brief Encapsulated legacy URI pattern matcher.
 *
 * State becomes fixed after `addPattern` calls; callers cannot reach past
 * the public API to bypass size or regex-safety limits.
 */
class UriMatcher {
 public:
  void addPattern(const UriPattern& pattern);

  bool matches(const std::string& uri) const;

  std::vector<std::string> getMatchingPatterns(const std::string& uri) const;

 private:
  PrefixTrie prefixTrie_;
  SuffixTrie suffixTrie_;
  std::unordered_map<std::string, std::string> exactPatterns_;
  std::vector<std::pair<std::regex, std::string>> regexPatterns_;
  std::unordered_map<std::string, std::string> hashPatterns_;
};

}  // namespace catapult
