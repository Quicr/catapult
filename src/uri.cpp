#include "catapult/uri.hpp"

#include <regex>

#include "catapult/crypto.hpp"
#include "catapult/error.hpp"
#include "catapult/internal/parse_limits.hpp"

namespace catapult {

namespace {
using catapult::internal::kMaxRegexPatternLength;
using catapult::internal::kMaxRegexPatterns;
using catapult::internal::kMaxUriLength;

// Validate regex pattern for potentially dangerous constructs.
// std::regex has no bounded-worst-case matcher; a component-aware URI
// matcher that avoids std::regex on the hot path is planned separately.
bool isRegexPatternSafe(const std::string& pattern) {
  if (pattern.length() > kMaxRegexPatternLength) {
    return false;
  }

  // Track groups and whether they contain quantifiers
  std::vector<bool> group_has_quantifier;
  int depth = 0;

  for (size_t i = 0; i < pattern.length(); ++i) {
    char c = pattern[i];

    // Skip escaped characters
    if (c == '\\' && i + 1 < pattern.length()) {
      ++i;
      continue;
    }

    // Skip character classes
    if (c == '[') {
      while (i + 1 < pattern.length() && pattern[i + 1] != ']') {
        if (pattern[i + 1] == '\\' && i + 2 < pattern.length()) {
          i += 2;
        } else {
          ++i;
        }
      }
      ++i;  // Skip closing ]
      continue;
    }

    if (c == '(') {
      // Check for non-capturing group (?:...) or other special groups
      bool is_group = true;
      if (i + 1 < pattern.length() && pattern[i + 1] == '?') {
        // Skip special constructs like (?=...), (?!...), (?<=...), (?<!...)
        if (i + 2 < pattern.length()) {
          char next = pattern[i + 2];
          if (next == '=' || next == '!' || next == '<') {
            is_group = false;
          }
        }
      }
      if (is_group) {
        group_has_quantifier.push_back(false);
        ++depth;
      }
    } else if (c == ')') {
      if (depth > 0 && !group_has_quantifier.empty()) {
        bool inner_quantified = group_has_quantifier.back();
        group_has_quantifier.pop_back();
        --depth;
        // Check if next char quantifies this group
        if (i + 1 < pattern.length()) {
          char next = pattern[i + 1];
          if (next == '+' || next == '*' || next == '?' || next == '{') {
            // Group is being quantified - if it contained quantifiers, reject
            if (inner_quantified) {
              return false;  // Nested quantifier: (a+)+ or similar
            }
            // Mark parent group as containing a quantifier
            if (!group_has_quantifier.empty()) {
              group_has_quantifier.back() = true;
            }
          }
        }
      }
    } else if (c == '+' || c == '*' || c == '?') {
      // Mark current group as containing a quantifier
      if (!group_has_quantifier.empty()) {
        group_has_quantifier.back() = true;
      }
    } else if (c == '{') {
      // Skip {n,m} style quantifiers
      while (i + 1 < pattern.length() && pattern[i + 1] != '}') {
        ++i;
      }
      if (!group_has_quantifier.empty()) {
        group_has_quantifier.back() = true;
      }
    } else if (c == '|') {
      // Alternation inside a quantified group can cause backtracking
      // (a|b+)+ is dangerous, but (a|b)+ is usually safe
      // We already track quantifiers in groups, so this is handled
    }
  }

  return true;
}
}  // namespace

void UriMatcher::addPattern(const UriPattern& pattern) {
  switch (pattern.type) {
    case UriPatternType::Exact:
      exactPatterns[pattern.pattern] = pattern.pattern;
      break;
    case UriPatternType::Prefix:
      prefixTrie.insert(pattern.pattern, pattern.pattern);
      break;
    case UriPatternType::Suffix:
      suffixTrie.insert(pattern.pattern, pattern.pattern);
      break;
    case UriPatternType::Regex:
      if (regexPatterns.size() >= kMaxRegexPatterns) {
        throw InvalidClaimValueError("Too many regex patterns");
      }
      if (!isRegexPatternSafe(pattern.pattern)) {
        throw InvalidClaimValueError("Regex pattern rejected for safety");
      }
      // Compilation failures previously fell through silently, letting the
      // matcher accept the claim while retaining zero patterns — a partially
      // populated matcher which would then pass through unrelated exact/
      // prefix/suffix entries. Surface the error instead.
      try {
        regexPatterns.emplace_back(std::regex(pattern.pattern),
                                   pattern.pattern);
      } catch (const std::regex_error&) {
        throw InvalidClaimValueError("Regex pattern failed to compile");
      }
      break;
    case UriPatternType::Hash:
      hashPatterns[pattern.pattern] = pattern.pattern;
      break;
  }
}

bool UriMatcher::matches(const std::string& uri) const {
  // Reject oversized URIs to prevent DoS
  if (uri.length() > kMaxUriLength) {
    return false;
  }

  // Check exact match
  if (exactPatterns.find(uri) != exactPatterns.end()) {
    return true;
  }

  // Check prefix match
  if (!prefixTrie.searchPrefix(uri).empty()) {
    return true;
  }

  // Check suffix match
  if (!suffixTrie.searchSuffix(uri).empty()) {
    return true;
  }

  // Check regex patterns
  for (const auto& regexPair : regexPatterns) {
    if (std::regex_match(uri, regexPair.first)) {
      return true;
    }
  }

  // Check hash match
  std::vector<uint8_t> uriBytes(uri.begin(), uri.end());
  std::vector<uint8_t> hashBytes = hashSha256(uriBytes);
  std::string uriHash = base64UrlEncode(hashBytes);
  if (hashPatterns.find(uriHash) != hashPatterns.end()) {
    return true;
  }

  return false;
}

std::vector<std::string> UriMatcher::getMatchingPatterns(
    const std::string& uri) const {
  std::vector<std::string> matches;

  // Reject oversized URIs to prevent DoS
  if (uri.length() > kMaxUriLength) {
    return matches;
  }

  // Check exact match
  auto exactIt = exactPatterns.find(uri);
  if (exactIt != exactPatterns.end()) {
    matches.push_back("exact:" + exactIt->second);
  }

  // Check prefix matches
  auto prefixMatches = prefixTrie.searchPrefix(uri);
  for (const auto& prefixMatch : prefixMatches) {
    matches.push_back("prefix:" + prefixMatch);
  }

  // Check suffix matches
  auto suffixMatches = suffixTrie.searchSuffix(uri);
  for (const auto& suffixMatch : suffixMatches) {
    matches.push_back("suffix:" + suffixMatch);
  }

  // Check regex patterns
  for (const auto& regexPair : regexPatterns) {
    if (std::regex_match(uri, regexPair.first)) {
      matches.push_back("regex:" + regexPair.second);
    }
  }

  // Check hash match
  std::vector<uint8_t> uriBytes(uri.begin(), uri.end());
  std::vector<uint8_t> hashBytes = hashSha256(uriBytes);
  std::string uriHash = base64UrlEncode(hashBytes);
  auto hashIt = hashPatterns.find(uriHash);
  if (hashIt != hashPatterns.end()) {
    matches.push_back("hash:" + hashIt->second);
  }

  return matches;
}

}  // namespace catapult