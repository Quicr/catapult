#include "catapult/uri.hpp"

#include <regex>

#include "catapult/crypto.hpp"

namespace catapult {

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
      try {
        regexPatterns.emplace_back(std::regex(pattern.pattern),
                                   pattern.pattern);
      } catch (const std::regex_error&) {
        // Invalid regex pattern, skip
      }
      break;
    case UriPatternType::Hash:
      hashPatterns[pattern.pattern] = pattern.pattern;
      break;
  }
}

bool UriMatcher::matches(const std::string& uri) const {
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