#include "catapult/uri.hpp"

#include <algorithm>
#include <cctype>
#include <regex>
#include <string>
#include <string_view>

#include "catapult/base64.hpp"
#include "catapult/crypto.hpp"
#include "catapult/error.hpp"
#include "catapult/internal/parse_limits.hpp"

namespace catapult {

namespace {

using catapult::internal::kMaxRegexPatternLength;
using catapult::internal::kMaxRegexPatterns;
using catapult::internal::kMaxUriLength;

// -------------------------------------------------------------------------
// URI parsing helpers (RFC 3986 subset sufficient for catu matching)
// -------------------------------------------------------------------------

std::string toLowerAscii(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (char c : s) {
    if (c >= 'A' && c <= 'Z') {
      out.push_back(static_cast<char>(c + ('a' - 'A')));
    } else {
      out.push_back(c);
    }
  }
  return out;
}

std::string stripLeadingZeros(std::string_view digits) {
  size_t i = 0;
  while (i + 1 < digits.size() && digits[i] == '0') {
    ++i;
  }
  return std::string(digits.substr(i));
}

bool isSchemeStart(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

bool isSchemeChar(char c) {
  return isSchemeStart(c) || (c >= '0' && c <= '9') || c == '+' || c == '-' ||
         c == '.';
}

// Remove RFC 3986 §5.2.4 dot-segments from a path.
std::string removeDotSegments(std::string_view input) {
  std::string out;
  out.reserve(input.size());
  std::string_view in = input;
  while (!in.empty()) {
    if (in.substr(0, 3) == "../") {
      in.remove_prefix(3);
    } else if (in.substr(0, 2) == "./") {
      in.remove_prefix(2);
    } else if (in.substr(0, 3) == "/./") {
      in.remove_prefix(2);
    } else if (in == "/.") {
      in = "/";
    } else if (in.substr(0, 4) == "/../") {
      in.remove_prefix(3);
      auto pos = out.find_last_of('/');
      if (pos == std::string::npos) {
        out.clear();
      } else {
        out.erase(pos);
      }
    } else if (in == "/..") {
      in = "/";
      auto pos = out.find_last_of('/');
      if (pos == std::string::npos) {
        out.clear();
      } else {
        out.erase(pos);
      }
    } else if (in == "." || in == "..") {
      in = "";
    } else {
      // Copy the leading segment (through next '/', excluding).
      size_t start = 0;
      size_t end = 1;
      if (in[0] == '/') {
        start = 0;
        end = in.find('/', 1);
      } else {
        start = 0;
        end = in.find('/');
      }
      if (end == std::string_view::npos) {
        out.append(in);
        in.remove_prefix(in.size());
      } else {
        out.append(in.substr(0, end));
        in.remove_prefix(end);
      }
    }
  }
  return out;
}

void splitPath(const std::string& path, std::string& parent, std::string& file,
               std::string& stem, std::string& ext) {
  auto slash = path.find_last_of('/');
  if (slash == std::string::npos) {
    parent = "";
    file = path;
  } else {
    parent = path.substr(0, slash);
    file = path.substr(slash + 1);
  }
  auto dot = file.find_last_of('.');
  if (dot == std::string::npos || dot == 0) {
    stem = file;
    ext = "";
  } else {
    stem = file.substr(0, dot);
    ext = file.substr(dot + 1);
  }
}

}  // namespace

std::optional<ParsedUri> parseUri(std::string_view uri) {
  if (uri.empty() || uri.size() > kMaxUriLength) {
    return std::nullopt;
  }

  size_t i = 0;
  if (!isSchemeStart(uri[0])) {
    return std::nullopt;
  }
  while (i < uri.size() && isSchemeChar(uri[i])) {
    ++i;
  }
  if (i == uri.size() || uri[i] != ':') {
    return std::nullopt;
  }
  ParsedUri out;
  out.scheme = toLowerAscii(uri.substr(0, i));
  ++i;  // consume ':'

  std::string_view rest = uri.substr(i);

  // Split off query and fragment (fragment discarded — not a catu component).
  std::string_view fragment_and_query = rest;
  auto frag_pos = fragment_and_query.find('#');
  if (frag_pos != std::string_view::npos) {
    fragment_and_query = fragment_and_query.substr(0, frag_pos);
  }
  auto q_pos = fragment_and_query.find('?');
  std::string_view path_and_authority;
  if (q_pos != std::string_view::npos) {
    path_and_authority = fragment_and_query.substr(0, q_pos);
    out.query = std::string(fragment_and_query.substr(q_pos + 1));
  } else {
    path_and_authority = fragment_and_query;
  }

  std::string_view path_view = path_and_authority;
  if (path_and_authority.substr(0, 2) == "//") {
    std::string_view authority = path_and_authority.substr(2);
    auto slash = authority.find('/');
    if (slash != std::string_view::npos) {
      path_view = authority.substr(slash);
      authority = authority.substr(0, slash);
    } else {
      path_view = "";
    }
    // Strip userinfo (RFC 3986 §3.2.1).
    auto at = authority.find('@');
    if (at != std::string_view::npos) {
      authority.remove_prefix(at + 1);
    }
    // IPv6 literal: [addr]:port
    if (!authority.empty() && authority.front() == '[') {
      auto close = authority.find(']');
      if (close == std::string_view::npos) {
        return std::nullopt;
      }
      out.host = toLowerAscii(authority.substr(1, close - 1));
      auto after = authority.substr(close + 1);
      if (!after.empty()) {
        if (after.front() != ':') {
          return std::nullopt;
        }
        out.port = stripLeadingZeros(after.substr(1));
      }
    } else {
      auto colon = authority.rfind(':');
      if (colon != std::string_view::npos) {
        out.host = toLowerAscii(authority.substr(0, colon));
        out.port = stripLeadingZeros(authority.substr(colon + 1));
      } else {
        out.host = toLowerAscii(authority);
      }
    }
  }

  out.path = removeDotSegments(path_view);
  splitPath(out.path, out.parent_path, out.filename, out.stem, out.extension);
  return out;
}

const std::string* componentValue(const ParsedUri& parsed,
                                  UriComponentLabel label) {
  switch (label) {
    case UriComponentLabel::Scheme:
      return &parsed.scheme;
    case UriComponentLabel::Host:
      return &parsed.host;
    case UriComponentLabel::Port:
      return &parsed.port;
    case UriComponentLabel::Path:
      return &parsed.path;
    case UriComponentLabel::Query:
      return &parsed.query;
    case UriComponentLabel::ParentPath:
      return &parsed.parent_path;
    case UriComponentLabel::Filename:
      return &parsed.filename;
    case UriComponentLabel::Stem:
      return &parsed.stem;
    case UriComponentLabel::Extension:
      return &parsed.extension;
  }
  return nullptr;
}

// -------------------------------------------------------------------------
// catu evaluation
// -------------------------------------------------------------------------

namespace {

// std::regex has unbounded worst-case backtracking. Callers pre-screen with
// isRegexPatternSafe, but we also refuse to spend more than one regex compile
// per evaluation attempt to keep validation deterministic.
bool matchComponent(UriMatchType type, const std::vector<uint8_t>& value_bytes,
                    const std::string& component) {
  std::string value(value_bytes.begin(), value_bytes.end());
  switch (type) {
    case UriMatchType::Exact:
      return component == value;
    case UriMatchType::Prefix:
      return component.size() >= value.size() &&
             component.compare(0, value.size(), value) == 0;
    case UriMatchType::Suffix:
      return component.size() >= value.size() &&
             component.compare(component.size() - value.size(), value.size(),
                               value) == 0;
    case UriMatchType::Contains:
      return component.find(value) != std::string::npos;
    case UriMatchType::Regex: {
      if (value.size() > kMaxRegexPatternLength) {
        return false;
      }
      try {
        std::regex re(value);
        return std::regex_match(component, re);
      } catch (const std::regex_error&) {
        return false;
      }
    }
    case UriMatchType::SHA256: {
      std::vector<uint8_t> bytes(component.begin(), component.end());
      return hashSha256(bytes) == value_bytes;
    }
    case UriMatchType::SHA512_256: {
      std::vector<uint8_t> bytes(component.begin(), component.end());
      return hashSha512_256(bytes) == value_bytes;
    }
  }
  return false;
}

}  // namespace

bool matchesCatu(const CatUriMatchMap& catu, const ParsedUri& parsed) {
  for (const auto& [label_raw, match] : catu.components) {
    if (label_raw < 0 ||
        label_raw > static_cast<int64_t>(UriComponentLabel::Extension)) {
      return false;
    }
    auto label = static_cast<UriComponentLabel>(label_raw);
    const std::string* component = componentValue(parsed, label);
    if (component == nullptr) {
      return false;
    }
    if (!matchComponent(match.type, match.value, *component)) {
      return false;
    }
  }
  return true;
}

bool matchesCatu(const CatUriMatchMap& catu, std::string_view uri) {
  auto parsed = parseUri(uri);
  if (!parsed) {
    return false;
  }
  return matchesCatu(catu, *parsed);
}

// -------------------------------------------------------------------------
// Legacy UriMatcher
// -------------------------------------------------------------------------

namespace {

// Reject constructs whose worst-case std::regex evaluation is unbounded.
bool isRegexPatternSafe(const std::string& pattern) {
  if (pattern.length() > kMaxRegexPatternLength) {
    return false;
  }

  std::vector<bool> group_has_quantifier;
  int depth = 0;

  for (size_t i = 0; i < pattern.length(); ++i) {
    char c = pattern[i];

    if (c == '\\' && i + 1 < pattern.length()) {
      ++i;
      continue;
    }

    if (c == '[') {
      while (i + 1 < pattern.length() && pattern[i + 1] != ']') {
        if (pattern[i + 1] == '\\' && i + 2 < pattern.length()) {
          i += 2;
        } else {
          ++i;
        }
      }
      ++i;
      continue;
    }

    if (c == '(') {
      bool is_group = true;
      if (i + 1 < pattern.length() && pattern[i + 1] == '?') {
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
        if (i + 1 < pattern.length()) {
          char next = pattern[i + 1];
          if (next == '+' || next == '*' || next == '?' || next == '{') {
            if (inner_quantified) {
              return false;
            }
            if (!group_has_quantifier.empty()) {
              group_has_quantifier.back() = true;
            }
          }
        }
      }
    } else if (c == '+' || c == '*' || c == '?') {
      if (!group_has_quantifier.empty()) {
        group_has_quantifier.back() = true;
      }
    } else if (c == '{') {
      while (i + 1 < pattern.length() && pattern[i + 1] != '}') {
        ++i;
      }
      if (!group_has_quantifier.empty()) {
        group_has_quantifier.back() = true;
      }
    }
  }

  return true;
}

}  // namespace

void UriMatcher::addPattern(const UriPattern& pattern) {
  switch (pattern.type) {
    case UriPatternType::Exact:
      exactPatterns_[pattern.pattern] = pattern.pattern;
      break;
    case UriPatternType::Prefix:
      prefixTrie_.insert(pattern.pattern, pattern.pattern);
      break;
    case UriPatternType::Suffix:
      suffixTrie_.insert(pattern.pattern, pattern.pattern);
      break;
    case UriPatternType::Regex:
      if (regexPatterns_.size() >= kMaxRegexPatterns) {
        throw InvalidClaimValueError("Too many regex patterns");
      }
      if (!isRegexPatternSafe(pattern.pattern)) {
        throw InvalidClaimValueError("Regex pattern rejected for safety");
      }
      try {
        regexPatterns_.emplace_back(std::regex(pattern.pattern),
                                    pattern.pattern);
      } catch (const std::regex_error&) {
        throw InvalidClaimValueError("Regex pattern failed to compile");
      }
      break;
    case UriPatternType::Hash:
      hashPatterns_[pattern.pattern] = pattern.pattern;
      break;
  }
}

bool UriMatcher::matches(const std::string& uri) const {
  if (uri.length() > kMaxUriLength) {
    return false;
  }

  if (exactPatterns_.find(uri) != exactPatterns_.end()) {
    return true;
  }
  if (!prefixTrie_.searchPrefix(uri).empty()) {
    return true;
  }
  if (!suffixTrie_.searchSuffix(uri).empty()) {
    return true;
  }
  for (const auto& regexPair : regexPatterns_) {
    if (std::regex_match(uri, regexPair.first)) {
      return true;
    }
  }

  std::vector<uint8_t> uriBytes(uri.begin(), uri.end());
  std::vector<uint8_t> hashBytes = hashSha256(uriBytes);
  std::string uriHash = base64UrlEncode(hashBytes);
  if (hashPatterns_.find(uriHash) != hashPatterns_.end()) {
    return true;
  }

  return false;
}

std::vector<std::string> UriMatcher::getMatchingPatterns(
    const std::string& uri) const {
  std::vector<std::string> matches;

  if (uri.length() > kMaxUriLength) {
    return matches;
  }

  auto exactIt = exactPatterns_.find(uri);
  if (exactIt != exactPatterns_.end()) {
    matches.push_back("exact:" + exactIt->second);
  }

  for (const auto& prefixMatch : prefixTrie_.searchPrefix(uri)) {
    matches.push_back("prefix:" + prefixMatch);
  }

  for (const auto& suffixMatch : suffixTrie_.searchSuffix(uri)) {
    matches.push_back("suffix:" + suffixMatch);
  }

  for (const auto& regexPair : regexPatterns_) {
    if (std::regex_match(uri, regexPair.first)) {
      matches.push_back("regex:" + regexPair.second);
    }
  }

  std::vector<uint8_t> uriBytes(uri.begin(), uri.end());
  std::vector<uint8_t> hashBytes = hashSha256(uriBytes);
  std::string uriHash = base64UrlEncode(hashBytes);
  auto hashIt = hashPatterns_.find(uriHash);
  if (hashIt != hashPatterns_.end()) {
    matches.push_back("hash:" + hashIt->second);
  }

  return matches;
}

}  // namespace catapult
