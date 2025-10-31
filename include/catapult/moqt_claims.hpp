/**
 * @file cat_moqt_claims.hpp
 * @brief MOQT-specific claim definitions and structures for CAT tokens
 *
 * This file implements the MOQT claims as defined in draft-law-moq-cat4moqt.
 */

#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <concepts>
#include <cstdint>
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "error.hpp"
#include "secure_vector.hpp"

namespace catapult {

/**
 * @brief MOQT claim identifiers according to the specification
 * Using high numbers (65000+) to avoid conflicts with existing CBOR tags
 */
constexpr int64_t CLAIM_MOQT = 65000;  ///< MOQT claim (was TBD_MOQT in spec)
constexpr int64_t CLAIM_MOQT_REVAL =
    65001;  ///< MOQT revalidation claim (was TBD_MOQT_REVAL in spec)

/**
 * @brief MOQT action identifiers according to Section 4 of the specification
 */
namespace moqt_actions {
constexpr int CLIENT_SETUP = 0;         ///< CLIENT_SETUP action
constexpr int SERVER_SETUP = 1;         ///< SERVER_SETUP action
constexpr int ANNOUNCE = 2;             ///< ANNOUNCE action
constexpr int SUBSCRIBE_NAMESPACE = 3;  ///< SUBSCRIBE_NAMESPACE action
constexpr int SUBSCRIBE = 4;            ///< SUBSCRIBE action
constexpr int SUBSCRIBE_UPDATE = 5;     ///< SUBSCRIBE_UPDATE action
constexpr int PUBLISH = 6;              ///< PUBLISH action
constexpr int FETCH = 7;                ///< FETCH action
constexpr int TRACK_STATUS = 8;         ///< TRACK_STATUS action

constexpr bool is_valid_action(int action) noexcept {
  return action >= CLIENT_SETUP && action <= TRACK_STATUS;
}

// Get action name for debugging
constexpr std::string_view action_name(int action) noexcept {
  switch (action) {
    case CLIENT_SETUP:
      return "CLIENT_SETUP";
    case SERVER_SETUP:
      return "SERVER_SETUP";
    case ANNOUNCE:
      return "ANNOUNCE";
    case SUBSCRIBE_NAMESPACE:
      return "SUBSCRIBE_NAMESPACE";
    case SUBSCRIBE:
      return "SUBSCRIBE";
    case SUBSCRIBE_UPDATE:
      return "SUBSCRIBE_UPDATE";
    case PUBLISH:
      return "PUBLISH";
    case FETCH:
      return "FETCH";
    case TRACK_STATUS:
      return "TRACK_STATUS";
    default:
      return "UNKNOWN";
  }
}
}  // namespace moqt_actions

/**
 * @brief MOQT action type concept for compile-time validation
 */
template <typename T>
concept MoqtActionType = std::integral<T> && requires(T action) {
  {
    moqt_actions::is_valid_action(static_cast<int>(action))
  } -> std::convertible_to<bool>;
};

/**
 * @brief Binary match types according to CTA-5007-B 4.6.1
 */
enum class BinaryMatchType : int {
  EXACT = 0,    ///< Exact match
  PREFIX = 1,   ///< Prefix match
  SUFFIX = 2,   ///< Suffix match
  CONTAINS = 3  ///< Contains match
};

/**
 * @brief Binary match object for namespace and track matching
 */
class MoqtBinaryMatch {
 public:
  BinaryMatchType match_type;
  std::vector<uint8_t> pattern;

  /**
   * @brief Factory methods for different match types
   */
  static MoqtBinaryMatch any() { return MoqtBinaryMatch{}; }

  static MoqtBinaryMatch exact(std::string_view pattern) {
    return MoqtBinaryMatch{BinaryMatchType::EXACT, pattern};
  }

  static MoqtBinaryMatch prefix(std::string_view pattern) {
    return MoqtBinaryMatch{BinaryMatchType::PREFIX, pattern};
  }

  static MoqtBinaryMatch suffix(std::string_view pattern) {
    return MoqtBinaryMatch{BinaryMatchType::SUFFIX, pattern};
  }

  static MoqtBinaryMatch contains(std::string_view pattern) {
    return MoqtBinaryMatch{BinaryMatchType::CONTAINS, pattern};
  }

 private:
  /**
   * @brief Default constructor for empty match (matches all)
   */
  MoqtBinaryMatch() : match_type(BinaryMatchType::EXACT), pattern{} {}

  /**
   * @brief Constructor with match type and pattern
   */
  MoqtBinaryMatch(BinaryMatchType type, std::span<const uint8_t> data)
      : match_type(type), pattern(data.begin(), data.end()) {}

  /**
   * @brief Constructor from string view (converts to binary)
   */
  MoqtBinaryMatch(BinaryMatchType type, std::string_view str)
      : match_type(type) {
    pattern.reserve(str.size());
    std::ranges::transform(str, std::back_inserter(pattern),
                           [](char c) { return static_cast<uint8_t>(c); });
  }

 public:
  /**
   * @brief Test if this match applies to the given binary data
   */
  [[nodiscard]] bool matches(std::span<const uint8_t> data) const noexcept;

  /**
   * @brief Test if this match applies to the given string
   */
  [[nodiscard]] bool matches(std::string_view str) const noexcept {
    std::vector<uint8_t> binary_str;
    binary_str.reserve(str.size());
    std::ranges::transform(str, std::back_inserter(binary_str),
                           [](char c) { return static_cast<uint8_t>(c); });
    return matches(binary_str);
  }

  /**
   * @brief Check if this is an empty match (matches everything)
   */
  [[nodiscard]] bool is_empty() const noexcept { return pattern.empty(); }

  /**
   * @brief Get pattern as string view (for debugging)
   */
  [[nodiscard]] std::string pattern_as_string() const {
    std::string result;
    result.reserve(pattern.size());
    std::ranges::transform(pattern, std::back_inserter(result),
                           [](uint8_t b) { return static_cast<char>(b); });
    return result;
  }
};  // class MoqtBinaryMatch

/**
 * @brief MOQT action scope representing one scope entry in the moqt claim
 */
class MoqtActionScope {
  friend class MoqtClaims;

 private:
  /**
   * @brief Default constructor
   */
  MoqtActionScope() = delete;

  /**
   * @brief Constructor with actions and match patterns
   */
  template <std::ranges::range ActionRange>
    requires MoqtActionType<std::ranges::range_value_t<ActionRange>>
  MoqtActionScope(const ActionRange& action_list, MoqtBinaryMatch ns_match,
                  MoqtBinaryMatch tr_match)
      : namespace_match(std::move(ns_match)), track_match(std::move(tr_match)) {
    auto action_copy = action_list;
    if constexpr (std::ranges::sized_range<ActionRange>) {
      actions.reserve(std::ranges::size(action_copy));
    }
    for (const auto& action : action_copy) {
      if (!moqt_actions::is_valid_action(action)) {
        throw InvalidClaimValueError("Invalid MOQT action: " +
                                     std::to_string(action));
      }
      actions.push_back(action);
    }
  }

 public:
  std::vector<int> actions;         ///< Allowed MOQT actions
  MoqtBinaryMatch namespace_match;  ///< Namespace match pattern
  MoqtBinaryMatch track_match;      ///< Track match pattern

  /**
   * @brief Factory method for creating validated scope
   */
  template <std::ranges::range ActionRange>
    requires std::ranges::range<ActionRange> &&
             MoqtActionType<std::ranges::range_value_t<ActionRange>>
  static MoqtActionScope create(const ActionRange& action_list,
                                MoqtBinaryMatch ns_match,
                                MoqtBinaryMatch tr_match) {
    return MoqtActionScope(action_list, std::move(ns_match),
                           std::move(tr_match));
  }

  /**
   * @brief Check if this scope authorizes the given action and resource
   */
  template <MoqtActionType ActionT>
  [[nodiscard]] bool authorizes(ActionT action, std::string_view namespace_name,
                                std::string_view track_name) const noexcept {
    // Check if action is in the allowed list
    if (!std::ranges::any_of(actions,
                             [action](int a) { return a == action; })) {
      return false;
    }

    // Check namespace match
    if (!namespace_match.is_empty() &&
        !namespace_match.matches(namespace_name)) {
      return false;
    }

    // Check track match
    if (!track_match.is_empty() && !track_match.matches(track_name)) {
      return false;
    }

    return true;
  }

  /**
   * @brief Get the number of actions in this scope
   */
  [[nodiscard]] size_t action_count() const noexcept { return actions.size(); }

  /**
   * @brief Check if this scope contains the given action
   */
  template <MoqtActionType ActionT>
  [[nodiscard]] bool contains_action(ActionT action) const noexcept {
    return std::ranges::any_of(actions,
                               [action](int a) { return a == action; });
  }
};

/**
 * @brief Compile-time action set for high-performance authorization
 */
template <int... Actions>
class CompileTimeActionSet {
  static constexpr std::array actions{Actions...};

  static_assert((moqt_actions::is_valid_action(Actions) && ...),
                "All actions must be valid MOQT actions");

 public:
  /**
   * @brief Check if the set contains the given action at compile time
   */
  template <int Action>
  static consteval bool contains() noexcept {
    return ((Action == Actions) || ...);
  }

  /**
   * @brief Check if the set contains the given action at runtime
   */
  [[nodiscard]] static bool contains(int action) noexcept {
    return ((action == Actions) || ...);
  }

  /**
   * @brief Get the size of the action set
   */
  static constexpr size_t size() noexcept { return sizeof...(Actions); }

  /**
   * @brief Get the actions as a span
   */
  [[nodiscard]] static constexpr std::span<const int> get_actions() noexcept {
    return std::span<const int>{actions.data(), actions.size()};
  }
};

/**
 * @brief Predefined compile-time action sets for common roles
 */
namespace role_actions {
// Publisher role: can publish content and announce namespaces
constexpr auto publisher =
    CompileTimeActionSet<moqt_actions::PUBLISH, moqt_actions::ANNOUNCE>{};

// Subscriber role: can subscribe to content and fetch data
constexpr auto subscriber =
    CompileTimeActionSet<moqt_actions::SUBSCRIBE, moqt_actions::FETCH>{};

// Full access role: all available actions
constexpr auto full_access = CompileTimeActionSet<
    moqt_actions::CLIENT_SETUP, moqt_actions::SERVER_SETUP,
    moqt_actions::ANNOUNCE, moqt_actions::SUBSCRIBE_NAMESPACE,
    moqt_actions::SUBSCRIBE, moqt_actions::SUBSCRIBE_UPDATE,
    moqt_actions::PUBLISH, moqt_actions::FETCH, moqt_actions::TRACK_STATUS>{};

// Read-only role: can only subscribe and fetch
constexpr auto read_only =
    CompileTimeActionSet<moqt_actions::SUBSCRIBE, moqt_actions::FETCH,
                         moqt_actions::SUBSCRIBE_NAMESPACE>{};
}  // namespace role_actions

/**
 * @brief Template utility functions for compile-time role validation
 */
template <typename ActionSet>
constexpr bool validates_role(const ActionSet& role, int action) noexcept {
  return role.contains(action);
}

template <int... AllowedActions>
constexpr bool is_action_allowed(int action) noexcept {
  constexpr auto action_set = CompileTimeActionSet<AllowedActions...>{};
  return action_set.contains(action);
}

/**
 * @brief Main MOQT claims structure
 */
class MoqtClaims {
 private:
  std::vector<MoqtActionScope> scopes;
  std::optional<std::chrono::seconds> revalidation_interval;

 public:
  /**
   * @brief Default constructor
   */
  MoqtClaims() = default;

  /**
   * @brief Constructor with initial capacity
   */
  explicit MoqtClaims(size_t initial_capacity) {
    scopes.reserve(initial_capacity);
  }

  /**
   * @brief Factory method for creating claims with capacity
   */
  static MoqtClaims create(size_t initial_capacity = 10) {
    return MoqtClaims{initial_capacity};
  }

  /**
   * @brief Add a scope to the claims
   */
  template <std::ranges::range ActionRange>
    requires MoqtActionType<std::ranges::range_value_t<ActionRange>>
  void addScope(const ActionRange& actions, MoqtBinaryMatch namespace_match,
                MoqtBinaryMatch track_match) {
    scopes.emplace_back(MoqtActionScope::create(
        actions, std::move(namespace_match), std::move(track_match)));
  }

  /**
   * @brief Add a pre-constructed scope
   */
  void addScope(MoqtActionScope scope) {
    scopes.emplace_back(std::move(scope));
  }

  /**
   * @brief Compile-time scope addition with action validation
   */
  template <int... Actions>
  void addCompileTimeScope(MoqtBinaryMatch namespace_match,
                           MoqtBinaryMatch track_match) {
    static_assert((moqt_actions::is_valid_action(Actions) && ...),
                  "All actions must be valid MOQT actions");

    constexpr std::array action_array{Actions...};
    scopes.emplace_back(MoqtActionScope::create(
        action_array, std::move(namespace_match), std::move(track_match)));
  }

  /**
   * @brief Check if the given action is authorized for the resource
   */
  template <MoqtActionType ActionT>
  [[nodiscard]] bool isAuthorized(ActionT action,
                                  std::string_view namespace_name,
                                  std::string_view track_name) const noexcept {
    return std::any_of(scopes.begin(), scopes.end(), [=](const auto& scope) {
      return scope.authorizes(action, namespace_name, track_name);
    });
  }

  /**
   * @brief Get the number of scopes
   */
  [[nodiscard]] size_t getScopeCount() const noexcept { return scopes.size(); }

  /**
   * @brief Get read-only access to scopes
   */
  [[nodiscard]] const std::vector<MoqtActionScope>& getScopes() const noexcept {
    return scopes;
  }

  /**
   * @brief Set revalidation interval in seconds
   */
  void setRevalidationInterval(std::chrono::seconds interval) {
    if (interval.count() <= 0) {
      throw InvalidClaimValueError("Revalidation interval must be positive");
    }
    revalidation_interval = interval;
  }

  /**
   * @brief Get revalidation interval
   */
  [[nodiscard]] std::optional<std::chrono::seconds> getRevalidationInterval()
      const noexcept {
    return revalidation_interval;
  }

  /**
   * @brief Get revalidation interval in seconds (for compatibility)
   */
  [[nodiscard]] std::optional<int64_t> getRevalidationIntervalSeconds()
      const noexcept {
    if (revalidation_interval.has_value()) {
      return revalidation_interval->count();
    }
    return std::nullopt;
  }

  /**
   * @brief Clear all scopes
   */
  void clear() noexcept { scopes.clear(); }

  /**
   * @brief Check if claims are empty
   */
  [[nodiscard]] bool empty() const noexcept { return scopes.empty(); }

  /**
   * @brief Get total number of actions across all scopes
   */
  [[nodiscard]] size_t getTotalActionCount() const noexcept {
    size_t total = 0;
    for (const auto& scope : scopes) {
      total += scope.action_count();
    }
    return total;
  }
};

template <size_t N>
consteval std::array<uint8_t, N - 1> string_to_binary(const char (&str)[N]) {
  std::array<uint8_t, N - 1> result{};  // -1 to exclude null terminator
  for (size_t i = 0; i < N - 1; ++i) {
    result[i] = static_cast<uint8_t>(str[i]);
  }
  return result;
}

// Forward declaration
struct EnhancedDpopClaims;

/**
 * @brief Extended CAT claims structure including MOQT claims
 */
struct ExtendedCatClaims {
  std::optional<MoqtClaims> moqt;  ///< MOQT claims
  ExtendedCatClaims() = default;
  ExtendedCatClaims(const ExtendedCatClaims& other) = default;
  ExtendedCatClaims(ExtendedCatClaims&&) noexcept = default;
  ExtendedCatClaims& operator=(const ExtendedCatClaims& other) = default;
  ExtendedCatClaims& operator=(ExtendedCatClaims&&) noexcept = default;

  /**
   * @brief Set MOQT claims
   */
  void setMoqtClaims(MoqtClaims claims) { moqt = std::move(claims); }

  /**
   * @brief Get read-only access to MOQT claims
   */
  [[nodiscard]] const MoqtClaims* getMoqtClaimsReadOnly() const noexcept {
    return moqt.has_value() ? &moqt.value() : nullptr;
  }

  /**
   * @brief Get mutable access to MOQT claims (creates if doesn't exist)
   */
  [[nodiscard]] MoqtClaims& getMoqtClaims() {
    if (!moqt.has_value()) {
      moqt = MoqtClaims{};
    }
    return moqt.value();
  }

  /**
   * @brief Check if MOQT claims exist
   */
  [[nodiscard]] bool hasMoqtClaims() const noexcept { return moqt.has_value(); }
};

}  // namespace catapult