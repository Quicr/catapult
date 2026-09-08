/**
 * @file cat_moqt_claims.hpp
 * @brief MOQT-specific claim definitions and structures for CAT tokens
 *
 * This file implements the MOQT claims as defined in draft-ietf-moq-c4m-01.
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
#include "internal/secure_vector.hpp"

namespace catapult {

/**
 * @brief MOQT claim identifiers.
 *
 * draft-ietf-moq-c4m-01 lists these claims as TBD_MOQT / TBD_MOQT_REVAL and
 * defers final label assignment to IANA. Until IANA assigns numbers we use
 * the private-label range (RFC 8949 §3.4 permits values ≥ 65000 for
 * private use) so that a token minted against catapult cannot collide with
 * a future IANA-registered claim id at any lower label. Deployments that
 * negotiate a different pair MUST swap these constants together and MUST
 * NOT ship them alongside another implementation without checking the
 * label pair matches — the wire form is otherwise silently incompatible.
 */
constexpr int64_t CLAIM_MOQT = 65000;  ///< MOQT scope claim (private label
                                       ///< pending IANA assignment)
constexpr int64_t CLAIM_MOQT_REVAL =
    65001;  ///< MOQT revalidation claim (private label pending IANA
            ///< assignment)

/**
 * @brief MOQT action identifiers per draft-ietf-moq-c4m
 */
namespace moqt_actions {
constexpr int CLIENT_SETUP = 0;
constexpr int SERVER_SETUP = 1;
constexpr int PUBLISH_NAMESPACE = 2;
// Legacy names retained for source compatibility with pre-draft-04
// consumers. New code should use the spec names above.
[[deprecated("use moqt_actions::PUBLISH_NAMESPACE")]]
constexpr int ANNOUNCE = 2;
constexpr int SUBSCRIBE_NAMESPACE = 3;
constexpr int SUBSCRIBE = 4;
constexpr int REQUEST_UPDATE = 5;
[[deprecated("use moqt_actions::REQUEST_UPDATE")]]
constexpr int SUBSCRIBE_UPDATE = 5;
constexpr int PUBLISH = 6;
constexpr int FETCH = 7;
constexpr int TRACK_STATUS = 8;

constexpr bool is_valid_action(int action) noexcept {
  return action >= CLIENT_SETUP && action <= TRACK_STATUS;
}

constexpr std::string_view action_name(int action) noexcept {
  switch (action) {
    case CLIENT_SETUP:
      return "CLIENT_SETUP";
    case SERVER_SETUP:
      return "SERVER_SETUP";
    case PUBLISH_NAMESPACE:
      return "PUBLISH_NAMESPACE";
    case SUBSCRIBE_NAMESPACE:
      return "SUBSCRIBE_NAMESPACE";
    case SUBSCRIBE:
      return "SUBSCRIBE";
    case REQUEST_UPDATE:
      return "REQUEST_UPDATE";
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
 * @brief Binary match types according to CTA-5007-B §4.6.1.
 *
 * `CONTAINS` (type 3) is intentionally in-model but out-of-profile for
 * CAT-4-MOQT: the draft's bin-match CDDL admits only exact/prefix/suffix,
 * so accepting an incoming type-3 tuple would silently broaden a token's
 * authorization scope. Both the encoder (src/cwt.cpp:serializeBinaryMatch)
 * and the decoder (src/cwt.cpp: `parse_bin_match`) reject type 3. The
 * factory `MoqtBinaryMatch::contains()` is kept so in-memory policy code
 * can express a substring test locally, and so the wire-form rejection
 * tests can construct a value to encode-and-fail against — but the value
 * MUST NOT reach any external interface.
 */
enum class BinaryMatchType : int {
  EXACT = 0,    ///< Exact match (CAT-4-MOQT profile)
  PREFIX = 1,   ///< Prefix match (CAT-4-MOQT profile)
  SUFFIX = 2,   ///< Suffix match (CAT-4-MOQT profile)
  CONTAINS = 3  ///< In-memory only; not part of CAT-4-MOQT wire profile
};

/**
 * @brief Binary match object for namespace and track matching
 *
 * ## Wildcard vs. "exact empty"
 *
 * A `MoqtBinaryMatch` distinguishes two shapes that share the same wire
 * shorthand and used to be conflated:
 *
 *   - `any()` — the wildcard: authorizes every resource on this dimension.
 *     Internally carried by the `is_wildcard_` flag, NOT by an empty
 *     `pattern` vector. On the wire this is encoded by omitting the match
 *     from the containing scope entirely.
 *   - `exact("")` — the exact zero-length match: authorizes only when the
 *     resource on this dimension is itself empty. Encoded as a bare
 *     empty bytestring (`0x40`).
 *
 * Prior versions returned `is_empty() == true` for both shapes, which
 * silently upgraded an `exact("")` to a wildcard. The factories now reject
 * empty patterns for `prefix()`/`suffix()`/`contains()` (an empty prefix
 * or suffix is a policy bug — it degenerates to "match everything" —
 * so the only permitted expression of that intent is `any()`), and
 * `exact("")` produces a match that trips only on empty inputs.
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
    if (pattern.empty()) {
      throw InvalidClaimValueError(
          "MoqtBinaryMatch::prefix('') is ambiguous: an empty prefix "
          "matches every input. Use any() to express 'no restriction'.");
    }
    return MoqtBinaryMatch{BinaryMatchType::PREFIX, pattern};
  }

  static MoqtBinaryMatch suffix(std::string_view pattern) {
    if (pattern.empty()) {
      throw InvalidClaimValueError(
          "MoqtBinaryMatch::suffix('') is ambiguous: an empty suffix "
          "matches every input. Use any() to express 'no restriction'.");
    }
    return MoqtBinaryMatch{BinaryMatchType::SUFFIX, pattern};
  }

  static MoqtBinaryMatch contains(std::string_view pattern) {
    if (pattern.empty()) {
      throw InvalidClaimValueError(
          "MoqtBinaryMatch::contains('') is ambiguous: an empty substring "
          "matches every input. Use any() to express 'no restriction'.");
    }
    return MoqtBinaryMatch{BinaryMatchType::CONTAINS, pattern};
  }

 private:
  /**
   * @brief Default constructor for the wildcard match (matches all)
   *
   * The wildcard is the ONLY match shape that returns `is_wildcard() ==
   * true` and short-circuits `matches()` to accept everything. Every
   * other factory produces a match with `is_wildcard_ == false`, even
   * when the resulting pattern is empty (i.e. `exact("")`).
   */
  MoqtBinaryMatch()
      : match_type(BinaryMatchType::EXACT), pattern{}, is_wildcard_(true) {}

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
   * @brief True iff this match is the wildcard (produced by `any()`).
   *
   * `is_empty()` is retained as a synonym for source compatibility but
   * now shares the same "wildcard-only" semantics — a match with an
   * empty pattern but non-wildcard type (e.g. `exact("")`) returns
   * `false` here.
   */
  [[nodiscard]] bool is_wildcard() const noexcept { return is_wildcard_; }

  /**
   * @brief Alias for `is_wildcard()`. Retained for source compatibility.
   */
  [[nodiscard]] bool is_empty() const noexcept { return is_wildcard_; }

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

 private:
  // True only for matches produced by `any()`. Not part of the wire form:
  // encoders omit a wildcard from the emitted scope entirely rather than
  // shipping any bytestring for it, and decoders reconstruct a wildcard by
  // inserting `any()` in the compound-match list. Distinguishes the
  // wildcard shape from `exact("")` (which authorises only empty inputs).
  bool is_wildcard_ = false;
};  // class MoqtBinaryMatch

/**
 * @brief Compound match combining multiple binary matches with AND semantics
 *
 * All conditions must match for the compound match to succeed.
 * This allows expressing constraints like "starts with /live AND ends with
 * .mp4" on a single dimension.
 */
class MoqtCompoundMatch {
 public:
  static MoqtCompoundMatch any() { return MoqtCompoundMatch{}; }

  static MoqtCompoundMatch single(MoqtBinaryMatch match) {
    MoqtCompoundMatch result;
    if (!match.is_empty()) {
      result.conditions_.push_back(std::move(match));
    }
    return result;
  }

  static MoqtCompoundMatch all(std::vector<MoqtBinaryMatch> conditions) {
    MoqtCompoundMatch result;
    for (auto& c : conditions) {
      if (!c.is_empty()) {
        result.conditions_.push_back(std::move(c));
      }
    }
    return result;
  }

  static MoqtCompoundMatch all(
      std::initializer_list<MoqtBinaryMatch> conditions) {
    return all(std::vector<MoqtBinaryMatch>(conditions));
  }

  [[nodiscard]] bool matches(std::span<const uint8_t> data) const noexcept {
    return std::ranges::all_of(conditions_,
                               [&](const auto& m) { return m.matches(data); });
  }

  [[nodiscard]] bool matches(std::string_view str) const noexcept {
    return std::ranges::all_of(conditions_,
                               [&](const auto& m) { return m.matches(str); });
  }

  [[nodiscard]] bool is_empty() const noexcept { return conditions_.empty(); }

  [[nodiscard]] size_t size() const noexcept { return conditions_.size(); }

  [[nodiscard]] const std::vector<MoqtBinaryMatch>& conditions()
      const noexcept {
    return conditions_;
  }

 private:
  MoqtCompoundMatch() = default;
  std::vector<MoqtBinaryMatch> conditions_;
};

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
   * @brief Constructor with actions and compound match patterns
   */
  template <std::ranges::range ActionRange>
    requires MoqtActionType<std::ranges::range_value_t<ActionRange>>
  MoqtActionScope(const ActionRange& action_list, MoqtCompoundMatch ns_match,
                  MoqtCompoundMatch tr_match)
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
  std::vector<int> actions;           ///< Allowed MOQT actions
  MoqtCompoundMatch namespace_match;  ///< Namespace match (AND of conditions)
  MoqtCompoundMatch track_match;      ///< Track match (AND of conditions)

  /**
   * @brief Factory method for creating validated scope with compound matches
   */
  template <std::ranges::range ActionRange>
    requires std::ranges::range<ActionRange> &&
             MoqtActionType<std::ranges::range_value_t<ActionRange>>
  static MoqtActionScope create(const ActionRange& action_list,
                                MoqtCompoundMatch ns_match,
                                MoqtCompoundMatch tr_match) {
    return MoqtActionScope(action_list, std::move(ns_match),
                           std::move(tr_match));
  }

  /**
   * @brief Factory method with single binary matches (convenience)
   */
  template <std::ranges::range ActionRange>
    requires std::ranges::range<ActionRange> &&
             MoqtActionType<std::ranges::range_value_t<ActionRange>>
  static MoqtActionScope create(const ActionRange& action_list,
                                MoqtBinaryMatch ns_match,
                                MoqtBinaryMatch tr_match) {
    return MoqtActionScope(action_list,
                           MoqtCompoundMatch::single(std::move(ns_match)),
                           MoqtCompoundMatch::single(std::move(tr_match)));
  }

  /**
   * @brief Check if this scope authorizes the given action and resource
   */
  template <MoqtActionType ActionT>
  [[nodiscard]] bool authorizes(ActionT action, std::string_view namespace_name,
                                std::string_view track_name) const noexcept {
    if (!std::ranges::any_of(actions,
                             [action](int a) { return a == action; })) {
      return false;
    }

    if (!namespace_match.is_empty() &&
        !namespace_match.matches(namespace_name)) {
      return false;
    }

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
// Publisher role: can publish content and claim namespaces
constexpr auto publisher =
    CompileTimeActionSet<moqt_actions::PUBLISH,
                         moqt_actions::PUBLISH_NAMESPACE>{};

// Subscriber role: can subscribe to content and fetch data
constexpr auto subscriber =
    CompileTimeActionSet<moqt_actions::SUBSCRIBE, moqt_actions::FETCH>{};

// Full access role: all available actions
constexpr auto full_access = CompileTimeActionSet<
    moqt_actions::CLIENT_SETUP, moqt_actions::SERVER_SETUP,
    moqt_actions::PUBLISH_NAMESPACE, moqt_actions::SUBSCRIBE_NAMESPACE,
    moqt_actions::SUBSCRIBE, moqt_actions::REQUEST_UPDATE,
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
   * @brief Add a scope with compound matches
   */
  template <std::ranges::range ActionRange>
    requires MoqtActionType<std::ranges::range_value_t<ActionRange>>
  void addScope(const ActionRange& actions, MoqtCompoundMatch namespace_match,
                MoqtCompoundMatch track_match) {
    scopes.emplace_back(MoqtActionScope::create(
        actions, std::move(namespace_match), std::move(track_match)));
  }

  /**
   * @brief Add a scope with single binary matches (convenience)
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
   * @brief Compile-time scope addition with compound matches
   */
  template <int... Actions>
  void addCompileTimeScope(MoqtCompoundMatch namespace_match,
                           MoqtCompoundMatch track_match) {
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