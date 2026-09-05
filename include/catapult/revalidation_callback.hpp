/**
 * @file revalidation_callback.hpp
 * @brief Pluggable observer for token revalidation events.
 *
 * CAT-4-MOQT `moqt-reval` requires that the resource server (relay) reject
 * a token once (`iat` + `moqt-reval`) is in the past. The library enforces
 * this in `CatTokenValidator::validate` by throwing
 * `TokenRevalidationRequiredError`.
 *
 * That alone is not enough for deployments that need to:
 *  - proactively refresh tokens before they hit the reval deadline
 *  - warn (metric / log) when a large fraction of admissions are
 *    landing near their reval interval
 *  - trigger a client-side re-issue flow rather than force the user to
 *    catch the exception in every call site
 *
 * `RevalidationCallback` is the seam. `CatTokenValidator` invokes it
 * during the reval check with the outcome (`Approaching` or `Expired`)
 * and the remaining budget. The default installed callback is a no-op
 * (`NoopRevalidationCallback`); relays that need observability plug in
 * their own implementation.
 *
 * ## Contract
 *
 * The callback runs on the validation hot path. Implementations MUST:
 *  - return promptly (target: bounded microseconds)
 *  - not allocate on the fast path if possible
 *  - be safe to call concurrently
 *  - not throw across the validator boundary — the library treats
 *    any escaped exception as a fatal internal-consistency failure
 *
 * Implementations that need to record metrics or trigger asynchronous
 * work should do so via lock-free counters or a bounded queue; blocking
 * I/O in the callback will stall admission for every caller.
 *
 * ## Warning threshold
 *
 * The validator computes a `TimeToReval` — the number of seconds
 * remaining until the reval deadline (possibly negative when we are
 * already past it). Callbacks decide their own warning window: e.g. a
 * relay might treat anything under 30 s as "approaching" and pre-fetch.
 * The library does not impose a threshold — that would tie deployment
 * policy to library semantics.
 */

#pragma once

#include <chrono>
#include <string_view>

namespace catapult {

/**
 * @brief Outcome the validator hands to the revalidation callback.
 */
enum class RevalidationStatus {
  /// The token is still within its reval interval; `time_to_reval` is
  /// positive (or zero). Emitted on every reval-check success so
  /// callbacks can observe the tail of the distribution and pre-fetch
  /// before the deadline hits.
  Fresh,

  /// The token has passed its reval deadline. Emitted just before
  /// `CatTokenValidator::validate` throws `TokenRevalidationRequiredError`
  /// (or before `tryValidate` returns the corresponding code).
  Expired,
};

/**
 * @brief Callback fired during moqt-reval enforcement.
 *
 * Not to be confused with `TokenRevalidationRequiredError`: that
 * exception is the *authorization* signal (reject the request); this
 * hook is the *observability* signal (record what happened).
 *
 * Callbacks MUST NOT throw. The validator does not catch exceptions
 * from this call — an escaped exception aborts the current validation
 * and unwinds through the caller.
 */
class RevalidationCallback {
 public:
  virtual ~RevalidationCallback() = default;

  /**
   * @brief Report a reval-check outcome.
   *
   * @param status Fresh or Expired.
   * @param token_id Value of the token's `jti`/`cti` if the token
   *   carries one; empty otherwise. Provided so implementations can
   *   correlate the callback with per-token traces without having to
   *   inspect the CatToken themselves.
   * @param iat The token's `iat` claim (absolute epoch seconds).
   * @param reval_interval The `moqt-reval` interval bound to the token.
   * @param time_to_reval Signed seconds from now to the deadline
   *   `iat + moqt-reval`. Negative when already past it; zero at the
   *   exact deadline.
   */
  virtual void onRevalidationCheck(
      RevalidationStatus status, std::string_view token_id, int64_t iat,
      std::chrono::seconds reval_interval,
      std::chrono::seconds time_to_reval) noexcept = 0;
};

/**
 * @brief Default in-tree implementation that discards every event.
 *
 * Sits behind the validator when the deployment has no observability
 * plumbing. Preserves the pre-callback behaviour of the library.
 */
class NoopRevalidationCallback final : public RevalidationCallback {
 public:
  void onRevalidationCheck(RevalidationStatus, std::string_view, int64_t,
                           std::chrono::seconds,
                           std::chrono::seconds) noexcept override {
    // Deliberate no-op: the library still throws TokenRevalidationRequiredError
    // for the Expired case; this callback just discards the observability
    // signal.
  }
};

}  // namespace catapult
