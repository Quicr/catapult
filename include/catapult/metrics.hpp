/**
 * @file metrics.hpp
 * @brief Metrics seam for the catapult library.
 *
 * Same shape as the logging seam (see `logging.hpp`): catapult defines
 * the metric surface, hosts install a sink, and every internal
 * `CAT_METRIC_*` call routes through it. If no sink is installed the
 * calls are silent no-ops; if `ENABLE_METRICS` is off at compile time
 * they compile out entirely.
 *
 * ## Contract
 *
 * - `MetricsSink::increment(name, by)` records a counter delta. `by`
 *   is >= 0 in practice; a delta of 1 is the common case.
 * - `MetricsSink::observe(name, value_ns)` records a single sample
 *   into a histogram. Catapult always reports durations in
 *   nanoseconds; hosts render them into whatever bucket structure
 *   their downstream metric system expects.
 * - `MetricsSink::gauge(name, value)` sets an absolute gauge (e.g.,
 *   cache size). Not used on admission hot paths — reserved for
 *   maintenance callbacks.
 * - Every method is `noexcept`. A sink that fails must drop the
 *   sample, not propagate. Catapult calls into sinks from paths that
 *   cannot unwind cleanly.
 * - Every method is called from arbitrary threads and MUST be safe to
 *   invoke concurrently. Adapters over non-thread-safe metric
 *   libraries must guard themselves.
 *
 * ## Naming
 *
 * Metric names are compile-time `const char*` literals defined in the
 * `catapult::metrics::names` namespace. Hosts SHOULD pre-register
 * these with their metric backend (declaring counter vs histogram
 * types) before installing the sink; a sink that receives an
 * unregistered name may either late-bind or drop.
 *
 * The name set is intentionally small at this revision. Additions
 * are semantic-versioned: names never change meaning, and removals
 * come with a deprecation window.
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>

namespace catapult {
namespace metrics {

/**
 * @brief The seam every host implements to receive catapult metric events.
 */
class MetricsSink {
 public:
  virtual ~MetricsSink() = default;

  /**
   * @brief Add `by` to the counter named `name`. Never negative in
   *        practice; hosts may treat a negative delta as an error.
   */
  virtual void increment(std::string_view name, uint64_t by) noexcept = 0;

  /**
   * @brief Record a duration sample (nanoseconds) into a histogram.
   */
  virtual void observe(std::string_view name, uint64_t value_ns) noexcept = 0;

  /**
   * @brief Set the absolute value of a gauge.
   */
  virtual void gauge(std::string_view name, int64_t value) noexcept = 0;
};

/**
 * @brief Install a sink. Pass `nullptr` to detach. Thread-safe.
 */
void setMetricsSink(std::shared_ptr<MetricsSink> sink) noexcept;

/**
 * @brief Snapshot the current sink. May return `nullptr`. Intended for
 *        the `CAT_METRIC_*` macros; hosts should not call directly.
 */
std::shared_ptr<MetricsSink> getMetricsSink() noexcept;

/**
 * @brief Discards every event. Same behaviour as installing no sink;
 *        useful when a host wants to state "metrics intentionally off"
 *        distinctly from "not yet wired".
 */
class NullMetricsSink final : public MetricsSink {
 public:
  void increment(std::string_view, uint64_t) noexcept override {}
  void observe(std::string_view, uint64_t) noexcept override {}
  void gauge(std::string_view, int64_t) noexcept override {}
};

// --------------------------------------------------------------------------
// Metric name registry
// --------------------------------------------------------------------------
//
// Names are library-owned and stable. A host's metric backend can be
// pre-registered against this list. Prefer these constants over string
// literals at call sites so a rename is a compile break, not a silent
// drop.
namespace names {

// Admission outcomes on the `CatTokenValidator` path. Every call to
// `intoValidated()` that runs to completion increments exactly one of
// these.
inline constexpr const char* kAdmissionAllow = "catapult.admission.allow";
inline constexpr const char* kAdmissionRejectExpired =
    "catapult.admission.reject.expired";
inline constexpr const char* kAdmissionRejectNotYetValid =
    "catapult.admission.reject.not_yet_valid";
inline constexpr const char* kAdmissionRejectIssuer =
    "catapult.admission.reject.issuer";
inline constexpr const char* kAdmissionRejectAudience =
    "catapult.admission.reject.audience";
inline constexpr const char* kAdmissionRejectPolicy =
    "catapult.admission.reject.policy";
inline constexpr const char* kAdmissionRejectMoqtScope =
    "catapult.admission.reject.moqt_scope";
inline constexpr const char* kAdmissionRejectReplay =
    "catapult.admission.reject.replay";
inline constexpr const char* kAdmissionRejectUsage =
    "catapult.admission.reject.usage_exhausted";
inline constexpr const char* kAdmissionRejectOther =
    "catapult.admission.reject.other";

// End-to-end admission latency in nanoseconds. Recorded once per
// `intoValidated()` call, regardless of outcome, so hosts can bucket
// their SLO on the same series that emits allow/reject counters.
inline constexpr const char* kAdmissionLatencyNs =
    "catapult.admission.latency_ns";

// DPoP-side counters. `validate_proof()` increments exactly one.
inline constexpr const char* kDpopValidateAllow = "catapult.dpop.allow";
inline constexpr const char* kDpopValidateReject = "catapult.dpop.reject";

// ReplayStore admit outcomes — surfaced from `admit()` return value
// so operators can distinguish freshness from replay from exhaustion
// without parsing log lines.
inline constexpr const char* kReplayAdmitted = "catapult.replay.admitted";
inline constexpr const char* kReplayHit = "catapult.replay.hit";
inline constexpr const char* kReplayStoreExhausted =
    "catapult.replay.store_exhausted";

}  // namespace names

}  // namespace metrics
}  // namespace catapult

// --------------------------------------------------------------------------
// Macro surface
// --------------------------------------------------------------------------

#ifdef ENABLE_METRICS

#define CAT_METRIC_INC(name)                                    \
  do {                                                          \
    auto _cat_msink = ::catapult::metrics::getMetricsSink();    \
    if (_cat_msink) _cat_msink->increment((name), 1);           \
  } while (0)

#define CAT_METRIC_INC_BY(name, by)                             \
  do {                                                          \
    auto _cat_msink = ::catapult::metrics::getMetricsSink();    \
    if (_cat_msink)                                             \
      _cat_msink->increment((name), static_cast<uint64_t>(by)); \
  } while (0)

#define CAT_METRIC_OBSERVE_NS(name, value_ns)                   \
  do {                                                          \
    auto _cat_msink = ::catapult::metrics::getMetricsSink();    \
    if (_cat_msink)                                             \
      _cat_msink->observe((name),                               \
                          static_cast<uint64_t>(value_ns));     \
  } while (0)

#define CAT_METRIC_GAUGE(name, value)                           \
  do {                                                          \
    auto _cat_msink = ::catapult::metrics::getMetricsSink();    \
    if (_cat_msink)                                             \
      _cat_msink->gauge((name), static_cast<int64_t>(value));   \
  } while (0)

#else

#define CAT_METRIC_INC(name) ((void)0)
#define CAT_METRIC_INC_BY(name, by) ((void)0)
#define CAT_METRIC_OBSERVE_NS(name, value_ns) ((void)0)
#define CAT_METRIC_GAUGE(name, value) ((void)0)

#endif  // ENABLE_METRICS
