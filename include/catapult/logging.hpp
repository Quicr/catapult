/**
 * @file logging.hpp
 * @brief Logging seam for the catapult library.
 *
 * catapult does not own its host's log pipeline. Embedders bring their
 * own logger (spdlog, absl, glog, or bespoke), and catapult routes
 * every internal `CAT_LOG_*` call through a `LogSink` they install.
 *
 * The library owns exactly two things: the severity taxonomy and the
 * macro surface. Everything else — where lines are written, how they
 * are formatted, whether trace-ids are attached — is the sink's job.
 *
 * Defaults:
 *   - No sink installed → all `CAT_LOG_*` calls are silently dropped.
 *     A relay that forgets to wire logging still runs; it just does
 *     not emit.
 *   - `ENABLE_LOGGING=OFF` at compile time → macros expand to no-ops.
 *     No runtime sink call is made and `std::format` is not invoked,
 *     so hot paths pay zero cost.
 *
 * Setting a sink is thread-safe (atomic pointer swap). Calls that
 * race with the swap either see the old sink or the new; they do not
 * observe a torn state.
 */

#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#ifdef ENABLE_LOGGING
#include <format>
#endif

namespace catapult {
namespace logging {

/**
 * @brief Severity levels used across the library.
 *
 * Ordering is significant: `enabled(level)` semantics require severities
 * to be comparable. `OFF` is a filter sentinel — a sink at level `OFF`
 * accepts nothing.
 */
enum class LogLevel {
  TRACE = 0,
  DEBUG = 1,
  INFO = 2,
  WARN = 3,
  ERROR = 4,
  CRITICAL = 5,
  OFF = 6
};

/**
 * @brief The seam every host implements to receive catapult log lines.
 *
 * Contract:
 *   - `log()` is called from arbitrary threads and must be safe to
 *     invoke concurrently. Sinks that wrap a non-thread-safe logger
 *     must guard themselves.
 *   - `log()` MUST NOT throw. Catapult calls into the sink from paths
 *     that cannot unwind cleanly (e.g. inside `noexcept` blocks). A
 *     sink that fails should drop the line, not propagate.
 *   - `enabled()` is a fast filter check. Catapult evaluates it before
 *     it formats the message so an expensive `std::format` call is
 *     avoided for filtered severities.
 *
 * The message is pre-formatted UTF-8 text. Structured fields, trace
 * IDs, and machine-readable context are the host's concern.
 */
class LogSink {
 public:
  virtual ~LogSink() = default;

  virtual void log(LogLevel level, std::string_view msg) noexcept = 0;

  virtual bool enabled(LogLevel /*level*/) const noexcept { return true; }
};

/**
 * @brief Install a sink. Pass `nullptr` to detach.
 *
 * Thread-safe. Ownership is shared — the sink survives as long as
 * catapult, or any code holding a `shared_ptr` from `getLogSink()`,
 * still references it. That matters because a log call may already be
 * in flight on another thread when the caller decides to swap sinks.
 */
void setLogSink(std::shared_ptr<LogSink> sink) noexcept;

/**
 * @brief Snapshot the current sink. May return `nullptr`.
 *
 * Intended for the `CAT_LOG_*` macros; hosts should not call this
 * directly. Returning a `shared_ptr` (rather than a raw pointer) means
 * a concurrent `setLogSink(nullptr)` cannot free the sink out from
 * under a log call in progress.
 */
std::shared_ptr<LogSink> getLogSink() noexcept;

// --------------------------------------------------------------------------
// Built-in sinks
// --------------------------------------------------------------------------

/**
 * @brief A sink that discards every line. Behaviourally equivalent to
 *        installing no sink at all; provided so hosts can express
 *        "logging is intentionally off" distinctly from "not yet wired".
 */
class NullSink final : public LogSink {
 public:
  void log(LogLevel, std::string_view) noexcept override {}
  bool enabled(LogLevel) const noexcept override { return false; }
};

/**
 * @brief A sink that writes plaintext lines to `std::cerr`. Useful for
 *        demos and CLI tools; production deployments should use their
 *        own structured pipeline.
 *
 * The minimum severity is settable; lines below it are dropped in
 * `enabled()` so no formatting cost is paid.
 */
class CerrSink final : public LogSink {
 public:
  explicit CerrSink(LogLevel min_level = LogLevel::INFO) noexcept
      : min_level_(min_level) {}

  void log(LogLevel level, std::string_view msg) noexcept override;

  bool enabled(LogLevel level) const noexcept override {
    return static_cast<int>(level) >= static_cast<int>(min_level_.load());
  }

  void setLevel(LogLevel level) noexcept { min_level_.store(level); }

 private:
  std::atomic<LogLevel> min_level_;
};

// --------------------------------------------------------------------------
// Back-compat shim
// --------------------------------------------------------------------------
//
// Earlier revisions of catapult exposed a `Logger::getInstance().setLevel()`
// singleton. Hosts calling that pattern keep working: `Logger` now
// forwards to `CerrSink` unless a sink has been installed, and preserves
// the string-to-level parsing helper for existing config-file callers.
class Logger {
 public:
  static Logger& getInstance();

  void setLevel(LogLevel level) noexcept;

  void setLogLevel(const std::string& level_str) noexcept;

 private:
  Logger();
};

}  // namespace logging
}  // namespace catapult

// --------------------------------------------------------------------------
// Macro surface
// --------------------------------------------------------------------------

#ifdef ENABLE_LOGGING

// Guard `enabled()` before the format call so filtered severities pay
// zero formatting cost. The `try/catch` is defensive: a format-error
// (e.g. mismatched argument) must not tear down the caller.
#define CAT_LOG_IMPL(level, ...)                           \
  do {                                                     \
    auto _cat_sink = ::catapult::logging::getLogSink();    \
    if (_cat_sink && _cat_sink->enabled(level)) {          \
      try {                                                \
        _cat_sink->log(level, ::std::format(__VA_ARGS__)); \
      } catch (...) {                                      \
      }                                                    \
    }                                                      \
  } while (0)

#define CAT_LOG_TRACE(...) \
  CAT_LOG_IMPL(::catapult::logging::LogLevel::TRACE, __VA_ARGS__)
#define CAT_LOG_DEBUG(...) \
  CAT_LOG_IMPL(::catapult::logging::LogLevel::DEBUG, __VA_ARGS__)
#define CAT_LOG_INFO(...) \
  CAT_LOG_IMPL(::catapult::logging::LogLevel::INFO, __VA_ARGS__)
#define CAT_LOG_WARN(...) \
  CAT_LOG_IMPL(::catapult::logging::LogLevel::WARN, __VA_ARGS__)
#define CAT_LOG_ERROR(...) \
  CAT_LOG_IMPL(::catapult::logging::LogLevel::ERROR, __VA_ARGS__)
#define CAT_LOG_CRITICAL(...) \
  CAT_LOG_IMPL(::catapult::logging::LogLevel::CRITICAL, __VA_ARGS__)

#else

// Fully compiled out. No sink lookup, no formatting, no branch.
#define CAT_LOG_TRACE(...) ((void)0)
#define CAT_LOG_DEBUG(...) ((void)0)
#define CAT_LOG_INFO(...) ((void)0)
#define CAT_LOG_WARN(...) ((void)0)
#define CAT_LOG_ERROR(...) ((void)0)
#define CAT_LOG_CRITICAL(...) ((void)0)

#endif  // ENABLE_LOGGING
