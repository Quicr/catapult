#include "catapult/logging.hpp"

#include <atomic>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

namespace catapult {
namespace logging {

namespace {

// The sink is held by a shared_ptr under a mutex so that:
//   - a concurrent `setLogSink()` and `getLogSink()` from another
//     thread yield a coherent snapshot rather than a torn read,
//   - `getLogSink()` returns a shared_ptr copy that keeps the sink
//     alive across the log call even if another thread swaps to a
//     different sink mid-call.
//
// Log volume is expected to be low relative to admission throughput
// (log lines fire on rejections and diagnostics, not per hot-path
// request), so a mutex per get is cheap. If profiling ever shows this
// as a hot path we can migrate to a `std::atomic<shared_ptr>` under
// C++20; for now the mutex is unambiguous and portable.
std::mutex& sink_mutex() {
  static std::mutex m;
  return m;
}

std::shared_ptr<LogSink>& sink_storage() {
  static std::shared_ptr<LogSink> s;
  return s;
}

const char* levelName(LogLevel level) noexcept {
  switch (level) {
    case LogLevel::TRACE:
      return "trace";
    case LogLevel::DEBUG:
      return "debug";
    case LogLevel::INFO:
      return "info";
    case LogLevel::WARN:
      return "warn";
    case LogLevel::ERROR:
      return "error";
    case LogLevel::CRITICAL:
      return "critical";
    case LogLevel::OFF:
      return "off";
  }
  return "unknown";
}

}  // namespace

void setLogSink(std::shared_ptr<LogSink> sink) noexcept {
  std::lock_guard<std::mutex> lock(sink_mutex());
  sink_storage() = std::move(sink);
}

std::shared_ptr<LogSink> getLogSink() noexcept {
  std::lock_guard<std::mutex> lock(sink_mutex());
  return sink_storage();
}

void CerrSink::log(LogLevel level, std::string_view msg) noexcept {
  // Writes to `std::cerr` from multiple threads can interleave at the
  // byte level. `std::cerr` is thread-safe for character output but
  // does not atomically batch a full line, so a concurrent writer can
  // slice ours. Guarded by a per-sink mutex to preserve line integrity.
  try {
    static std::mutex io_mutex;
    std::lock_guard<std::mutex> lock(io_mutex);
    std::cerr << '[' << levelName(level) << "] " << msg << '\n';
  } catch (...) {
    // Contract: log() cannot throw. If cerr itself somehow fails we
    // drop the line.
  }
}

// --------------------------------------------------------------------------
// Back-compat singleton
// --------------------------------------------------------------------------
//
// The pre-abstraction `Logger::getInstance()` singleton exposed
// `setLevel()` / `setLogLevel()`. Hosts that still call these keep
// working: the singleton owns a `CerrSink`, installs it on first
// touch, and forwards level changes to it. A host that installs its
// own sink via `setLogSink()` replaces the CerrSink outright and the
// singleton's setLevel becomes a no-op against the now-unreferenced
// CerrSink.

namespace {

std::shared_ptr<CerrSink>& defaultCerrSink() {
  static std::shared_ptr<CerrSink> s = std::make_shared<CerrSink>();
  return s;
}

}  // namespace

Logger::Logger() {
  auto sink = defaultCerrSink();
  setLogSink(sink);
}

Logger& Logger::getInstance() {
  static Logger instance;
  return instance;
}

void Logger::setLevel(LogLevel level) noexcept {
  defaultCerrSink()->setLevel(level);
}

void Logger::setLogLevel(const std::string& level_str) noexcept {
  if (level_str == "trace")
    setLevel(LogLevel::TRACE);
  else if (level_str == "debug")
    setLevel(LogLevel::DEBUG);
  else if (level_str == "info")
    setLevel(LogLevel::INFO);
  else if (level_str == "warn")
    setLevel(LogLevel::WARN);
  else if (level_str == "error")
    setLevel(LogLevel::ERROR);
  else if (level_str == "critical")
    setLevel(LogLevel::CRITICAL);
  else if (level_str == "off")
    setLevel(LogLevel::OFF);
  else
    setLevel(LogLevel::INFO);
}

}  // namespace logging
}  // namespace catapult
