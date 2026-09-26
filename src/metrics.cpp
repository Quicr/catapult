#include "catapult/metrics.hpp"

#include <memory>
#include <mutex>

namespace catapult {
namespace metrics {

namespace {

// Same construction as `logging.cpp`: mutex-guarded shared_ptr so a
// concurrent `setMetricsSink` and `getMetricsSink` from another thread
// yield a coherent snapshot, and callers that took a snapshot keep the
// sink alive across their metric call even if another thread swaps.
std::mutex& sink_mutex() {
  static std::mutex m;
  return m;
}

std::shared_ptr<MetricsSink>& sink_storage() {
  static std::shared_ptr<MetricsSink> s;
  return s;
}

}  // namespace

void setMetricsSink(std::shared_ptr<MetricsSink> sink) noexcept {
  std::lock_guard<std::mutex> lock(sink_mutex());
  sink_storage() = std::move(sink);
}

std::shared_ptr<MetricsSink> getMetricsSink() noexcept {
  std::lock_guard<std::mutex> lock(sink_mutex());
  return sink_storage();
}

}  // namespace metrics
}  // namespace catapult
