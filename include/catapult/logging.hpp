#pragma once

#ifdef ENABLE_LOGGING
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <memory>
#include <string>

namespace catapult {
namespace logging {

enum class LogLevel {
  TRACE = 0,
  DEBUG = 1,
  INFO = 2,
  WARN = 3,
  ERROR = 4,
  CRITICAL = 5,
  OFF = 6
};

class Logger {
 public:
  static Logger& getInstance() {
    static Logger instance;
    return instance;
  }

  void setLevel(LogLevel level) {
    spdlog::level::level_enum spdlog_level;
    switch (level) {
      case LogLevel::TRACE:
        spdlog_level = spdlog::level::trace;
        break;
      case LogLevel::DEBUG:
        spdlog_level = spdlog::level::debug;
        break;
      case LogLevel::INFO:
        spdlog_level = spdlog::level::info;
        break;
      case LogLevel::WARN:
        spdlog_level = spdlog::level::warn;
        break;
      case LogLevel::ERROR:
        spdlog_level = spdlog::level::err;
        break;
      case LogLevel::CRITICAL:
        spdlog_level = spdlog::level::critical;
        break;
      case LogLevel::OFF:
        spdlog_level = spdlog::level::off;
        break;
    }
    if (logger_) {
      logger_->set_level(spdlog_level);
    }
  }

  std::shared_ptr<spdlog::logger> getLogger() const { return logger_; }

  void setLogLevel(const std::string& level_str) {
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
      setLevel(LogLevel::INFO);  // default
  }

 private:
  Logger() {
    logger_ = spdlog::stdout_color_mt("catapult");
    logger_->set_level(spdlog::level::info);
    logger_->set_pattern("[%H:%M:%S.%e] [%n] [%l] %v");
  }

  std::shared_ptr<spdlog::logger> logger_;
};

}  // namespace logging
}  // namespace catapult

// Convenience macros for logging
#define CAT_LOG_TRACE(...) \
  catapult::logging::Logger::getInstance().getLogger()->trace(__VA_ARGS__)
#define CAT_LOG_DEBUG(...) \
  catapult::logging::Logger::getInstance().getLogger()->debug(__VA_ARGS__)
#define CAT_LOG_INFO(...) \
  catapult::logging::Logger::getInstance().getLogger()->info(__VA_ARGS__)
#define CAT_LOG_WARN(...) \
  catapult::logging::Logger::getInstance().getLogger()->warn(__VA_ARGS__)
#define CAT_LOG_ERROR(...) \
  catapult::logging::Logger::getInstance().getLogger()->error(__VA_ARGS__)
#define CAT_LOG_CRITICAL(...) \
  catapult::logging::Logger::getInstance().getLogger()->critical(__VA_ARGS__)

#else
// No-op macros when logging is disabled
#define CAT_LOG_TRACE(...)
#define CAT_LOG_DEBUG(...)
#define CAT_LOG_INFO(...)
#define CAT_LOG_WARN(...)
#define CAT_LOG_ERROR(...)
#define CAT_LOG_CRITICAL(...)

namespace catapult {
namespace logging {
enum class LogLevel { TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL, OFF };
class Logger {
 public:
  static Logger& getInstance() {
    static Logger instance;
    return instance;
  }
  void setLevel(LogLevel) {}
  void setLogLevel(const std::string&) {}
};
}  // namespace logging
}  // namespace catapult

#endif