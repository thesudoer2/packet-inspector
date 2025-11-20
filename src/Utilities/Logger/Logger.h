#pragma once

#include <atomic>
#include <thread>

#include <concurrentqueue/moodycamel/concurrentqueue.h>

#include <spdlog/spdlog.h>

#include "Patterns/Singleton.h"

namespace Logger {

constexpr const char* LOGGER_NAME = "PacketInspectorAsyncLogger";

enum class LogLevel { TRACE, DEBUG, INFO, WARNING, ERROR, CRITICAL };

struct LogMessage
{
    LogLevel level;
    std::string message;
    std::string logger_name;

    LogMessage() = default;

    LogMessage(LogLevel lvl, std::string msg, std::string name = "default")
      : level(lvl), message(std::move(msg)), logger_name(std::move(name))
    {}
};

class AsyncLogger final : public Utility::SingletonBase<AsyncLogger>
{
    friend Utility::SingletonBase<AsyncLogger>;

public:
    AsyncLogger() = delete;

    ~AsyncLogger() noexcept;

    // Non-blocking log functions for producer threads
    void log(LogLevel level, const std::string &message, const std::string &logger_name = "default") noexcept;

    // Convenience methods
    void trace(const std::string &msg) noexcept;
    void debug(const std::string &msg) noexcept;
    void info(const std::string &msg) noexcept;
    void warn(const std::string &msg) noexcept;
    void error(const std::string &msg) noexcept;
    void critical(const std::string &msg) noexcept;

    // Get queue statistics
    size_t queueSize() const noexcept;

    void shutdown() noexcept;

private:
    AsyncLogger(size_t queue_size = 10000, bool enable_console = true) noexcept;

    void processLogs() noexcept;

    void logToSpdlog(const LogMessage &msg) noexcept;

private:
    moodycamel::ConcurrentQueue<LogMessage> queue_;
    std::atomic<bool> running_;
    std::thread logger_thread_;
    std::shared_ptr<spdlog::logger> spdlog_logger_;
};

}// namespace Logger