#include "Logger.h"

#include <cinttypes>

#include <spdlog/sinks/systemd_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace Logger
{

AsyncLogger::AsyncLogger(std::size_t queue_size, bool enable_console) noexcept
: queue_(queue_size)
, running_(true)
{
    // Create spdlog logger with multiple sinks
    std::vector<spdlog::sink_ptr> sinks;

    // Systemd sink
    auto systemd_sink = std::make_shared<spdlog::sinks::systemd_sink_st>();
    systemd_sink->set_level(spdlog::level::info);
    sinks.push_back(systemd_sink);

    // Optional console sink
    if (enable_console) {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(spdlog::level::info);
        sinks.push_back(console_sink);
    }

    // Create the logger
    spdlog_logger_ = std::make_shared<spdlog::logger>(LOGGER_NAME, sinks.begin(), sinks.end());

    // Set pattern: [timestamp] [level] [thread id] message
    spdlog_logger_->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");
    spdlog_logger_->set_level(spdlog::level::trace);

    // Register as default logger
    spdlog::set_default_logger(spdlog_logger_);

    // Start logger thread
    logger_thread_ = std::thread(&AsyncLogger::processLogs, this);
}

AsyncLogger::~AsyncLogger() noexcept
{
    shutdown();
}

void AsyncLogger::log(LogLevel level, const std::string &message, const std::string &logger_name) noexcept
{
    LogMessage msg(level, message, logger_name);

    if (!queue_.enqueue(msg)) {
        // Queue full - fallback to direct spdlog call (will block)
        spdlog::error("Log queue full! Falling back to blocking write.");
        logToSpdlog(msg);
    }
}

void AsyncLogger::trace(const std::string &msg) noexcept
{
    log(LogLevel::TRACE, msg);
}

void AsyncLogger::debug(const std::string &msg) noexcept
{
    log(LogLevel::DEBUG, msg);
}

void AsyncLogger::info(const std::string &msg) noexcept
{
    log(LogLevel::INFO, msg);
}

void AsyncLogger::warn(const std::string &msg) noexcept
{
    log(LogLevel::WARNING, msg);
}

void AsyncLogger::error(const std::string &msg) noexcept
{
    log(LogLevel::ERROR, msg);
}

void AsyncLogger::critical(const std::string &msg) noexcept
{
    log(LogLevel::CRITICAL, msg);
}

std::size_t AsyncLogger::queueSize() const noexcept
{
    return queue_.size_approx();
}

void AsyncLogger::shutdown() noexcept
{
    if (!running_.exchange(false)) return;

    spdlog::info("Shutting down async logger...");

    if (logger_thread_.joinable()) {
        logger_thread_.join();
    }

    spdlog::info("Async logger shutdown complete.");
    spdlog::shutdown();// Flush and close all spdlog loggers
}

void AsyncLogger::processLogs() noexcept
{
    LogMessage msg;
    const size_t BULK_SIZE = 100;
    LogMessage bulk_buffer[BULK_SIZE];

    while (running_ || queue_.size_approx() > 0) {
        // Try bulk dequeue for better performance
        size_t count = queue_.try_dequeue_bulk(bulk_buffer, BULK_SIZE);

        if (count > 0) {
            for (size_t i = 0; i < count; ++i) { logToSpdlog(bulk_buffer[i]); }
            spdlog_logger_->flush();// Flush after bulk write
        } else {
            // No messages, sleep briefly to avoid busy-waiting
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    // Final flush
    spdlog_logger_->flush();
}

void AsyncLogger::logToSpdlog(const LogMessage &msg) noexcept
{
    switch (msg.level) {
    case LogLevel::TRACE:
        spdlog_logger_->trace(msg.message);
        break;
    case LogLevel::DEBUG:
        spdlog_logger_->debug(msg.message);
        break;
    case LogLevel::INFO:
        spdlog_logger_->info(msg.message);
        break;
    case LogLevel::WARNING:
        spdlog_logger_->warn(msg.message);
        break;
    case LogLevel::ERROR:
        spdlog_logger_->error(msg.message);
        break;
    case LogLevel::CRITICAL:
        spdlog_logger_->critical(msg.message);
        break;
    }
}

} // namespace Logger