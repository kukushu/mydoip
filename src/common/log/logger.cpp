#include "logger.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace logsys {

Logger& Logger::instance() {
    static Logger logger;
    return logger;
}

void Logger::setLevel(Level level) { minLevel_ = level; }

const char* Logger::levelToString(Level level) {
    switch (level) {
        case Level::Trace: return "TRACE";
        case Level::Debug: return "DEBUG";
        case Level::Info: return "INFO";
        case Level::Warn: return "WARN";
        case Level::Error: return "ERROR";
    }
    return "UNKNOWN";
}

void Logger::log(Level level, const std::string& module, const std::string& message) {
    if (static_cast<int>(level) < static_cast<int>(minLevel_)) return;

    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif

    std::ostringstream ts;
    ts << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");

    std::lock_guard<std::mutex> lock(mutex_);
    std::cout << ts.str() << " [" << levelToString(level) << "] [" << module << "] " << message << std::endl;
}

}  // namespace logsys
