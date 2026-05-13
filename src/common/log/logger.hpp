#pragma once

#include <mutex>
#include <string>

namespace logsys {

enum class Level { Trace = 0, Debug = 1, Info = 2, Warn = 3, Error = 4 };

class Logger {
public:
    static Logger& instance();

    void setLevel(Level level);
    void log(Level level, const std::string& module, const std::string& message);

private:
    Logger() = default;
    static const char* levelToString(Level level);

    Level minLevel_{Level::Info};
    std::mutex mutex_;
};

}  // namespace logsys

#define LOG_TRACE(module, message) ::logsys::Logger::instance().log(::logsys::Level::Trace, module, message)
#define LOG_DEBUG(module, message) ::logsys::Logger::instance().log(::logsys::Level::Debug, module, message)
#define LOG_INFO(module, message) ::logsys::Logger::instance().log(::logsys::Level::Info, module, message)
#define LOG_WARN(module, message) ::logsys::Logger::instance().log(::logsys::Level::Warn, module, message)
#define LOG_ERROR(module, message) ::logsys::Logger::instance().log(::logsys::Level::Error, module, message)
