#ifndef NG_LOGGIN_H
#define NG_LOGGIN_H

#include <chrono>
#include <format>
#include <iostream>
#include <ostream>
#include <system_error>
#include <utility>
#include <string>

extern bool ng_use_timestamps;

namespace ng::logging {

typedef enum tag_log_level : int {
    NG_TRC = 0,
    NG_INF,
    NG_WRN,
    NG_ERR
} log_level_t;

typedef void (*logger_out_t)(const std::string& log_line, log_level_t level);
typedef void (*wlogger_out_t)(const std::wstring& log_line, log_level_t level);

static log_level_t _log_level = NG_INF;

static std::string get_error_message(int error_no) {
    return std::system_category().message(error_no);
}

static std::string get_timestamp(void) {
    std::stringstream ss;
    auto now =
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    ss << std::put_time(std::localtime(&now), "[%Y-%m-%d %H:%M:%S] ");

    return ss.str();
}

static std::wstring wget_timestamp(void) {
    std::wstringstream ss;
    auto now =
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    ss << std::put_time(std::localtime(&now), L"[%Y-%m-%d %H:%M:%S] ");

    return ss.str();
}

static logger_out_t configure_logger(logger_out_t logger) {
    static logger_out_t _logger = [](const std::string& log_line,
                                     log_level_t level) {
        std::ostream* out = nullptr;
        std::string prefix;

        switch (level) {
            case NG_TRC:
                if (_log_level == NG_TRC) {
                    prefix = "[TRACE] ";
                    out = &std::cout;
                }
                break;
            case NG_INF:
                if (_log_level <= NG_INF) {
                    prefix = "[INFO] ";
                    out = &std::cout;
                }
                break;
            case NG_WRN:
                if (_log_level <= NG_WRN) {
                    prefix = "[WARN] ";
                    out = &std::cout;
                }
                break;
            case NG_ERR:
            default:
                prefix = "[ERROR] ";
                out = &std::cerr;
                break;
        }

        if (out == nullptr) {
            return;
        }

        if (ng_use_timestamps) {
            (*out) << get_timestamp();
        }

        (*out) << prefix << log_line << "\n";
    };

    if (logger != nullptr) {
        _logger = logger;
    }

    return _logger;
}

static void log(const std::string& log_line, log_level_t level = NG_INF) {
    logger_out_t _logger = configure_logger(nullptr);
    _logger(log_line, level);
}

template <typename T>
static void trace(const T& log_line) {
    log(log_line, NG_TRC);
}

template <typename T>
static void trace(T&& log_line) {
    log(std::forward<T>(log_line), NG_TRC);
}

template <typename... Args>
static void trace(std::string_view fmt, Args&... args) {
    log(std::vformat(fmt, std::make_format_args(args...)), NG_TRC);
}

template <typename... Args>
static void trace(std::string_view fmt, Args&&... args) {
    log(std::vformat(fmt, std::make_format_args(args...)), NG_TRC);
}

template <typename T>
static void info(const T& log_line) {
    log(log_line, NG_INF);
}

template <typename... Args>
static void info(std::string_view fmt, Args&... args) {
    log(std::vformat(fmt, std::make_format_args(args...)), NG_INF);
}

template <typename... Args>
static void info(std::string_view fmt, Args&&... args) {
    log(std::vformat(fmt, std::make_format_args(args...)), NG_INF);
}

template <typename T>
static void error(const T& log_line) {
    log(log_line, NG_ERR);
}

template <typename... Args>
static void error(std::string_view fmt, Args&... args) {
    log(std::vformat(fmt, std::make_format_args(args...)), NG_ERR);
}

template <typename... Args>
static void error(std::string_view fmt, Args&&... args) {
    log(std::vformat(fmt, std::make_format_args(args...)), NG_ERR);
}

template <typename T>
static void warn(const T& log_line) {
    log(log_line, NG_WRN);
}

template <typename... Args>
static void warn(std::string_view fmt, Args&... args) {
    log(std::vformat(fmt, std::make_format_args(args...)), NG_ERR);
}

template <typename... Args>
static void warn(std::string_view fmt, Args&&... args) {
    log(std::vformat(fmt, std::make_format_args(args...)), NG_ERR);
}

static wlogger_out_t configure_wlogger(wlogger_out_t logger) {
    static wlogger_out_t _logger = [](const std::wstring& log_line,
                                      log_level_t level) {
        std::wostream* out = nullptr;
        std::wstring prefix;

        switch (level) {
            case NG_TRC:
                if (_log_level == NG_TRC) {
                    prefix = L"[TRACE] ";
                    out = &std::wcout;
                }
                break;
            case NG_INF:
                if (_log_level <= NG_INF) {
                    prefix = L"[INFO] ";
                    out = &std::wcout;
                }
                break;
            case NG_WRN:
                if (_log_level <= NG_WRN) {
                    prefix = L"[WARN] ";
                    out = &std::wcout;
                }
                break;
            case NG_ERR:
            default:
                prefix = L"[ERROR] ";
                out = &std::wcerr;
                break;
        }

        if (out == nullptr) {
            return;
        }

        if (ng_use_timestamps) {
            (*out) << wget_timestamp();
        }

        (*out) << prefix << log_line << L"\n";
    };

    if (logger != nullptr) {
        _logger = logger;
    }

    return _logger;
}

static void log(const std::wstring& log_line, log_level_t level = NG_INF) {
    auto _logger = configure_wlogger(nullptr);
    _logger(log_line, level);
}

template <typename... Args>
static void trace(std::wstring_view fmt, Args&... args) {
    log(std::vformat(fmt, std::make_format_args(args...)), NG_TRC);
}

template <typename... Args>
static void trace(std::wstring_view fmt, Args&&... args) {
    log(std::vformat(fmt, std::make_format_args(args...)), NG_TRC);
}

template <typename... Args>
static void info(std::wstring_view fmt, Args&... args) {
    log(std::vformat(fmt, std::make_format_args(args...)), NG_INF);
}

template <typename... Args>
static void error(std::wstring_view fmt, Args&... args) {
    log(std::vformat(fmt, std::make_format_args(args...)), NG_ERR);
}

template <typename... Args>
static void error(std::wstring_view fmt, Args&&... args) {
    log(std::vformat(fmt, std::make_format_args(args...)), NG_ERR);
}

template <typename... Args>
static void warn(std::wstring_view fmt, Args&... args) {
    log(std::vformat(fmt, std::make_format_args(args...)), NG_ERR);
}

template <typename... Args>
static void warn(std::wstring_view fmt, Args&&... args) {
    log(std::vformat(fmt, std::make_format_args(args...)), NG_ERR);
}

}  // namespace ng::logging

#endif
