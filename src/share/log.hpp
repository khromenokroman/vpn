#pragma once

#include <fmt/format.h>
#include <syslog.h>

#include <cstdio>
#include <string>
#include <system_error>
#include <utility>

/**
 * @brief Пишет сообщение в syslog с форматированием fmt.
 *
 * Типы аргументов проверяются при компиляции, в отличие от формата printf у syslog,
 * где несовпадение спецификатора и типа (например %lu для uint64_t на 32-битной платформе) - UB.
 *
 * @param priority приоритет syslog (LOG_ERR, LOG_INFO, ...)
 * @param format строка формата fmt
 * @param args аргументы
 */
template <typename... Args>
void log_msg(int priority, fmt::format_string<Args...> format, Args&&... args) {
    syslog(priority, "%s", fmt::format(format, std::forward<Args>(args)...).c_str());
}

/**
 * @brief Текст ошибки errno, безопасно для вызова из нескольких потоков (в отличие от strerror).
 * @param err код errno
 */
inline std::string errno_str(int err) { return std::system_category().message(err); }

/**
 * @brief Сообщает об ошибке запуска: в stderr (видно при ручном запуске) и в syslog (видно в журнале службы).
 * @param format строка формата fmt
 * @param args аргументы
 */
template <typename... Args>
void report_error(fmt::format_string<Args...> format, Args&&... args) {
    std::string msg = fmt::format(format, std::forward<Args>(args)...);
    std::fprintf(stderr, "%s\n", msg.c_str());
    syslog(LOG_ERR, "%s", msg.c_str());
}
