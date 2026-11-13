#pragma once

#include <fmt/format.h>
#include <syslog.h>

#include <chrono>
#include <cstdint>
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

/**
 * @brief Открывает syslog для программы.
 * @param ident имя в журнале (journalctl -t <ident>)
 */
inline void init_syslog(const char* ident) { openlog(ident, LOG_PID, LOG_DAEMON); }

/**
 * @brief Ограничение частоты одного вида сообщений: поток одинаковых отказов не забивает журнал.
 *
 * Не потокобезопасен: у каждого потока свой экземпляр.
 */
class LogThrottle {
   public:
    /** @param interval не чаще одного сообщения за этот интервал */
    explicit LogThrottle(std::chrono::seconds interval) : m_interval(interval) {}

    /** @return true, если сообщение можно писать сейчас; пропущенные с прошлого раза считаются в suppressed() */
    bool allow() {
        auto now = std::chrono::steady_clock::now();
        if (now < m_next) {
            ++m_suppressed;
            return false;
        }
        m_next = now + m_interval;
        m_last_suppressed = m_suppressed;
        m_suppressed = 0;
        return true;
    }

    /** @brief Сколько сообщений пропущено перед последним разрешённым. */
    std::uint64_t suppressed() const { return m_last_suppressed; }

   private:
    std::chrono::steady_clock::time_point m_next{};
    std::chrono::seconds m_interval;
    std::uint64_t m_suppressed = 0;
    std::uint64_t m_last_suppressed = 0;
};
