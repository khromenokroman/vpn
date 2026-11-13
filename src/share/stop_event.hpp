#pragma once

#include <chrono>

/**
 * @brief Событие остановки рабочих потоков на eventfd.
 *
 * Потоки ждут данные через poll() одновременно на своём дескрипторе и на событии, поэтому
 * блокирующий read() на TUN больше не мешает остановке: закрытие дескриптора из другого потока
 * не будит read() и к тому же гонка (номер fd может достаться другому файлу).
 */
class StopEvent {
   public:
    /** @throw std::system_error если eventfd не создан */
    StopEvent();
    ~StopEvent();

    StopEvent(const StopEvent&) = delete;
    StopEvent& operator=(const StopEvent&) = delete;

    /** @brief Взводит событие; все ожидающие и будущие wait_* сразу возвращают STOP. */
    void notify() noexcept;

    /** @brief Взведено ли событие. */
    bool is_set() const noexcept;

    /** @brief Результат ожидания. */
    enum class Wait {
        READY,   ///< дескриптор готов к чтению
        STOP,    ///< взведено событие остановки
        TIMEOUT, ///< истёк таймаут
        ERROR,   ///< ошибка poll() или дескриптора, errno сохранён
    };

    /**
     * @brief Ждёт, пока fd станет читаемым или придёт остановка.
     * @param fd дескриптор данных
     * @param timeout таймаут; отрицательный - без таймаута
     * @return READY, STOP, TIMEOUT или ERROR
     */
    Wait wait_readable(int fd, std::chrono::milliseconds timeout = std::chrono::milliseconds{-1}) const noexcept;

    /**
     * @brief Ждёт остановку не дольше timeout.
     * @return STOP или TIMEOUT (ERROR при сбое poll)
     */
    Wait wait_for(std::chrono::milliseconds timeout) const noexcept;

   private:
    Wait poll_impl(int fd, int timeout_ms) const noexcept;

    int m_fd = -1;
};
