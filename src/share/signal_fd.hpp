#pragma once

#include <initializer_list>

/**
 * @brief Приём сигналов через signalfd вместо асинхронных обработчиков.
 *
 * В обработчике сигнала допустимы только async-signal-safe функции; syslog, mutex, join и exit
 * к ним не относятся. Здесь сигналы блокируются и читаются из дескриптора в обычном потоке.
 *
 * Конструктор нужно вызвать до создания потоков: маска сигналов наследуется, и сигнал
 * не будет доставлен в случайный рабочий поток.
 */
class SignalFd {
   public:
    /**
     * @brief Блокирует сигналы во всём процессе и создаёт signalfd.
     * @param signals номера сигналов
     * @throw std::system_error при ошибке sigprocmask или signalfd
     */
    explicit SignalFd(std::initializer_list<int> signals);
    ~SignalFd();

    SignalFd(const SignalFd&) = delete;
    SignalFd& operator=(const SignalFd&) = delete;

    /** @brief Дескриптор для poll(). */
    int get_fd() const noexcept { return m_fd; }

    /**
     * @brief Читает пришедший сигнал.
     * @return номер сигнала или 0, если сигналов нет
     */
    int read_signal() const noexcept;

   private:
    int m_fd = -1;
};
