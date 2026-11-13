#include <gtest/gtest.h>
#include <pthread.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <future>
#include <thread>

#include "share/signal_fd.hpp"
#include "share/stop_event.hpp"

using namespace std::chrono_literals;

namespace {

/** @brief Пара дескрипторов pipe, закрывается в деструкторе. */
struct Pipe {
    Pipe() { EXPECT_EQ(::pipe(fds), 0) << "pipe(): " << std::strerror(errno); }
    ~Pipe() {
        ::close(fds[0]);
        ::close(fds[1]);
    }
    int fds[2] = {-1, -1};
};

const char* to_str(StopEvent::Wait w) {
    switch (w) {
        case StopEvent::Wait::READY:
            return "READY";
        case StopEvent::Wait::STOP:
            return "STOP";
        case StopEvent::Wait::TIMEOUT:
            return "TIMEOUT";
        case StopEvent::Wait::ERROR:
            return "ERROR";
    }
    return "?";
}

} // namespace

/**
 * @brief Главное исправление остановки: поток, ждущий данных без таймаута на дескрипторе, где данных
 * нет (как TUN без трафика), просыпается по notify() из другого потока за доли секунды.
 */
TEST(StopEvent, WakesBlockedWaiter) {
    StopEvent stop;
    Pipe idle;
    auto waiter = std::async(std::launch::async, [&] { return stop.wait_readable(idle.fds[0]); });
    ASSERT_EQ(waiter.wait_for(100ms), std::future_status::timeout) << "без данных и без notify() ожидание не должно завершаться";
    stop.notify();
    ASSERT_EQ(waiter.wait_for(2s), std::future_status::ready) << "notify() не разбудил поток за 2 с";
    EXPECT_STREQ(to_str(waiter.get()), "STOP");
}

/**
 * @brief Данные на дескрипторе дают READY, пока остановки нет.
 */
TEST(StopEvent, ReadyOnData) {
    StopEvent stop;
    Pipe p;
    ASSERT_EQ(::write(p.fds[1], "x", 1), 1);
    EXPECT_STREQ(to_str(stop.wait_readable(p.fds[0], 1s)), "READY") << "в pipe 1 байт, остановки нет";
}

/**
 * @brief Остановка важнее данных: после notify() поток выходит, даже если очередь не пуста.
 */
TEST(StopEvent, StopWinsOverData) {
    StopEvent stop;
    Pipe p;
    ASSERT_EQ(::write(p.fds[1], "x", 1), 1);
    stop.notify();
    EXPECT_STREQ(to_str(stop.wait_readable(p.fds[0])), "STOP") << "в pipe 1 байт и взведена остановка";
}

/**
 * @brief Событие не сбрасывается: каждый из нескольких потоков увидит остановку.
 */
TEST(StopEvent, StaysSet) {
    StopEvent stop;
    EXPECT_FALSE(stop.is_set()) << "новое событие";
    stop.notify();
    for (int i = 0; i < 3; ++i) {
        EXPECT_TRUE(stop.is_set()) << "проверка " << i << " после одного notify()";
        EXPECT_STREQ(to_str(stop.wait_for(0ms)), "STOP") << "проверка " << i;
    }
}

/**
 * @brief Без событий wait_for завершается по таймауту, не раньше него.
 */
TEST(StopEvent, TimesOut) {
    StopEvent stop;
    auto start = std::chrono::steady_clock::now();
    EXPECT_STREQ(to_str(stop.wait_for(50ms)), "TIMEOUT");
    EXPECT_GE(std::chrono::steady_clock::now() - start, 45ms) << "таймаут 50 мс";
}

/**
 * @brief Сигнал, отправленный процессу, читается из signalfd и не вызывает обработчик по умолчанию
 * (SIGTERM без блокировки завершил бы тест).
 */
TEST(SignalFd, ReceivesBlockedSignal) {
    SignalFd signals({SIGUSR1});
    StopEvent stop;
    ASSERT_EQ(::kill(::getpid(), SIGUSR1), 0);
    ASSERT_STREQ(to_str(stop.wait_readable(signals.get_fd(), 2s)), "READY") << "SIGUSR1 не дошёл до signalfd за 2 с";
    EXPECT_EQ(signals.read_signal(), SIGUSR1);
    EXPECT_EQ(signals.read_signal(), 0) << "второго сигнала не было";
}
