#include "signal_fd.hpp"

#include <sys/signalfd.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <system_error>

SignalFd::SignalFd(std::initializer_list<int> signals) {
    sigset_t mask;
    sigemptyset(&mask);
    for (int sig : signals) {
        sigaddset(&mask, sig);
    }
    if (::sigprocmask(SIG_BLOCK, &mask, nullptr) < 0) {
        throw std::system_error(errno, std::system_category(), "sigprocmask");
    }
    m_fd = ::signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
    if (m_fd < 0) {
        throw std::system_error(errno, std::system_category(), "signalfd");
    }
}

SignalFd::~SignalFd() { ::close(m_fd); }

int SignalFd::read_signal() const noexcept {
    signalfd_siginfo info{};
    ssize_t n;
    do {
        n = ::read(m_fd, &info, sizeof(info));
    } while (n < 0 && errno == EINTR);
    return n == static_cast<ssize_t>(sizeof(info)) ? static_cast<int>(info.ssi_signo) : 0;
}
