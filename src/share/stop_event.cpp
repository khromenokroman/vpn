#include "stop_event.hpp"

#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <system_error>

StopEvent::StopEvent() : m_fd(::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)) {
    if (m_fd < 0) {
        throw std::system_error(errno, std::system_category(), "eventfd");
    }
}

StopEvent::~StopEvent() { ::close(m_fd); }

void StopEvent::notify() noexcept {
    std::uint64_t one = 1;
    // счётчик eventfd не сбрасывается чтением нигде, поэтому событие остаётся взведённым
    [[maybe_unused]] ssize_t n = ::write(m_fd, &one, sizeof(one));
}

bool StopEvent::is_set() const noexcept { return poll_impl(-1, 0) == Wait::STOP; }

StopEvent::Wait StopEvent::wait_readable(int fd, std::chrono::milliseconds timeout) const noexcept {
    return poll_impl(fd, timeout.count() < 0 ? -1 : static_cast<int>(timeout.count()));
}

StopEvent::Wait StopEvent::wait_for(std::chrono::milliseconds timeout) const noexcept { return poll_impl(-1, static_cast<int>(timeout.count())); }

StopEvent::Wait StopEvent::poll_impl(int fd, int timeout_ms) const noexcept {
    // fd = -1: poll игнорирует запись, ждём только событие
    pollfd fds[2] = {{m_fd, POLLIN, 0}, {fd, POLLIN, 0}};
    for (;;) {
        int rc = ::poll(fds, 2, timeout_ms);
        if (rc < 0) {
            if (errno == EINTR) continue;
            return Wait::ERROR;
        }
        if (rc == 0) return Wait::TIMEOUT;
        if (fds[0].revents & POLLIN) return Wait::STOP;
        if (fds[1].revents & POLLIN) return Wait::READY;
        if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            errno = (fds[1].revents & POLLNVAL) ? EBADF : EIO;
            return Wait::ERROR;
        }
    }
}
