#include "device.hpp"

#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "command.hpp"
#include "log.hpp"

TunDevice::~TunDevice() { close(); }

void TunDevice::close() noexcept {
    if (m_fd >= 0) {
        ::close(m_fd);
        m_fd = -1;
    }
}

bool TunDevice::open(const std::string& name, const std::string& ip, std::size_t mtu) {
    close();

    ifreq ifr{};
    // имя должно поместиться вместе с завершающим нулём, иначе ядро прочитает имя без терминатора
    if (name.empty() || name.size() >= sizeof(ifr.ifr_name)) {
        log_msg(LOG_ERR, "Недопустимое имя TUN-интерфейса \"{}\": от 1 до {} символов", name, sizeof(ifr.ifr_name) - 1);
        return false;
    }

    int fd = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        log_msg(LOG_ERR, "Не удалось открыть TUN-устройство: {}", errno_str(errno));
        return false;
    }

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    std::memcpy(ifr.ifr_name, name.data(), name.size());

    if (::ioctl(fd, TUNSETIFF, &ifr) < 0) {
        log_msg(LOG_ERR, "Ошибка ioctl TUNSETIFF для {}: {}", name, errno_str(errno));
        ::close(fd);
        return false;
    }
    m_fd = fd;

    // интерфейс не persistent: при закрытии дескриптора ядро удаляет его вместе с адресом и маршрутами
    const std::string mtu_str = std::to_string(mtu);
    if (run_command({"ip", "addr", "add", ip + "/24", "dev", name}) != 0 || run_command({"ip", "link", "set", "dev", name, "mtu", mtu_str}) != 0 ||
        run_command({"ip", "link", "set", "dev", name, "txqueuelen", "1000"}) != 0 || run_command({"ip", "link", "set", "dev", name, "up"}) != 0) {
        log_msg(LOG_ERR, "Не удалось настроить TUN-интерфейс {}", name);
        close();
        return false;
    }
    log_msg(LOG_INFO, "TUN-устройство {} создано с IP {}, MTU {}", name, ip, mtu);
    return true;
}
