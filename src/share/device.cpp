#include "device.hpp"

#include <fcntl.h>
#include <fmt/format.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>

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

    std::system(fmt::format("ip addr add {}/24 dev {}", ip, name).c_str());
    std::system(fmt::format("ip link set {} mtu {}", name, mtu).c_str());
    std::system(fmt::format("ip link set {} txqueuelen 1000", name).c_str());
    std::system(fmt::format("ip link set {} up 2>/dev/null", name).c_str());
    std::system("echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null");
    log_msg(LOG_INFO, "TUN-устройство {} создано с IP {}, MTU {}", name, ip, mtu);
    return true;
}
