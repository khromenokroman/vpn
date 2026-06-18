#include "device.hpp"

#include <fcntl.h>
#include <fmt/format.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/syslog.h>
#include <unistd.h>

#include <cstdlib>

TunDevice::TunDevice() : m_fd(-1) {}

bool TunDevice::open(std::string_view name, std::string_view ip,std::size_t mtu) {
    m_fd = createTunDevice(name, ip, mtu);
    return m_fd >= 0;
}

void TunDevice::close() {
    if (m_fd >= 0) {
        ::close(m_fd);
        m_fd = -1;
    }
}

int TunDevice::getFd() const { return m_fd; }
bool TunDevice::isOpen() const { return m_fd >= 0; }
int TunDevice::createTunDevice(std::string_view name, std::string_view ip, std::size_t mtu) {
    struct ifreq ifr;
    int fd;

    if ((fd = ::open(m_tun_device.data(), O_RDWR)) < 0) {
        syslog(LOG_ERR, "Не удалось открыть TUN-устройство: %s", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name.data(), IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        syslog(LOG_ERR, "Ошибка ioctl TUNSETIFF: %s", strerror(errno));
        ::close(fd);
        return -1;
    }

    system(::fmt::format("ip addr add {}/24 dev {}", ip, name).c_str());
    system(::fmt::format("ip link set {} mtu {}", name, m_mtu).c_str());
    system(::fmt::format("ip link set {} txqueuelen 1000", name).c_str());
    system(::fmt::format("ip link set {} up 2>/dev/null", name).c_str());
    system("echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null");
    syslog(LOG_INFO, "TUN-устройство %s создано с IP %s, MTU %d", name.data(), ip.data(), mtu);
    return fd;
}
