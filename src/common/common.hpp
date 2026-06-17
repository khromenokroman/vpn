#pragma once

#include <fcntl.h>
#include <fmt/format.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <unistd.h>

#include <atomic>
#include <boost/asio.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/bind/bind.hpp>
#include <boost/system/error_code.hpp>
#include <chrono>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <utility> // for std::exchange
#include <vector>

// Определяем макрос, чтобы избежать включения linux/if.h из if_tun.h
#define _LINUX_IF_H
#include <linux/if_tun.h>
#undef _LINUX_IF_H
#include <net/if.h>

#define BUFFER_SIZE 65536
#define VPN_MTU 1500
#define TUN_DEVICE "/dev/net/tun"

using boost::asio::ip::udp;

// Инициализация syslog
inline void initSyslog(const char* ident) { openlog(ident, LOG_PID, LOG_DAEMON); }

// Закрытие syslog
inline void closeSyslog() { closelog(); }

// Создание TUN устройства
int createTunDevice(std::string_view name, std::string_view ip) {
    struct ifreq ifr;
    int fd;

    if ((fd = open(TUN_DEVICE, O_RDWR)) < 0) {
        syslog(LOG_ERR, "Cannot open TUN device: %s", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    strncpy(ifr.ifr_name, name.data(), IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        syslog(LOG_ERR, "ioctl TUNSETIFF failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    system(::fmt::format("ip addr add {}/24 dev {}", ip, name).c_str());
    system(::fmt::format("ip link set {} up 2>/dev/null", name).c_str());
    system("echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null");
    syslog(LOG_INFO, "TUN device %s created with IP %s", name.data(), ip.data());
    return fd;
}

// Настройка маршрутов на клиенте
void setupClientRoutes(const std::string& tun_name = "tun0") {
    system("ip route del default 2>/dev/null");

    std::string cmd = "ip route add default via 192.168.200.1 dev " + tun_name + " 2>/dev/null";
    if (system(cmd.c_str()) != 0) {
        syslog(LOG_ERR, "Failed to set default route through VPN");
    } else {
        syslog(LOG_INFO, "Default route set through VPN on %s", tun_name.c_str());
    }
}

void setupServerRoutes(std::string_view tun_name, std::string_view external_iface, std::size_t vpn_port) {
    system(::fmt::format("iptables -t nat -D POSTROUTING -s 192.168.200.0/24 -o {} -j MASQUERADE", external_iface).c_str());
    system(::fmt::format("iptables -D FORWARD -i {} -o {} -j ACCEPT", tun_name, external_iface).c_str());
    system(::fmt::format("iptables -D FORWARD -i {} -o {} -j ACCEPT", external_iface, tun_name).c_str());
    system(::fmt::format("iptables -D INPUT -p udp --dport {} -j ACCEPT", vpn_port).c_str());
    system(::fmt::format("iptables -t nat -A POSTROUTING -s 192.168.200.0/24 -o {} -j MASQUERADE", external_iface).c_str());
    system(::fmt::format("iptables -A FORWARD -i {} -o {} -j ACCEPT", tun_name, external_iface).c_str());
    system(::fmt::format("iptables -A FORWARD -i {} -o {} -j ACCEPT", external_iface, tun_name).c_str());
    system(::fmt::format("iptables -I INPUT 1 -p udp --dport {} -j ACCEPT", vpn_port).c_str());
    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    syslog(LOG_INFO, "NAT and forwarding rules configured for %s through %s on UDP port %lu", tun_name.data(), external_iface.data(), vpn_port);
}

// Получение имени внешнего интерфейса
std::string getDefaultInterface() {
    FILE* fp = popen("ip route | grep default | awk '{print $5}'", "r");
    if (!fp) return "ens3";

    char buffer[256];
    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
        buffer[strcspn(buffer, "\n")] = 0;
        pclose(fp);
        return std::string(buffer);
    }

    pclose(fp);
    return "ens3";
}
std::string getDefaultGateway() {
    FILE* fp = popen("ip route | grep default | awk '{print $3}'", "r");
    if (!fp) return "";
    char buffer[256];
    if (fgets(buffer, sizeof(buffer), fp) != nullptr) {
        buffer[strcspn(buffer, "\n")] = 0;
        pclose(fp);
        return std::string(buffer);
    }
    pclose(fp);
    return "";
}

class TunDevice {
   public:
    explicit TunDevice() : m_fd(-1) {}

    bool open(std::string_view name, std::string_view ip) {
        m_fd = createTunDevice(name, ip);
        if (m_fd < 0) return false;
        return true;
    }

    void close() {
        if (m_fd >= 0) {
            ::close(m_fd);
            m_fd = -1;
        }
    }

    int getFd() const { return m_fd; }
    bool isOpen() const { return m_fd >= 0; }

    bool write(const char* data, size_t length) {
        if (m_fd < 0) return false;
        ssize_t written = ::write(m_fd, data, length);
        if (written < 0) {
            syslog(LOG_ERR, "TUN write failed: %s", strerror(errno));
            return false;
        }
        return written == static_cast<ssize_t>(length);
    }

   private:
    int m_fd;
};