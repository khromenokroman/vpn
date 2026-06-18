#pragma once

#include <fcntl.h>
#include <fmt/format.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

// Определяем макрос, чтобы избежать включения linux/if.h из if_tun.h
#define _LINUX_IF_H
#include <linux/if_tun.h>
#undef _LINUX_IF_H
#include <net/if.h>

#define BUFFER_SIZE 65536
#define VPN_MTU 1400
#define TUN_DEVICE "/dev/net/tun"
#define UDP_SOCKET_BUF_SIZE (8 * 1024 * 1024)

// Инициализация syslog
inline void initSyslog(const char* ident, int log_level) {
    openlog(ident, LOG_PID, LOG_DAEMON);
    setlogmask(LOG_UPTO(log_level));
}

inline void closeSyslog() { closelog(); }

// Увеличение буферов UDP-сокета (требует root)
inline void tuneUdpSocket(int fd, int buf_size = UDP_SOCKET_BUF_SIZE) {
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &buf_size, sizeof(buf_size)) < 0) {
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &buf_size, sizeof(buf_size)) < 0) {
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
    }
    int actual_rcv = 0, actual_snd = 0;
    socklen_t len = sizeof(int);
    getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &actual_rcv, &len);
    getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &actual_snd, &len);
    syslog(LOG_INFO, "UDP-сокет: SO_RCVBUF=%d, SO_SNDBUF=%d", actual_rcv, actual_snd);
}

// Создание TUN устройства
inline int createTunDevice(std::string_view name, std::string_view ip) {
    struct ifreq ifr;
    int fd;

    if ((fd = open(TUN_DEVICE, O_RDWR)) < 0) {
        syslog(LOG_ERR, "Не удалось открыть TUN-устройство: %s", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name.data(), IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        syslog(LOG_ERR, "Ошибка ioctl TUNSETIFF: %s", strerror(errno));
        close(fd);
        return -1;
    }

    system(::fmt::format("ip addr add {}/24 dev {}", ip, name).c_str());
    system(::fmt::format("ip link set {} mtu {}", name, VPN_MTU).c_str());
    system(::fmt::format("ip link set {} txqueuelen 1000", name).c_str());
    system(::fmt::format("ip link set {} up 2>/dev/null", name).c_str());
    system("echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null");
    syslog(LOG_INFO, "TUN-устройство %s создано с IP %s, MTU %d", name.data(), ip.data(), VPN_MTU);
    return fd;
}

inline void setupClientRoutes(const std::string& tun_name = "tun0") {
    system("ip route del default 2>/dev/null");
    std::string cmd = "ip route add default via 192.168.200.1 dev " + tun_name + " 2>/dev/null";
    if (system(cmd.c_str()) != 0) {
        syslog(LOG_ERR, "Не удалось установить маршрут по умолчанию через VPN");
    } else {
        syslog(LOG_INFO, "Маршрут по умолчанию установлен через %s", tun_name.c_str());
    }
}

inline void setupServerRoutes(std::string_view tun_name, std::string_view external_iface, std::size_t vpn_port) {
    system(::fmt::format("iptables -t nat -D POSTROUTING -s 192.168.200.0/24 -o {} -j MASQUERADE", external_iface).c_str());
    system(::fmt::format("iptables -D FORWARD -i {} -o {} -j ACCEPT", tun_name, external_iface).c_str());
    system(::fmt::format("iptables -D FORWARD -i {} -o {} -j ACCEPT", external_iface, tun_name).c_str());
    system(::fmt::format("iptables -D INPUT -p udp --dport {} -j ACCEPT", vpn_port).c_str());
    system(::fmt::format("iptables -t nat -A POSTROUTING -s 192.168.200.0/24 -o {} -j MASQUERADE", external_iface).c_str());
    system(::fmt::format("iptables -A FORWARD -i {} -o {} -j ACCEPT", tun_name, external_iface).c_str());
    system(::fmt::format("iptables -A FORWARD -i {} -o {} -j ACCEPT", external_iface, tun_name).c_str());
    system(::fmt::format("iptables -I INPUT 1 -p udp --dport {} -j ACCEPT", vpn_port).c_str());
    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    syslog(LOG_INFO, "Правила NAT настроены для %s через %s на порту %lu", tun_name.data(), external_iface.data(), vpn_port);
}

inline std::string getDefaultInterface() {
    FILE* fp = popen("ip route | grep default | awk '{print $5}'", "r");
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

inline std::string getDefaultGateway() {
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
    TunDevice() : m_fd(-1) {}

    bool open(std::string_view name, std::string_view ip) {
        m_fd = createTunDevice(name, ip);
        return m_fd >= 0;
    }

    void close() {
        if (m_fd >= 0) {
            ::close(m_fd);
            m_fd = -1;
        }
    }

    int getFd() const { return m_fd; }
    bool isOpen() const { return m_fd >= 0; }

   private:
    int m_fd;
};