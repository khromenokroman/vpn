#pragma once

#include <fcntl.h>
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
#include <thread>
#include <utility> // for std::exchange
#include <vector>

// Определяем макрос, чтобы избежать включения linux/if.h из if_tun.h
#define _LINUX_IF_H
#include <linux/if_tun.h>
#undef _LINUX_IF_H
#include <net/if.h>

#define BUFFER_SIZE 65536
#define VPN_PORT 51820
#define VPN_MTU 1500
#define TUN_DEVICE "/dev/net/tun"

using boost::asio::ip::udp;

// Инициализация syslog
inline void initSyslog(const char* ident) { openlog(ident, LOG_PID, LOG_DAEMON); }

// Закрытие syslog
inline void closeSyslog() { closelog(); }

// Создание TUN устройства
int createTunDevice(const std::string& name = "tun0", const std::string& ip = "192.168.200.2") {
    struct ifreq ifr;
    int fd;

    if ((fd = open(TUN_DEVICE, O_RDWR)) < 0) {
        syslog(LOG_ERR, "Cannot open TUN device: %s", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        syslog(LOG_ERR, "ioctl TUNSETIFF failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    // Настройка IP адреса
    std::string cmd = "ip addr add " + ip + "/24 dev " + name + " 2>/dev/null";
    system(cmd.c_str());

    cmd = "ip link set " + name + " up 2>/dev/null";
    system(cmd.c_str());

    // Включаем IP forwarding
    system("echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null");

    syslog(LOG_INFO, "TUN device %s created with IP %s", name.c_str(), ip.c_str());
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

// Настройка маршрутов на сервере
void setupServerRoutes(const std::string& tun_name = "tun0") {
    std::string cmd;
    cmd = "iptables -t nat -D POSTROUTING -s 192.168.200.0/24 -o ens3 -j MASQUERADE 2>/dev/null";
    system(cmd.c_str());
    cmd = "iptables -D FORWARD -i " + tun_name + " -o ens3 -j ACCEPT 2>/dev/null";
    system(cmd.c_str());
    cmd = "iptables -D FORWARD -i ens3 -o " + tun_name + " -j ACCEPT 2>/dev/null";
    system(cmd.c_str());

    cmd = "iptables -t nat -A POSTROUTING -s 192.168.200.0/24 -o ens3 -j MASQUERADE";
    if (system(cmd.c_str()) != 0) {
        syslog(LOG_ERR, "Failed to add NAT rule");
        return;
    }

    cmd = "iptables -A FORWARD -i " + tun_name + " -o ens3 -j ACCEPT";
    system(cmd.c_str());

    cmd = "iptables -A FORWARD -i ens3 -o " + tun_name + " -j ACCEPT";
    system(cmd.c_str());

    system("iptables -I INPUT 1 -p udp --dport 51820 -j ACCEPT");

    system("echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null");

    syslog(LOG_INFO, "NAT and forwarding rules configured for %s", tun_name.c_str());
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
// Класс для работы с TUN устройством (только открытие/закрытие/запись)
class TunDevice {
   private:
    int fd;

   public:
    TunDevice() : fd(-1) {}

    bool open(const std::string& name = "tun0", const std::string& ip = "192.168.200.2") {
        fd = createTunDevice(name, ip);
        if (fd < 0) return false;
        return true;
    }

    void close() {
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
        }
    }

    int getFd() const { return fd; }
    bool isOpen() const { return fd >= 0; }

    bool write(const char* data, size_t length) {
        if (fd < 0) return false;
        ssize_t written = ::write(fd, data, length);
        if (written < 0) {
            syslog(LOG_ERR, "TUN write failed: %s", strerror(errno));
            return false;
        }
        return written == static_cast<ssize_t>(length);
    }
};