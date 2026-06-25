#include "os.hpp"

#include <fmt/format.h>
#include <sys/socket.h>
#include <sys/syslog.h>

#include <string>
void Os::tune_udp_socket(int fd, int size) {
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &size, sizeof(size)) < 0) {
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &size, sizeof(size)) < 0) {
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
    }
    int actual_rcv = 0, actual_snd = 0;
    socklen_t len = sizeof(int);
    getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &actual_rcv, &len);
    getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &actual_snd, &len);
    syslog(LOG_INFO, "UDP-сокет: SO_RCVBUF=%d, SO_SNDBUF=%d", actual_rcv, actual_snd);
}
void Os::setup_client_routes(std::string_view tun_name) {
    system("ip route del default");
    syslog(LOG_INFO, "Удален маршрут по умолчанию");
    system(::fmt::format("ip route add default via 192.168.200.1 dev {}", tun_name).c_str());
    syslog(LOG_INFO, "Маршрут по умолчанию установлен через %s", tun_name.data());
}
void Os::setup_server_routes(std::string_view tun_name, std::string_view external_iface, std::size_t vpn_port) {
    system(::fmt::format("iptables -t nat -D POSTROUTING -s 192.168.200.0/24 -o {} -j MASQUERADE", external_iface).c_str());
    system(::fmt::format("iptables -D FORWARD -i {} -o {} -j ACCEPT", tun_name, external_iface).c_str());
    system(::fmt::format("iptables -D FORWARD -i {} -o {} -j ACCEPT", external_iface, tun_name).c_str());
    system(::fmt::format("iptables -D INPUT -p tcp --dport {} -j ACCEPT", vpn_port).c_str());
    system(::fmt::format("iptables -t nat -A POSTROUTING -s 192.168.200.0/24 -o {} -j MASQUERADE", external_iface).c_str());
    system(::fmt::format("iptables -A FORWARD -i {} -o {} -j ACCEPT", tun_name, external_iface).c_str());
    system(::fmt::format("iptables -A FORWARD -i {} -o {} -j ACCEPT", external_iface, tun_name).c_str());
    system(::fmt::format("iptables -I INPUT 1 -p tcp --dport {} -j ACCEPT", vpn_port).c_str());
    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    syslog(LOG_INFO, "Правила NAT настроены для %s через %s на порту %lu", tun_name.data(), external_iface.data(), vpn_port);
}
std::string Os::get_default_interface() {
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

std::string Os::get_default_gateway() {
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
void Os::init_syslog(const char* ident, int log_level) {
    openlog(ident, LOG_PID, LOG_DAEMON);
    setlogmask(LOG_UPTO(log_level));
}

void Os::close_syslog() { closelog(); }