#include "net.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <fstream>
#include <limits>
#include <sstream>

#include "log.hpp"

std::optional<DefaultRoute> parse_default_route(std::istream& in) {
    std::string line;
    std::getline(in, line); // заголовок

    std::optional<DefaultRoute> best;
    unsigned long best_metric = std::numeric_limits<unsigned long>::max();
    while (std::getline(in, line)) {
        std::istringstream ss(line);
        std::string iface;
        unsigned long dest = 0, gateway = 0, flags = 0, refcnt = 0, use = 0, metric = 0, mask = 0;
        ss >> iface >> std::hex >> dest >> gateway >> flags >> std::dec >> refcnt >> use >> metric >> std::hex >> mask;
        if (!ss || dest != 0 || mask != 0 || (flags & RTF_UP) == 0) continue;
        if (metric >= best_metric) continue;

        best_metric = metric;
        // ядро печатает адрес как %08X от значения в сетевом порядке байт, то есть это готовый s_addr
        best = DefaultRoute{iface, (flags & RTF_GATEWAY) ? ipv4_to_string(static_cast<std::uint32_t>(gateway)) : std::string{}};
    }
    return best;
}

std::optional<DefaultRoute> get_default_route() {
    std::ifstream in("/proc/net/route");
    if (!in) {
        log_msg(LOG_ERR, "Не удалось открыть /proc/net/route");
        return std::nullopt;
    }
    return parse_default_route(in);
}

bool is_valid_ifname(std::string_view name) {
    if (name.empty() || name.size() >= IFNAMSIZ || name.front() == '-') return false;
    for (char c : name) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
        if (!ok) return false;
    }
    return name != "." && name != "..";
}

std::optional<std::uint32_t> parse_ipv4(const std::string& text) {
    in_addr addr{};
    if (::inet_pton(AF_INET, text.c_str(), &addr) != 1) return std::nullopt;
    return addr.s_addr;
}

std::string ipv4_to_string(std::uint32_t addr_be) {
    char buf[INET_ADDRSTRLEN] = {};
    ::inet_ntop(AF_INET, &addr_be, buf, sizeof(buf));
    return buf;
}

std::string subnet24_cidr(std::uint32_t addr_be) { return ipv4_to_string(addr_be & htonl(0xFFFFFF00u)) + "/24"; }

void tune_udp_socket(int fd, int size) {
    if (::setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &size, sizeof(size)) < 0) {
        ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    }
    if (::setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &size, sizeof(size)) < 0) {
        ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
    }
    int actual_rcv = 0, actual_snd = 0;
    socklen_t len = sizeof(actual_rcv);
    ::getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &actual_rcv, &len);
    len = sizeof(actual_snd);
    ::getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &actual_snd, &len);
    log_msg(LOG_INFO, "UDP-сокет: SO_RCVBUF={}, SO_SNDBUF={}", actual_rcv, actual_snd);
}

bool enable_ip_forward() {
    int fd = ::open("/proc/sys/net/ipv4/ip_forward", O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        log_msg(LOG_ERR, "Не удалось открыть net.ipv4.ip_forward: {}", errno_str(errno));
        return false;
    }
    ssize_t n = ::write(fd, "1\n", 2);
    int err = errno;
    ::close(fd);
    if (n != 2) {
        log_msg(LOG_ERR, "Не удалось включить net.ipv4.ip_forward: {}", errno_str(err));
        return false;
    }
    return true;
}
