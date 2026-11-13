#include "packet.hpp"

#include <arpa/inet.h>

#include <cstring>

namespace {

constexpr unsigned char CONTROL_MARK = 0x00;
constexpr unsigned char TYPE_KEEP_ALIVE = 0x01;

} // namespace

std::optional<Ipv4Addrs> parse_ipv4_packet(const char* data, std::size_t size) {
    if (size < IPV4_HEADER_MIN) return std::nullopt;
    auto first = static_cast<unsigned char>(data[0]);
    if ((first >> 4) != 4) return std::nullopt;
    std::size_t ihl = static_cast<std::size_t>(first & 0x0F) * 4;
    if (ihl < IPV4_HEADER_MIN || ihl > size) return std::nullopt;

    Ipv4Addrs addrs{};
    std::memcpy(&addrs.src, data + 12, sizeof(addrs.src));
    std::memcpy(&addrs.dst, data + 16, sizeof(addrs.dst));
    return addrs;
}

bool is_control_packet(const char* data, std::size_t size) { return size > 0 && static_cast<unsigned char>(data[0]) == CONTROL_MARK; }

std::array<char, KEEP_ALIVE_SIZE> make_keep_alive(std::uint32_t tun_ip, std::int64_t time_ns) {
    std::array<char, KEEP_ALIVE_SIZE> out{};
    out[0] = static_cast<char>(CONTROL_MARK);
    out[1] = static_cast<char>(TYPE_KEEP_ALIVE);
    std::memcpy(out.data() + 4, &tun_ip, sizeof(tun_ip));
    auto t = static_cast<std::uint64_t>(time_ns);
    for (int i = 15; i >= 8; --i) {
        out[i] = static_cast<char>(t & 0xFF);
        t >>= 8;
    }
    return out;
}

std::optional<KeepAlive> parse_keep_alive(const char* data, std::size_t size) {
    if (size != KEEP_ALIVE_SIZE || !is_control_packet(data, size) || static_cast<unsigned char>(data[1]) != TYPE_KEEP_ALIVE) {
        return std::nullopt;
    }
    KeepAlive ka{};
    std::memcpy(&ka.tun_ip, data + 4, sizeof(ka.tun_ip));
    std::uint64_t t = 0;
    for (int i = 8; i < 16; ++i) t = (t << 8) | static_cast<unsigned char>(data[i]);
    ka.time_ns = static_cast<std::int64_t>(t);
    return ka;
}

bool same_subnet24(std::uint32_t a_be, std::uint32_t b_be) { return (a_be & htonl(0xFFFFFF00u)) == (b_be & htonl(0xFFFFFF00u)); }
