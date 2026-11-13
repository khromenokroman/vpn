#include <arpa/inet.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <sstream>
#include <string>

#include "share/command.hpp"
#include "share/net.hpp"
#include "share/packet.hpp"
#include "share/routing.hpp"

using ::testing::ElementsAre;

namespace {

const char* const ROUTE_HEADER = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n";

std::uint32_t ip(const char* text) {
    in_addr a{};
    EXPECT_EQ(::inet_pton(AF_INET, text, &a), 1) << text;
    return a.s_addr;
}

/** @brief IPv4-заголовок 20 байт с адресами. */
std::array<char, 20> ipv4_header(const char* src, const char* dst) {
    std::array<char, 20> h{};
    h[0] = 0x45;
    std::uint32_t s = ip(src), d = ip(dst);
    std::memcpy(h.data() + 12, &s, 4);
    std::memcpy(h.data() + 16, &d, 4);
    return h;
}

} // namespace

/**
 * @brief Из /proc/net/route выбирается маршрут по умолчанию с наименьшей метрикой; шлюз
 * переводится из %08X (сетевой порядок байт в little-endian записи) в точечную запись.
 */
TEST(DefaultRoute, PicksLowestMetric) {
    std::string table = std::string(ROUTE_HEADER) +
                        "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
                        "eth0\t00000000\t0158A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
                        "eth0\t0058A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
    std::istringstream in(table);
    auto r = parse_default_route(in);
    ASSERT_TRUE(r.has_value()) << "таблица:\n" << table;
    EXPECT_EQ(r->iface, "eth0") << "у eth0 метрика 100, у wlan0 600";
    EXPECT_EQ(r->gateway, "192.168.88.1") << "Gateway 0158A8C0";
}

/**
 * @brief Маршрут по умолчанию без шлюза (point-to-point, например ppp0) даёт пустой gateway.
 */
TEST(DefaultRoute, WithoutGateway) {
    std::istringstream in(std::string(ROUTE_HEADER) + "ppp0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n");
    auto r = parse_default_route(in);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->iface, "ppp0");
    EXPECT_EQ(r->gateway, "") << "флаг RTF_GATEWAY не установлен";
}

/**
 * @brief Нет маршрута по умолчанию или он опущен (нет RTF_UP): nullopt.
 */
TEST(DefaultRoute, Missing) {
    std::istringstream only_net(std::string(ROUTE_HEADER) + "eth0\t0058A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n");
    EXPECT_FALSE(parse_default_route(only_net).has_value()) << "только маршрут сети 192.168.88.0/24";
    std::istringstream down(std::string(ROUTE_HEADER) + "eth0\t00000000\t0158A8C0\t0002\t0\t0\t100\t00000000\t0\t0\t0\n");
    EXPECT_FALSE(parse_default_route(down).has_value()) << "флаги 0002: шлюз есть, RTF_UP нет";
    std::istringstream empty("");
    EXPECT_FALSE(parse_default_route(empty).has_value()) << "пустой файл";
}

/**
 * @brief Имя интерфейса уходит аргументом в ip/iptables: допустимы только безопасные символы,
 * без '-' в начале (иначе это ключ) и короче IFNAMSIZ.
 */
TEST(Ifname, Validation) {
    for (const char* good : {"tun0", "eth0", "enp3s0", "wg-vpn", "br_lan", "eth0.100", "abcdefghijklmno"}) {
        EXPECT_TRUE(is_valid_ifname(good)) << "имя \"" << good << "\" должно приниматься";
    }
    for (const char* bad : {"", "-j", "tun0;reboot", "tun 0", "a/b", "abcdefghijklmnop", ".", "..", "tun$(id)"}) {
        EXPECT_FALSE(is_valid_ifname(bad)) << "имя \"" << bad << "\" должно отвергаться";
    }
}

/**
 * @brief Адрес сервера проверяется до любых команд: строка с shell-символами не IPv4.
 */
TEST(Ipv4, ParseAndFormat) {
    EXPECT_EQ(parse_ipv4("10.0.0.1"), ip("10.0.0.1"));
    for (const char* bad : {"", "1.2.3", "1.2.3.4; rm -rf /", "256.1.1.1", "example.com", "::1"}) {
        EXPECT_FALSE(parse_ipv4(bad).has_value()) << "\"" << bad << "\" не IPv4";
    }
    EXPECT_EQ(ipv4_to_string(ip("192.168.200.7")), "192.168.200.7");
    EXPECT_EQ(subnet24_cidr(ip("192.168.200.7")), "192.168.200.0/24");
    EXPECT_TRUE(same_subnet24(ip("192.168.200.1"), ip("192.168.200.254")));
    EXPECT_FALSE(same_subnet24(ip("192.168.200.1"), ip("192.168.201.1")));
}

/**
 * @brief Адреса берутся только из IPv4-пакета с корректной длиной заголовка; IPv6, обрезанный
 * пакет и IHL больше размера отвергаются (раньше проверялась только длина).
 */
TEST(Packet, ParseIpv4) {
    auto h = ipv4_header("192.168.200.2", "8.8.8.8");
    auto a = parse_ipv4_packet(h.data(), h.size());
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->src, ip("192.168.200.2"));
    EXPECT_EQ(a->dst, ip("8.8.8.8"));

    EXPECT_FALSE(parse_ipv4_packet(h.data(), 19)) << "19 байт меньше заголовка";
    auto v6 = h;
    v6[0] = 0x60;
    EXPECT_FALSE(parse_ipv4_packet(v6.data(), v6.size())) << "версия 6";
    auto long_ihl = h;
    long_ihl[0] = 0x46;
    EXPECT_FALSE(parse_ipv4_packet(long_ihl.data(), long_ihl.size())) << "IHL=6 (24 байта) при пакете 20 байт";
    auto short_ihl = h;
    short_ihl[0] = 0x44;
    EXPECT_FALSE(parse_ipv4_packet(short_ihl.data(), short_ihl.size())) << "IHL=4 меньше минимума";
}

/**
 * @brief Keep-alive: туда и обратно с адресом и временем отправителя (в том числе отрицательным
 * и с установленным старшим байтом), это служебный пакет, а не IPv4, и он короче заголовка IPv4.
 */
TEST(Packet, KeepAlive) {
    for (std::int64_t t : {std::int64_t{1763060000123456789}, std::int64_t{0}, std::int64_t{-1}, std::int64_t{0x7F00000000000001}}) {
        SCOPED_TRACE("time_ns=" + std::to_string(t));
        auto ka = make_keep_alive(ip("192.168.200.5"), t);
        EXPECT_TRUE(is_control_packet(ka.data(), ka.size()));
        EXPECT_FALSE(parse_ipv4_packet(ka.data(), ka.size()));
        EXPECT_LT(ka.size(), IPV4_HEADER_MIN);
        auto parsed = parse_keep_alive(ka.data(), ka.size());
        ASSERT_TRUE(parsed);
        EXPECT_EQ(parsed->tun_ip, ip("192.168.200.5"));
        EXPECT_EQ(parsed->time_ns, t);
    }

    auto ka = make_keep_alive(ip("192.168.200.5"), 1);
    EXPECT_EQ(static_cast<unsigned char>(ka[15]), 1) << "время big-endian: младший байт последний";
    EXPECT_FALSE(parse_keep_alive(ka.data(), ka.size() - 1)) << "обрезан";
    EXPECT_FALSE(parse_keep_alive(ka.data(), 8)) << "keep-alive до 0.5.0.0 (8 байт, без времени)";
    auto other_type = ka;
    other_type[1] = 0x02;
    EXPECT_FALSE(parse_keep_alive(other_type.data(), other_type.size())) << "неизвестный тип 0x02";
    auto h = ipv4_header("192.168.200.2", "8.8.8.8");
    EXPECT_FALSE(is_control_packet(h.data(), h.size())) << "IPv4 не служебный";
}

/**
 * @brief Правила NAT сервера: ответы снаружи в туннель только по conntrack, добавление и удаление
 * отличаются только операцией (иначе удаление при остановке не найдёт правило).
 */
TEST(Routing, ServerNatRules) {
    auto rules = server_nat_rules("tun0", "eth0", "192.168.200.0/24", 51820);
    ASSERT_EQ(rules.size(), 4u);
    EXPECT_THAT(rules[0].add_argv(),
                ElementsAre("iptables", "-w", "-t", "nat", "-A", "POSTROUTING", "-s", "192.168.200.0/24", "-o", "eth0", "-j", "MASQUERADE"));
    EXPECT_THAT(rules[0].delete_argv(),
                ElementsAre("iptables", "-w", "-t", "nat", "-D", "POSTROUTING", "-s", "192.168.200.0/24", "-o", "eth0", "-j", "MASQUERADE"));
    EXPECT_THAT(rules[2].add_argv(), ElementsAre("iptables", "-w", "-A", "FORWARD", "-i", "eth0", "-o", "tun0", "-m", "conntrack", "--ctstate",
                                                 "RELATED,ESTABLISHED", "-j", "ACCEPT"));
    EXPECT_THAT(rules[3].add_argv(), ElementsAre("iptables", "-w", "-I", "INPUT", "1", "-p", "udp", "--dport", "51820", "-j", "ACCEPT"));
    EXPECT_THAT(rules[3].delete_argv(), ElementsAre("iptables", "-w", "-D", "INPUT", "-p", "udp", "--dport", "51820", "-j", "ACCEPT"));
}

/**
 * @brief Клиент не трогает маршрут по умолчанию: две половины /1 через TUN и маршрут до сервера
 * через исходный шлюз; удаление в обратном порядке.
 */
TEST(Routing, ClientRoutes) {
    auto add = client_route_add_cmds("203.0.113.10", DefaultRoute{"eth0", "192.168.88.1"}, "tun0");
    ASSERT_EQ(add.size(), 3u);
    EXPECT_THAT(add[0], ElementsAre("ip", "route", "replace", "203.0.113.10/32", "via", "192.168.88.1", "dev", "eth0"));
    EXPECT_THAT(add[1], ElementsAre("ip", "route", "replace", "0.0.0.0/1", "dev", "tun0"));
    EXPECT_THAT(add[2], ElementsAre("ip", "route", "replace", "128.0.0.0/1", "dev", "tun0"));
    for (const auto& cmd : add) {
        EXPECT_THAT(command_to_string(cmd), ::testing::Not(::testing::HasSubstr("default"))) << "маршрут по умолчанию не меняется";
    }

    auto ptp = client_route_add_cmds("203.0.113.10", DefaultRoute{"ppp0", ""}, "tun0");
    EXPECT_THAT(ptp[0], ElementsAre("ip", "route", "replace", "203.0.113.10/32", "dev", "ppp0")) << "маршрут по умолчанию без шлюза";

    auto del = client_route_del_cmds("203.0.113.10", "tun0");
    ASSERT_EQ(del.size(), 3u);
    EXPECT_THAT(del[2], ElementsAre("ip", "route", "del", "203.0.113.10/32"));
}

/**
 * @brief Команда запускается без shell: аргумент с ';' и '$()' доходит до программы одной строкой,
 * код завершения возвращается, отсутствующая программа даёт -1.
 */
TEST(Command, NoShell) {
    EXPECT_EQ(run_command({"sh", "-c", "test \"$1\" = 'a; touch /tmp/pwned $(id)'", "sh", "a; touch /tmp/pwned $(id)"}, true), 0)
        << "аргумент должен прийти без разбора shell";
    EXPECT_EQ(run_command({"sh", "-c", "exit 3"}, true), 3);
    EXPECT_EQ(run_command({"/nonexistent/program"}, true), -1);
}
