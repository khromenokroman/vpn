#pragma once

#include <cstddef>
#include <cstdint>
#include <istream>
#include <optional>
#include <string>
#include <string_view>

/** @brief Размер буфера пакета: максимальный IP-пакет. */
inline constexpr std::size_t BUFFER_SIZE = 65536;
/** @brief Желаемый размер буферов UDP-сокета. */
inline constexpr int UDP_SOCKET_BUF_SIZE = 8 * 1024 * 1024;

/**
 * @brief Маршрут по умолчанию.
 */
struct DefaultRoute {
    std::string iface;   ///< интерфейс
    std::string gateway; ///< шлюз; пустой, если маршрут без шлюза (point-to-point)
};

/**
 * @brief Находит маршрут по умолчанию в формате /proc/net/route (с наименьшей метрикой среди поднятых).
 * @param in содержимое /proc/net/route
 * @return маршрут или nullopt, если его нет
 */
std::optional<DefaultRoute> parse_default_route(std::istream& in);

/** @brief Маршрут по умолчанию из /proc/net/route. */
std::optional<DefaultRoute> get_default_route();

/**
 * @brief Проверяет имя сетевого интерфейса: 1..15 символов из [A-Za-z0-9_.-], не начинается с '-'.
 *
 * Имя передаётся аргументом ip/iptables; с '-' в начале оно было бы принято за ключ.
 */
bool is_valid_ifname(std::string_view name);

/**
 * @brief Разбирает IPv4-адрес в точечной записи.
 * @return адрес в сетевом порядке байт или nullopt
 */
std::optional<std::uint32_t> parse_ipv4(const std::string& text);

/** @brief IPv4-адрес в сетевом порядке байт в точечную запись. */
std::string ipv4_to_string(std::uint32_t addr_be);

/** @brief Подсеть /24 адреса в виде "a.b.c.0/24" (сеть туннеля). */
std::string subnet24_cidr(std::uint32_t addr_be);

/**
 * @brief Увеличивает буферы UDP-сокета (SO_*BUFFORCE от root, иначе в пределах net.core.*mem_max).
 * @param fd сокет
 * @param size желаемый размер в байтах
 */
void tune_udp_socket(int fd, int size = UDP_SOCKET_BUF_SIZE);

/**
 * @brief Включает net.ipv4.ip_forward.
 * @return false, если не удалось записать (причина в syslog)
 */
bool enable_ip_forward();
