#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

/**
 * @brief Разбор открытых пакетов туннеля.
 *
 * Внутри шифрования передаются IPv4-пакеты и служебные пакеты. Служебный пакет начинается с байта 0x00:
 * у IP-пакета старшие 4 бита первого байта - версия (4 или 6), поэтому 0x00 с IP не спутать.
 *
 * Keep-alive: [0x00][тип 0x01][0x00][0x00][IPv4 отправителя в туннеле, 4 байта][время отправителя, нс, int64 big-endian].
 * Клиент шлёт его раз в 10 с, сервер отвечает своим. По времени получатель отличает свежий keep-alive
 * от перехваченного раньше (см. PeerState).
 */

/** @brief Размер keep-alive в байтах. */
inline constexpr std::size_t KEEP_ALIVE_SIZE = 16;

/** @brief Размер заголовка IPv4 без опций. */
inline constexpr std::size_t IPV4_HEADER_MIN = 20;

/**
 * @brief Адреса IPv4-пакета в сетевом порядке байт.
 */
struct Ipv4Addrs {
    std::uint32_t src; ///< источник
    std::uint32_t dst; ///< назначение
};

/**
 * @brief Достаёт адреса из IPv4-пакета.
 * @param data пакет
 * @param size размер пакета
 * @return адреса или nullopt, если это не IPv4 (версия, длина заголовка, размер)
 */
std::optional<Ipv4Addrs> parse_ipv4_packet(const char* data, std::size_t size);

/** @brief Служебный ли пакет (первый байт 0x00). */
bool is_control_packet(const char* data, std::size_t size);

/**
 * @brief Содержимое keep-alive.
 */
struct KeepAlive {
    std::int64_t time_ns; ///< время отправителя, нс от эпохи Unix
    std::uint32_t tun_ip; ///< адрес отправителя в туннеле, сетевой порядок байт
};

/**
 * @brief Собирает keep-alive.
 * @param tun_ip адрес отправителя в туннеле, сетевой порядок байт
 * @param time_ns время отправителя, wall_clock_ns()
 */
std::array<char, KEEP_ALIVE_SIZE> make_keep_alive(std::uint32_t tun_ip, std::int64_t time_ns);

/**
 * @brief Разбирает keep-alive.
 * @return содержимое или nullopt, если это не keep-alive
 */
std::optional<KeepAlive> parse_keep_alive(const char* data, std::size_t size);

/** @brief Лежат ли адреса в одной подсети /24. */
bool same_subnet24(std::uint32_t a_be, std::uint32_t b_be);
