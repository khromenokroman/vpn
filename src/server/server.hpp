#pragma once

#include <netinet/in.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>

#include "share/crypto.hpp"
#include "share/device.hpp"
#include "share/log.hpp"
#include "share/replay.hpp"
#include "share/routing.hpp"
#include "share/signal_fd.hpp"
#include "share/stop_event.hpp"

/**
 * @brief VPN-сервер: TUN-интерфейс, UDP-сокет и таблица клиентов.
 *
 * Потоки: TUN -> UDP (поиск клиента по адресу назначения), UDP -> TUN (регистрация клиента по keep-alive,
 * проверка повторов) и очистка неактивных клиентов. Остановка через StopEvent, дескрипторы закрываются только
 * после завершения потоков.
 */
class VPNServer {
   public:
    /**
     * @param tun_name имя TUN-интерфейса
     * @param tun_ip адрес сервера в туннеле
     * @param external_iface внешний интерфейс для NAT; пустой - интерфейс маршрута по умолчанию
     * @param port UDP-порт
     * @param mtu MTU TUN-интерфейса
     * @param key общий секрет
     */
    VPNServer(std::string_view tun_name, std::string_view tun_ip, std::string_view external_iface, std::uint16_t port, std::size_t mtu,
              std::string_view key);
    ~VPNServer();

    VPNServer(const VPNServer&) = delete;
    VPNServer& operator=(const VPNServer&) = delete;

    /** @brief Создаёт TUN, настраивает NAT и сокет. @return false при ошибке (причина в syslog) */
    bool init();

    /**
     * @brief Запускает потоки и ждёт сигнал завершения, раз в 30 с пишет статистику.
     * @param signals заблокированные сигналы завершения
     * @return true - остановлен сигналом, false - аварийно остановился рабочий поток
     */
    bool run(const SignalFd& signals);

    /** @brief Останавливает и дожидается потоков, закрывает дескрипторы; повторный вызов безопасен. */
    void stop() noexcept;

   private:
    struct ClientInfo {
        PeerState peer; ///< сессия клиента и окно номеров
        std::chrono::steady_clock::time_point last_seen;
        sockaddr_in addr;
    };

    void tun_to_udp_loop();
    void udp_to_tun_loop();
    void cleanup_loop();
    void log_stats();

    /**
     * @brief Проверяет пакет клиента на повтор и обновляет его адрес; клиента создаёт только keep-alive.
     * @param tun_ip адрес клиента в туннеле
     * @param header заголовок пакета
     * @param keep_alive_time_ns время из keep-alive; nullopt для данных
     * @param from адрес, с которого пришёл пакет
     * @return true - пакет принят
     */
    bool accept_from_client(std::uint32_t tun_ip, const PacketHeader& header, std::optional<std::int64_t> keep_alive_time_ns,
                            const sockaddr_in& from);
    /** @brief Отвечает клиенту своим keep-alive: так клиент узнаёт сессию сервера. */
    void send_keep_alive(const sockaddr_in& to);
    /** @brief Пишет в журнал причину отказа, не чаще раза в минуту для каждой причины. */
    void log_rejected(PeerState::Verdict v, std::uint32_t tun_ip, const sockaddr_in& from, std::optional<std::int64_t> keep_alive_time_ns);

    std::unordered_map<std::uint32_t, ClientInfo> m_clients;
    std::unique_ptr<NatRules> m_nat;
    std::mutex m_clients_mutex;

    std::thread m_tun_to_udp_thread;
    std::thread m_udp_to_tun_thread;
    std::thread m_cleanup_thread;

    std::string m_tun_name;
    std::string m_tun_ip;
    std::string m_external_iface;

    Crypto m_crypto;
    TxSession m_tx;
    LogThrottle m_skew_log{std::chrono::seconds(60)};
    LogThrottle m_stale_log{std::chrono::seconds(60)};
    LogThrottle m_old_protocol_log{std::chrono::seconds(60)};
    StopEvent m_stop;
    TunDevice m_tun;

    std::atomic<std::uint64_t> m_packets_to_clients{0};
    std::atomic<std::uint64_t> m_packets_from_clients{0};
    std::atomic<std::uint64_t> m_rejected{0};
    std::uint64_t m_last_to = 0;
    std::uint64_t m_last_from = 0;
    std::size_t m_mtu;

    std::uint32_t m_tun_ip_be = 0;
    int m_udp_fd = -1;
    std::uint16_t m_port;
    bool m_stopped = false;
};
