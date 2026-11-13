#pragma once

#include <netinet/in.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

#include "share/crypto.hpp"
#include "share/device.hpp"
#include "share/log.hpp"
#include "share/packet.hpp"
#include "share/replay.hpp"
#include "share/routing.hpp"
#include "share/signal_fd.hpp"
#include "share/stop_event.hpp"

/**
 * @brief VPN-клиент: TUN-интерфейс, маршрут по умолчанию через туннель и UDP-сокет к серверу.
 *
 * Потоки: TUN -> UDP и UDP -> TUN. Главный поток шлёт keep-alive и пишет статистику. Пакеты сервера
 * принимаются после его ответного keep-alive и проверяются на повтор.
 * Остановка через StopEvent, дескрипторы закрываются только после завершения потоков.
 */
class VPNClient {
   public:
    /**
     * @param server_ip IPv4-адрес сервера
     * @param port UDP-порт сервера
     * @param mtu MTU TUN-интерфейса
     * @param tun_name имя TUN-интерфейса
     * @param tun_ip адрес клиента в туннеле
     * @param key общий секрет
     */
    VPNClient(std::string_view server_ip, std::uint16_t port, std::size_t mtu, std::string_view tun_name, std::string_view tun_ip,
              std::string_view key);
    ~VPNClient();

    VPNClient(const VPNClient&) = delete;
    VPNClient& operator=(const VPNClient&) = delete;

    /** @brief Создаёт TUN, меняет маршруты, открывает сокет. @return false при ошибке (причина в syslog) */
    bool init();

    /**
     * @brief Запускает потоки и ждёт сигнал завершения; каждые 10 с keep-alive, каждые 30 с статистика.
     * @param signals заблокированные сигналы завершения
     * @return true - остановлен сигналом, false - аварийно остановился рабочий поток
     */
    bool run(const SignalFd& signals);

    /** @brief Останавливает и дожидается потоков, закрывает дескрипторы; повторный вызов безопасен. */
    void stop() noexcept;

   private:
    void tun_to_udp_loop();
    void udp_to_tun_loop();
    void send_keep_alive();
    void log_stats();
    /** @brief Пишет в журнал, если сервер давно не отвечал на keep-alive; вызывается из run(). */
    void check_server_alive();
    /** @brief Пишет в журнал причину отказа в пакете сервера, не чаще раза в минуту для каждой причины. */
    void log_rejected(PeerState::Verdict v, const std::optional<KeepAlive>& ka);

    std::unique_ptr<ClientRoutes> m_routes;

    std::thread m_tun_to_udp_thread;
    std::thread m_udp_to_tun_thread;

    std::string m_tun_name;
    std::string m_tun_ip;
    std::string m_server_ip;

    Crypto m_crypto;
    TxSession m_tx;
    PeerState m_server; ///< только в потоке UDP -> TUN
    LogThrottle m_skew_log{std::chrono::seconds(60)};
    LogThrottle m_stale_log{std::chrono::seconds(60)};
    LogThrottle m_old_protocol_log{std::chrono::seconds(60)};
    StopEvent m_stop;
    TunDevice m_tun;
    sockaddr_in m_server_addr{};

    std::atomic<std::uint64_t> m_packets_sent{0};
    std::atomic<std::uint64_t> m_packets_received{0};
    std::atomic<std::uint64_t> m_rejected{0};
    /** @brief Время последнего принятого keep-alive сервера (или запуска), steady_clock::duration::count(). */
    std::atomic<std::int64_t> m_server_seen_ns{0};
    std::uint64_t m_last_sent = 0;
    std::uint64_t m_last_received = 0;
    std::size_t m_mtu;

    std::uint32_t m_tun_ip_be = 0;
    int m_udp_fd = -1;
    std::uint16_t m_port;
    bool m_stopped = false;
    bool m_server_lost_logged = false; ///< только в run()
};
