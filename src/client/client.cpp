#include "client.hpp"

#include <arpa/inet.h>
#include <linux/ip.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <boost/program_options.hpp>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>

#include "share/key_file.hpp"
#include "share/log.hpp"
#include "share/os.hpp"

namespace {

/** @brief Период keep-alive: сервер забывает клиента через 60 с тишины. */
constexpr auto KEEP_ALIVE_INTERVAL = std::chrono::seconds(10);
/** @brief Статистика пишется каждый N-й keep-alive. */
constexpr unsigned STATS_EVERY = 3;
/** @brief Запас буфера шифротекста сверх BUFFER_SIZE, не меньше Crypto::overhead(). */
constexpr std::size_t CRYPTO_SLACK = 128;
static_assert(CRYPTO_SLACK >= Crypto::overhead());

} // namespace

VPNClient::VPNClient(std::string_view server_ip, std::uint16_t port, std::size_t mtu, std::string_view tun_name, std::string_view tun_ip,
                     std::string_view key)
    : m_tun_name{tun_name}, m_tun_ip{tun_ip}, m_server_ip{server_ip}, m_crypto{key}, m_mtu{mtu}, m_port{port} {}

VPNClient::~VPNClient() { stop(); }

bool VPNClient::init() {
    if (!m_tun.open(m_tun_name, m_tun_ip, m_mtu)) {
        log_msg(LOG_ERR, "Не удалось создать TUN-устройство");
        return false;
    }

    // интерфейс и шлюз запоминаются до смены маршрута по умолчанию
    std::string iface = Os().get_default_interface();
    std::string gateway = Os().get_default_gateway();

    // маршрут до сервера через реальный интерфейс, чтобы сам туннель не шёл в туннель
    if (!gateway.empty() && !iface.empty()) {
        std::string cmd = "ip route add " + m_server_ip + " via " + gateway + " dev " + iface + " 2>/dev/null";
        if (std::system(cmd.c_str()) != 0) {
            log_msg(LOG_WARNING, "Не удалось добавить маршрут до сервера");
        } else {
            log_msg(LOG_INFO, "Маршрут до сервера {} через {} dev {}", m_server_ip, gateway, iface);
        }
    }

    Os().setup_client_routes(m_tun_name);

    m_udp_fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (m_udp_fd < 0) {
        log_msg(LOG_ERR, "Не удалось создать UDP-сокет: {}", errno_str(errno));
        return false;
    }

    if (!iface.empty()) {
        if (::setsockopt(m_udp_fd, SOL_SOCKET, SO_BINDTODEVICE, iface.c_str(), iface.size()) < 0) {
            log_msg(LOG_WARNING, "SO_BINDTODEVICE {}: {}", iface, errno_str(errno));
        } else {
            log_msg(LOG_INFO, "UDP-сокет привязан к интерфейсу {}", iface);
        }
    }

    Os().tune_udp_socket(m_udp_fd);

    m_server_addr.sin_family = AF_INET;
    m_server_addr.sin_port = htons(m_port);
    if (::inet_pton(AF_INET, m_server_ip.c_str(), &m_server_addr.sin_addr) != 1) {
        log_msg(LOG_ERR, "Недопустимый IP сервера: {}", m_server_ip);
        return false;
    }

    log_msg(LOG_INFO, "VPN-клиент инициализирован, сервер {}:{}", m_server_ip, m_port);
    return true;
}

bool VPNClient::run(const SignalFd& signals) {
    log_msg(LOG_INFO, "Запуск VPN-клиента...");
    send_keep_alive();

    m_tun_to_udp_thread = std::thread([this]() { tun_to_udp_loop(); });
    m_udp_to_tun_thread = std::thread([this]() { udp_to_tun_loop(); });
    log_msg(LOG_INFO, "VPN-клиент запущен");

    unsigned ticks = 0;
    auto next_tick = std::chrono::steady_clock::now() + KEEP_ALIVE_INTERVAL;
    for (;;) {
        auto timeout = std::chrono::duration_cast<std::chrono::milliseconds>(next_tick - std::chrono::steady_clock::now());
        switch (m_stop.wait_readable(signals.get_fd(), std::max(timeout, std::chrono::milliseconds{0}))) {
            case StopEvent::Wait::READY: {
                int sig = signals.read_signal();
                const char* name = sig > 0 ? ::sigabbrev_np(sig) : nullptr;
                log_msg(LOG_INFO, "Получен сигнал SIG{}, остановка", name ? name : "?");
                return true;
            }
            case StopEvent::Wait::STOP:
                log_msg(LOG_ERR, "Рабочий поток остановился с ошибкой, завершение");
                return false;
            case StopEvent::Wait::TIMEOUT:
                send_keep_alive();
                if (++ticks % STATS_EVERY == 0) log_stats();
                next_tick += KEEP_ALIVE_INTERVAL;
                break;
            case StopEvent::Wait::ERROR:
                log_msg(LOG_ERR, "Ошибка ожидания сигнала: {}", errno_str(errno));
                return false;
        }
    }
}

void VPNClient::log_stats() {
    std::uint64_t s = m_packets_sent.load(std::memory_order_relaxed);
    std::uint64_t r = m_packets_received.load(std::memory_order_relaxed);
    log_msg(LOG_DEBUG, "Статистика: отправлено={} (+{}), получено={} (+{})", s, s - m_last_sent, r, r - m_last_received);
    m_last_sent = s;
    m_last_received = r;
}

void VPNClient::stop() noexcept {
    if (m_stopped) return;
    m_stopped = true;
    m_stop.notify();
    if (m_tun_to_udp_thread.joinable()) m_tun_to_udp_thread.join();
    if (m_udp_to_tun_thread.joinable()) m_udp_to_tun_thread.join();
    // дескрипторы закрываются только после join, см. VPNServer::stop
    if (m_udp_fd >= 0) {
        ::close(m_udp_fd);
        m_udp_fd = -1;
    }
    m_tun.close();
    log_msg(LOG_INFO, "VPN-клиент остановлен");
}

void VPNClient::tun_to_udp_loop() {
    std::array<char, BUFFER_SIZE> plain_buffer;
    std::array<char, BUFFER_SIZE + CRYPTO_SLACK> encrypted_buffer;
    const int tun_fd = m_tun.get_fd();
    const std::uint32_t skip1 = ::inet_addr("192.168.200.1");
    const std::uint32_t skip2 = ::inet_addr("192.168.200.2");
    const std::uint32_t skip3 = ::inet_addr("192.168.200.3");

    for (;;) {
        StopEvent::Wait w = m_stop.wait_readable(tun_fd);
        if (w == StopEvent::Wait::STOP) return;
        if (w == StopEvent::Wait::ERROR) {
            log_msg(LOG_ERR, "Ошибка ожидания TUN: {}", errno_str(errno));
            break;
        }

        ssize_t n = ::read(tun_fd, plain_buffer.data(), plain_buffer.size());
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            log_msg(LOG_ERR, "Ошибка чтения TUN: {}", errno_str(errno));
            break;
        }
        if (n < static_cast<ssize_t>(sizeof(iphdr))) continue;

        iphdr ip;
        std::memcpy(&ip, plain_buffer.data(), sizeof(ip));
        //@todo: надо фильтровать по сети
        if (ip.daddr == skip1 || ip.daddr == skip2 || ip.daddr == skip3) {
            continue;
        }

        std::size_t encrypted_size = 0;
        if (!m_crypto.encrypt(plain_buffer.data(), static_cast<std::size_t>(n), encrypted_buffer.data(), encrypted_size)) {
            continue;
        }

        ssize_t sent =
            ::sendto(m_udp_fd, encrypted_buffer.data(), encrypted_size, 0, reinterpret_cast<const sockaddr*>(&m_server_addr), sizeof(m_server_addr));
        if (sent >= 0) {
            m_packets_sent.fetch_add(1, std::memory_order_relaxed);
        } else if (errno != EINTR && errno != EAGAIN && errno != ECONNREFUSED) {
            log_msg(LOG_ERR, "Ошибка отправки на сервер: {}", errno_str(errno));
        }
    }
    m_stop.notify();
}

void VPNClient::udp_to_tun_loop() {
    std::array<char, BUFFER_SIZE + CRYPTO_SLACK> encrypted_buffer;
    std::array<char, BUFFER_SIZE> plain_buffer;
    const int tun_fd = m_tun.get_fd();

    for (;;) {
        StopEvent::Wait w = m_stop.wait_readable(m_udp_fd);
        if (w == StopEvent::Wait::STOP) return;
        if (w == StopEvent::Wait::ERROR) {
            log_msg(LOG_ERR, "Ошибка ожидания UDP: {}", errno_str(errno));
            break;
        }

        ssize_t n = ::recv(m_udp_fd, encrypted_buffer.data(), encrypted_buffer.size(), 0);
        if (n < 0) {
            // ECONNREFUSED: сервер ещё не запущен, ICMP port unreachable на прошлую отправку
            if (errno == EINTR || errno == EAGAIN || errno == ECONNREFUSED) continue;
            log_msg(LOG_ERR, "Ошибка приёма UDP: {}", errno_str(errno));
            break;
        }

        std::size_t plain_size = 0;
        if (!m_crypto.decrypt(encrypted_buffer.data(), static_cast<std::size_t>(n), plain_buffer.data(), plain_size)) {
            continue;
        }

        ssize_t written = ::write(tun_fd, plain_buffer.data(), plain_size);
        if (written >= 0) {
            m_packets_received.fetch_add(1, std::memory_order_relaxed);
        } else if (errno != EINTR && errno != EAGAIN) {
            log_msg(LOG_WARNING, "Ошибка записи в TUN: {}", errno_str(errno));
        }
    }
    m_stop.notify();
}

void VPNClient::send_keep_alive() {
    const char dummy = 0;
    ::sendto(m_udp_fd, &dummy, 0, 0, reinterpret_cast<const sockaddr*>(&m_server_addr), sizeof(m_server_addr));
}

namespace po = boost::program_options;

int main(int argc, char* argv[]) try {
    Os().init_syslog("vpn-client", LOG_INFO);
    // до создания потоков: маска наследуется, сигналы читаются только из signalfd
    SignalFd signals({SIGINT, SIGTERM});
    std::signal(SIGPIPE, SIG_IGN);

    std::string server_ip;
    int port = 0;
    int mtu = 1420;
    std::string tun_name;
    std::string tun_ip;
    std::string key_file;

    po::options_description desc("Параметры VPN-клиента", 200, 100);
    desc.add_options()("help,h", "показать справку")("server,s", po::value<std::string>(&server_ip)->required(), "IP-адрес VPN-сервера")(
        "port,p", po::value<int>(&port)->required(), "UDP-порт VPN-сервера")("mtu,m", po::value<int>(&mtu)->default_value(1420),
                                                                             "MTU TUN-интерфейса")(
        "tun-name,n", po::value<std::string>(&tun_name)->default_value("tun0"), "имя TUN-интерфейса")(
        "tun-ip,i", po::value<std::string>(&tun_ip)->default_value("192.168.200.2"), "IP-адрес TUN-интерфейса")(
        "key-file,k", po::value<std::string>(&key_file),
        "файл общего ключа (владелец root, права 0600); без параметра - $CREDENTIALS_DIRECTORY/vpn-key")("version,V", "показать версию");

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        if (vm.count("help")) {
            std::cout << desc << std::endl;
            return EXIT_SUCCESS;
        }
        if (vm.count("version")) {
            std::cout << POMA_VPN_VERSION << std::endl;
            return EXIT_SUCCESS;
        }
        po::notify(vm);
    } catch (const po::error& e) {
        std::cerr << "Ошибка параметров: " << e.what() << "\n\n" << desc << std::endl;
        log_msg(LOG_ERR, "Ошибка параметров: {}", e.what());
        return EXIT_FAILURE;
    }

    if (port <= 0 || port > 65535) {
        report_error("Недопустимый порт: {}", port);
        return EXIT_FAILURE;
    }
    if (mtu < 576 || mtu > 65535) {
        report_error("Недопустимый MTU: {}", mtu);
        return EXIT_FAILURE;
    }
    if (::geteuid() != 0) {
        report_error("Клиент должен быть запущен от имени root");
        return EXIT_FAILURE;
    }
    if (sodium_init() < 0) {
        report_error("Не удалось инициализировать libsodium");
        return EXIT_FAILURE;
    }

    SecretBuffer key(1);
    try {
        key = load_key(key_file);
    } catch (const KeyFileError& e) {
        report_error("{}", e.what());
        return EXIT_FAILURE;
    }

    log_msg(LOG_INFO, "Запуск VPN-клиента {}: server={}:{}, mtu={}, tun={}/{}", POMA_VPN_VERSION, server_ip, port, mtu, tun_name, tun_ip);

    VPNClient client(server_ip, static_cast<std::uint16_t>(port), static_cast<std::size_t>(mtu), tun_name, tun_ip, key.view());
    key = SecretBuffer(1);

    if (!client.init()) {
        report_error("Не удалось инициализировать клиент, подробности в журнале: journalctl -t vpn-client");
        return EXIT_FAILURE;
    }
    bool by_signal = client.run(signals);
    client.stop();
    Os().close_syslog();
    return by_signal ? EXIT_SUCCESS : EXIT_FAILURE;
} catch (const std::exception& e) {
    report_error("Аварийное завершение: {}", e.what());
    return EXIT_FAILURE;
}
