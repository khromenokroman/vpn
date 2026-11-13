#include "server.hpp"

#include <arpa/inet.h>
#include <linux/ip.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <boost/program_options.hpp>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>

#include "share/key_file.hpp"
#include "share/log.hpp"
#include "share/os.hpp"
#include "share/signal_fd.hpp"

namespace {

/** @brief Клиент удаляется после стольких секунд без пакетов. */
constexpr auto CLIENT_TIMEOUT = std::chrono::seconds(60);
/** @brief Период проверки неактивных клиентов. */
constexpr auto CLEANUP_INTERVAL = std::chrono::seconds(10);
/** @brief Период записи статистики. */
constexpr auto STATS_INTERVAL = std::chrono::seconds(30);
/** @brief Запас буфера шифротекста сверх BUFFER_SIZE, не меньше Crypto::overhead(). */
constexpr std::size_t CRYPTO_SLACK = 128;
static_assert(CRYPTO_SLACK >= Crypto::overhead());

std::string ip_to_string(std::uint32_t addr_be) {
    char buf[INET_ADDRSTRLEN] = {};
    ::inet_ntop(AF_INET, &addr_be, buf, sizeof(buf));
    return buf;
}

std::string endpoint_to_string(const sockaddr_in& addr) { return fmt::format("{}:{}", ip_to_string(addr.sin_addr.s_addr), ntohs(addr.sin_port)); }

} // namespace

VPNServer::VPNServer(std::string_view tun_name, std::string_view tun_ip, std::uint16_t port, std::size_t mtu, std::string_view key)
    : m_tun_name(tun_name), m_tun_ip(tun_ip), m_crypto{key}, m_mtu{mtu}, m_port(port) {}

VPNServer::~VPNServer() { stop(); }

bool VPNServer::init() {
    m_external_iface = Os().get_default_interface();

    if (!m_tun.open(m_tun_name, m_tun_ip, m_mtu)) {
        log_msg(LOG_ERR, "Не удалось создать TUN-устройство");
        return false;
    }

    Os().setup_server_routes(m_tun_name, m_external_iface, m_port);

    m_udp_fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (m_udp_fd < 0) {
        log_msg(LOG_ERR, "Не удалось создать UDP-сокет: {}", errno_str(errno));
        return false;
    }

    int reuse = 1;
    ::setsockopt(m_udp_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(m_port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (::bind(m_udp_fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
        log_msg(LOG_ERR, "Не удалось занять UDP-порт {}: {}", m_port, errno_str(errno));
        return false;
    }

    Os().tune_udp_socket(m_udp_fd);

    std::array<char, 256> hostname{};
    ::gethostname(hostname.data(), hostname.size() - 1);
    log_msg(LOG_INFO, "VPN-сервер инициализирован на порту {}, хост {}, внешний интерфейс {}", m_port, hostname.data(), m_external_iface);
    return true;
}

bool VPNServer::run(const SignalFd& signals) {
    log_msg(LOG_INFO, "Запуск VPN-сервера...");
    m_tun_to_udp_thread = std::thread([this]() { tun_to_udp_loop(); });
    m_udp_to_tun_thread = std::thread([this]() { udp_to_tun_loop(); });
    m_cleanup_thread = std::thread([this]() { cleanup_loop(); });
    log_msg(LOG_INFO, "VPN-сервер запущен");

    auto next_stats = std::chrono::steady_clock::now() + STATS_INTERVAL;
    for (;;) {
        auto timeout = std::chrono::duration_cast<std::chrono::milliseconds>(next_stats - std::chrono::steady_clock::now());
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
                log_stats();
                next_stats += STATS_INTERVAL;
                break;
            case StopEvent::Wait::ERROR:
                log_msg(LOG_ERR, "Ошибка ожидания сигнала: {}", errno_str(errno));
                return false;
        }
    }
}

void VPNServer::log_stats() {
    std::uint64_t to = m_packets_to_clients.load(std::memory_order_relaxed);
    std::uint64_t from = m_packets_from_clients.load(std::memory_order_relaxed);
    std::size_t clients;
    {
        std::lock_guard<std::mutex> lk(m_clients_mutex);
        clients = m_clients.size();
    }
    log_msg(LOG_DEBUG, "Статистика: TUN->клиентам={} (+{}), клиенты->TUN={} (+{}), клиентов={}", to, to - m_last_to, from, from - m_last_from,
            clients);
    m_last_to = to;
    m_last_from = from;
}

void VPNServer::stop() noexcept {
    if (m_stopped) return;
    m_stopped = true;
    m_stop.notify();
    if (m_tun_to_udp_thread.joinable()) m_tun_to_udp_thread.join();
    if (m_udp_to_tun_thread.joinable()) m_udp_to_tun_thread.join();
    if (m_cleanup_thread.joinable()) m_cleanup_thread.join();
    // дескрипторы закрываются только после join: иначе поток может обратиться к номеру fd,
    // который уже достался другому файлу
    if (m_udp_fd >= 0) {
        ::close(m_udp_fd);
        m_udp_fd = -1;
    }
    m_tun.close();
    log_msg(LOG_INFO, "VPN-сервер остановлен");
}

void VPNServer::tun_to_udp_loop() {
    std::array<char, BUFFER_SIZE> plain_buffer;
    std::array<char, BUFFER_SIZE + CRYPTO_SLACK> encrypted_buffer;
    const int tun_fd = m_tun.get_fd();

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

        sockaddr_in client_addr{};
        {
            std::lock_guard<std::mutex> lk(m_clients_mutex);
            auto it = m_clients.find(ip.daddr);
            if (it == m_clients.end()) continue;
            client_addr = it->second.addr;
        }

        std::size_t encrypted_size = 0;
        if (!m_crypto.encrypt(plain_buffer.data(), static_cast<std::size_t>(n), encrypted_buffer.data(), encrypted_size)) {
            continue;
        }

        ssize_t sent =
            ::sendto(m_udp_fd, encrypted_buffer.data(), encrypted_size, 0, reinterpret_cast<const sockaddr*>(&client_addr), sizeof(client_addr));
        if (sent >= 0) {
            m_packets_to_clients.fetch_add(1, std::memory_order_relaxed);
        } else if (errno != EINTR && errno != EAGAIN) {
            log_msg(LOG_ERR, "Ошибка отправки клиенту {}: {}", endpoint_to_string(client_addr), errno_str(errno));
        }
    }
    m_stop.notify();
}

void VPNServer::udp_to_tun_loop() {
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

        sockaddr_in peer{};
        socklen_t peer_len = sizeof(peer);
        ssize_t n = ::recvfrom(m_udp_fd, encrypted_buffer.data(), encrypted_buffer.size(), 0, reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (n < 0) {
            // ECONNREFUSED: ICMP port unreachable от клиента на прошлую отправку, сокет исправен
            if (errno == EINTR || errno == EAGAIN || errno == ECONNREFUSED) continue;
            log_msg(LOG_ERR, "Ошибка приёма UDP: {}", errno_str(errno));
            break;
        }

        std::size_t plain_size = 0;
        if (!m_crypto.decrypt(encrypted_buffer.data(), static_cast<std::size_t>(n), plain_buffer.data(), plain_size)) {
            continue;
        }
        if (plain_size < sizeof(iphdr)) continue;

        iphdr ip;
        std::memcpy(&ip, plain_buffer.data(), sizeof(ip));
        const std::uint32_t src = ip.saddr;

        // принимаются только адреса из 192.168.200.0/24
        if ((src & htonl(0xFFFFFF00)) != htonl(0xC0A8C800)) {
            continue;
        }

        {
            std::lock_guard<std::mutex> lk(m_clients_mutex);
            auto [it, inserted] = m_clients.try_emplace(src, ClientInfo{std::chrono::steady_clock::now(), peer});
            if (inserted) {
                log_msg(LOG_INFO, "Новый клиент: {} с {}", ip_to_string(src), endpoint_to_string(peer));
            } else {
                it->second.addr = peer;
                it->second.last_seen = std::chrono::steady_clock::now();
            }
        }

        ssize_t written = ::write(tun_fd, plain_buffer.data(), plain_size);
        if (written >= 0) {
            m_packets_from_clients.fetch_add(1, std::memory_order_relaxed);
        } else if (errno != EINTR && errno != EAGAIN) {
            // пакет, который ядро не приняло (например, битый заголовок), не повод останавливать сервер
            log_msg(LOG_WARNING, "Ошибка записи в TUN: {}", errno_str(errno));
        }
    }
    m_stop.notify();
}

void VPNServer::cleanup_loop() {
    while (m_stop.wait_for(CLEANUP_INTERVAL) == StopEvent::Wait::TIMEOUT) {
        auto now = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> lk(m_clients_mutex);
        for (auto it = m_clients.begin(); it != m_clients.end();) {
            if (now - it->second.last_seen > CLIENT_TIMEOUT) {
                log_msg(LOG_WARNING, "Удалён неактивный клиент: {}", ip_to_string(it->first));
                it = m_clients.erase(it);
            } else {
                ++it;
            }
        }
    }
}

namespace po = boost::program_options;

int main(int argc, char* argv[]) try {
    Os().init_syslog("vpn-server", LOG_INFO);
    // до создания потоков: маска наследуется, сигналы читаются только из signalfd
    SignalFd signals({SIGINT, SIGTERM});
    std::signal(SIGPIPE, SIG_IGN);

    int port = 0;
    int mtu = 1420;
    std::string tun_name;
    std::string tun_ip;
    std::string key_file;

    po::options_description desc("Параметры VPN-сервера", 200, 100);
    desc.add_options()("help,h", "показать справку")("port,p", po::value<int>(&port)->required(), "UDP-порт для прослушивания")(
        "mtu,m", po::value<int>(&mtu)->default_value(1420), "MTU TUN-интерфейса")(
        "tun-name,n", po::value<std::string>(&tun_name)->default_value("tun0"), "имя TUN-интерфейса")(
        "tun-ip,i", po::value<std::string>(&tun_ip)->default_value("192.168.200.1"), "IP-адрес TUN-интерфейса")(
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
        report_error("Сервер должен быть запущен от имени root");
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

    log_msg(LOG_INFO, "Запуск VPN-сервера {}: port={}, mtu={}, tun={}/{}", POMA_VPN_VERSION, port, mtu, tun_name, tun_ip);

    VPNServer server(tun_name, tun_ip, static_cast<std::uint16_t>(port), static_cast<std::size_t>(mtu), key.view());
    key = SecretBuffer(1);

    if (!server.init()) {
        report_error("Не удалось инициализировать сервер, подробности в журнале: journalctl -t vpn-server");
        return EXIT_FAILURE;
    }
    bool by_signal = server.run(signals);
    server.stop();
    Os().close_syslog();
    return by_signal ? EXIT_SUCCESS : EXIT_FAILURE;
} catch (const std::exception& e) {
    report_error("Аварийное завершение: {}", e.what());
    return EXIT_FAILURE;
}
