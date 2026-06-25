#include "server.hpp"

#include <linux/ip.h>
#include <sys/syslog.h>
#include <unistd.h>

#include <boost/program_options.hpp>
#include <csignal>
#include <cstring>
#include <iostream>

#include "../share/os.hpp"

VPNServer::VPNServer(std::string_view tun_name, std::string_view tun_ip, std::size_t port, std::size_t mtu, std::string_view key)
    : m_crypto{key}, m_tun_name(tun_name), m_tun_ip(tun_ip), m_port(port), m_mtu{mtu} {
    m_external_iface = Os().get_default_interface();
}

VPNServer::~VPNServer() { stop(); }

bool VPNServer::init() {
    if (!m_tun.open(m_tun_name, m_tun_ip, m_mtu)) {
        syslog(LOG_ERR, "Не удалось создать TUN-устройство");
        return false;
    }

    Os().setup_server_routes(m_tun_name, m_external_iface, m_port);

    m_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (m_udp_fd < 0) {
        syslog(LOG_ERR, "Не удалось создать UDP-сокет: %s", strerror(errno));
        return false;
    }

    int reuse = 1;
    setsockopt(m_udp_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(m_port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(m_udp_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        syslog(LOG_ERR, "Не удалось забиндить UDP-сокет: %s", strerror(errno));
        return false;
    }

    Os().tune_udp_socket(m_udp_fd);

    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    syslog(LOG_INFO, "VPN-сервер инициализирован на порту %zu", m_port);
    syslog(LOG_INFO, "Хост: %s, внешний интерфейс: %s", hostname, m_external_iface.c_str());
    return true;
}

void VPNServer::run() {
    syslog(LOG_INFO, "Запуск VPN-сервера...");
    m_tun_to_udp_thread = std::thread([this]() { tun_to_udp_loop(); });
    m_udp_to_tun_thread = std::thread([this]() { udp_to_tun_loop(); });
    m_cleanup_thread = std::thread([this]() { cleanup_loop(); });
    syslog(LOG_INFO, "VPN-сервер запущен");

    uint64_t last_to = 0, last_from = 0;
    while (m_running) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        if (!m_running) break;
        uint64_t to = m_packets_to_clients.load();
        uint64_t from = m_packets_from_clients.load();
        syslog(LOG_DEBUG, "Статистика: TUN->клиентам=%lu (+%lu), клиенты->TUN=%lu (+%lu), клиентов=%zu", to, to - last_to, from, from - last_from,
               m_clients.size());
        last_to = to;
        last_from = from;
    }
}

void VPNServer::stop() {
    if (!m_running.exchange(false)) return;
    if (m_udp_fd >= 0) {
        shutdown(m_udp_fd, SHUT_RDWR);
        ::close(m_udp_fd);
        m_udp_fd = -1;
    }
    m_tun.close();
    if (m_tun_to_udp_thread.joinable()) m_tun_to_udp_thread.join();
    if (m_udp_to_tun_thread.joinable()) m_udp_to_tun_thread.join();
    if (m_cleanup_thread.joinable()) m_cleanup_thread.join();
    syslog(LOG_INFO, "VPN-сервер остановлен");
}

void VPNServer::tun_to_udp_loop() {
    char plain_buffer[BUFFER_SIZE];
    char encrypted_buffer[BUFFER_SIZE + 128];
    int tun_fd = m_tun.get_fd();

    while (m_running) {
        ssize_t n = ::read(tun_fd, plain_buffer, BUFFER_SIZE);
        if (n <= 0) {
            if (n < 0 && errno != EINTR && m_running) {
                syslog(LOG_ERR, "Ошибка чтения TUN: %s", strerror(errno));
            }
            if (n == 0 || (n < 0 && errno != EINTR)) break;
            continue;
        }

        if (n < (ssize_t)sizeof(struct iphdr)) continue;

        struct iphdr* ip = (struct iphdr*)plain_buffer;
        uint32_t dest = ip->daddr;

        sockaddr_in client_addr;
        bool found = false;
        {
            std::lock_guard<std::mutex> lk(m_clients_mutex);
            auto it = m_clients.find(dest);
            if (it != m_clients.end()) {
                client_addr = it->second.addr;
                found = true;
            }
        }

        if (!found) continue;

        std::size_t encrypted_size = 0;
        if (!m_crypto.encrypt(plain_buffer, static_cast<std::size_t>(n), encrypted_buffer, encrypted_size)) {
            continue;
        }

        ssize_t sent = ::sendto(m_udp_fd, encrypted_buffer, encrypted_size, 0, (sockaddr*)&client_addr, sizeof(client_addr));
        if (sent > 0) {
            m_packets_to_clients.fetch_add(1, std::memory_order_relaxed);
        } else if (sent < 0 && errno != EINTR && errno != EAGAIN && m_running) {
            syslog(LOG_ERR, "sendto клиенту: %s", strerror(errno));
        }
    }
}

void VPNServer::udp_to_tun_loop() {
    char encrypted_buffer[BUFFER_SIZE + 128];
    char plain_buffer[BUFFER_SIZE];
    int tun_fd = m_tun.get_fd();
    sockaddr_in peer{};
    socklen_t peer_len = sizeof(peer);

    while (m_running) {
        peer_len = sizeof(peer);
        ssize_t n = ::recvfrom(m_udp_fd, encrypted_buffer, sizeof(encrypted_buffer), 0, (sockaddr*)&peer, &peer_len);
        if (n <= 0) {
            if (n < 0 && errno != EINTR && m_running) {
                syslog(LOG_ERR, "Ошибка recvfrom: %s", strerror(errno));
            }
            if (n == 0) continue;
            if (n < 0 && errno != EINTR) break;
            continue;
        }

        std::size_t plain_size = 0;
        if (!m_crypto.decrypt(encrypted_buffer, static_cast<std::size_t>(n), plain_buffer, plain_size)) {
            continue;
        }

        if (plain_size < sizeof(struct iphdr)) continue;

        struct iphdr* ip = (struct iphdr*)plain_buffer;
        uint32_t src = ip->saddr;

        if ((src & htonl(0xFFFFFF00)) != htonl(0xC0A8C800)) {
            continue;
        }

        {
            std::lock_guard<std::mutex> lk(m_clients_mutex);
            auto it = m_clients.find(src);
            if (it == m_clients.end()) {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &src, ip_str, INET_ADDRSTRLEN);
                syslog(LOG_INFO, "Новый клиент: %s с %s:%d", ip_str, inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
                m_clients[src] = {peer, std::chrono::steady_clock::now()};
            } else {
                it->second.addr = peer;
                it->second.last_seen = std::chrono::steady_clock::now();
            }
        }

        ssize_t written = ::write(tun_fd, plain_buffer, plain_size);
        if (written > 0) {
            m_packets_from_clients.fetch_add(1);
        } else if (written < 0 && errno != EINTR && m_running) {
            syslog(LOG_ERR, "Ошибка записи в TUN: %s", strerror(errno));
        }
    }
}

void VPNServer::cleanup_loop() {
    while (m_running) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        if (!m_running) break;

        auto now = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> lk(m_clients_mutex);
        for (auto it = m_clients.begin(); it != m_clients.end();) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last_seen);
            if (elapsed.count() > 60) {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &it->first, ip_str, INET_ADDRSTRLEN);
                syslog(LOG_WARNING, "Удалён неактивный клиент: %s", ip_str);
                it = m_clients.erase(it);
            } else {
                ++it;
            }
        }
    }
}

static VPNServer* g_server = nullptr;
namespace po = boost::program_options;

int main(int argc, char* argv[]) {
    Os().init_syslog("vpn-server", LOG_INFO);
    signal(SIGINT, [](int) {
        syslog(LOG_INFO, "Получен сигнал SIGINT");
        if (g_server) g_server->stop();
        exit(EXIT_SUCCESS);
    });
    signal(SIGTERM, [](int) {
        syslog(LOG_INFO, "Получен сигнал SIGTERM");
        if (g_server) g_server->stop();
        exit(EXIT_SUCCESS);
    });
    signal(SIGPIPE, SIG_IGN);

    if (geteuid() != 0) {
        syslog(LOG_ERR, "Сервер должен быть запущен от имени root");
        return EXIT_FAILURE;
    }

    if (sodium_init() < 0) {
        syslog(LOG_ERR, "Не удалось инициализировать libsodium");
        return EXIT_FAILURE;
    }

    int port = 0;
    int mtu = 1420;
    std::string tun_name;
    std::string tun_ip;
    std::string key;

    po::options_description desc("Параметры VPN-сервера");
    desc.add_options()("help,h", "показать справку")("port,p", po::value<int>(&port)->required(), "UDP-порт для прослушивания")(
        "mtu,m", po::value<int>(&mtu)->default_value(1420), "MTU TUN-интерфейса")(
        "tun-name,n", po::value<std::string>(&tun_name)->default_value("tun0"), "имя TUN-интерфейса")(
        "tun-ip,i", po::value<std::string>(&tun_ip)->default_value("192.168.200.1"), "IP-адрес TUN-интерфейса")(
        "key,k", po::value<std::string>(&key)->required(), "общий ключ шифрования");

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);

        if (vm.count("help")) {
            std::cout << desc << std::endl;
            return EXIT_SUCCESS;
        }

        po::notify(vm);
    } catch (const po::error& e) {
        std::cerr << "Ошибка параметров: " << e.what() << "\n\n" << desc << std::endl;
        syslog(LOG_ERR, "Ошибка параметров: %s", e.what());
        return EXIT_FAILURE;
    }

    if (port <= 0 || port > 65535) {
        std::cerr << "Недопустимый порт: " << port << std::endl;
        syslog(LOG_ERR, "Недопустимый порт: %d", port);
        return EXIT_FAILURE;
    }
    if (mtu < 576 || mtu > 65535) {
        std::cerr << "Недопустимый MTU: " << mtu << std::endl;
        syslog(LOG_ERR, "Недопустимый MTU: %d", mtu);
        return EXIT_FAILURE;
    }

    syslog(LOG_INFO, "Запуск VPN-сервера: port=%d, mtu=%d, tun=%s/%s", port, mtu, tun_name.c_str(), tun_ip.c_str());

    VPNServer server(tun_name, tun_ip, port, mtu, key);
    g_server = &server;

    if (!server.init()) {
        syslog(LOG_ERR, "Не удалось инициализировать сервер");
        return EXIT_FAILURE;
    }
    server.run();

    Os().close_syslog();
    return EXIT_SUCCESS;
}
