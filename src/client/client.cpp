#include <arpa/inet.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/syslog.h>

#include <atomic>
#include <boost/program_options.hpp>
#include <csignal>
#include <cstring>
#include <iostream>
#include <thread>

#include "../share/crypto.hpp"
#include "../share/device.hpp"
#include "../share/os.hpp"

static bool tcp_recv_all(int fd, void* buf, size_t len) {
    size_t received = 0;
    while (received < len) {
        ssize_t n = ::recv(fd, static_cast<char*>(buf) + received, len - received, 0);
        if (n <= 0) return false;
        received += static_cast<size_t>(n);
    }
    return true;
}

static bool tcp_send_all(int fd, const void* buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(fd, static_cast<const char*>(buf) + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

static bool recv_packet(int fd, char* buf, size_t& out_len) {
    uint16_t net_len;
    if (!tcp_recv_all(fd, &net_len, sizeof(net_len))) return false;
    uint16_t len = ntohs(net_len);
    if (len == 0) return false;
    if (!tcp_recv_all(fd, buf, len)) return false;
    out_len = len;
    return true;
}

static bool send_packet(int fd, const char* buf, size_t len) {
    if (len > UINT16_MAX) return false;
    uint16_t net_len = htons(static_cast<uint16_t>(len));
    return tcp_send_all(fd, &net_len, sizeof(net_len)) && tcp_send_all(fd, buf, len);
}

class VPNClient {
   private:
    int m_tcp_fd = -1;
    TunDevice m_tun;
    sockaddr_in m_server_addr{};
    std::atomic<bool> m_running{true};

    std::thread m_tun_to_tcp_thread;
    std::thread m_tcp_to_tun_thread;
    std::string m_tun_name;
    std::string m_tun_ip;
    std::size_t m_port;
    std::size_t m_mtu;
    std::string m_server_ip;
    Crypto m_crypto;
    std::atomic<uint64_t> m_packets_sent{0};
    std::atomic<uint64_t> m_packets_received{0};

   public:
    VPNClient(std::string_view server_ip, std::size_t port, std::size_t mtu, std::string_view tun_name, std::string_view tun_ip, std::string_view key)
        : m_tun_name{tun_name}, m_tun_ip{tun_ip}, m_port{port}, m_mtu{mtu}, m_server_ip{server_ip}, m_crypto{key} {}

    ~VPNClient() { stop(); }

    bool init() {
        if (!m_tun.open(m_tun_name, m_tun_ip, m_mtu)) {
            syslog(LOG_ERR, "Не удалось создать TUN-устройство");
            return false;
        }

        std::string iface = Os().get_default_interface();
        std::string gateway = Os().get_default_gateway();

        if (!gateway.empty() && !iface.empty()) {
            std::string cmd = "ip route add " + m_server_ip + " via " + gateway + " dev " + iface + " 2>/dev/null";
            if (system(cmd.c_str()) != 0) {
                syslog(LOG_WARNING, "Не удалось добавить маршрут до сервера");
            } else {
                syslog(LOG_INFO, "Маршрут до сервера %s через %s dev %s", m_server_ip.c_str(), gateway.c_str(), iface.c_str());
            }
        }

        Os().setup_client_routes();

        m_server_addr.sin_family = AF_INET;
        m_server_addr.sin_port = htons(m_port);
        if (inet_pton(AF_INET, m_server_ip.c_str(), &m_server_addr.sin_addr) != 1) {
            syslog(LOG_ERR, "Недопустимый IP сервера: %s", m_server_ip.c_str());
            return false;
        }

        m_tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (m_tcp_fd < 0) {
            syslog(LOG_ERR, "Не удалось создать TCP-сокет: %s", strerror(errno));
            return false;
        }

        if (!iface.empty()) {
            if (setsockopt(m_tcp_fd, SOL_SOCKET, SO_BINDTODEVICE, iface.c_str(), iface.length()) < 0) {
                syslog(LOG_WARNING, "SO_BINDTODEVICE %s: %s", iface.c_str(), strerror(errno));
            } else {
                syslog(LOG_INFO, "TCP-сокет привязан к интерфейсу %s", iface.c_str());
            }
        }

        int flag = 1;
        int keepidle = 30, keepintvl = 10, keepcnt = 3;
        setsockopt(m_tcp_fd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag));
        setsockopt(m_tcp_fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
        setsockopt(m_tcp_fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
        setsockopt(m_tcp_fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));

        if (::connect(m_tcp_fd, (sockaddr*)&m_server_addr, sizeof(m_server_addr)) < 0) {
            syslog(LOG_ERR, "Не удалось подключиться к серверу %s:%zu: %s",
                   m_server_ip.c_str(), m_port, strerror(errno));
            return false;
        }

        syslog(LOG_INFO, "VPN-клиент подключён к %s:%zu", m_server_ip.c_str(), m_port);
        return true;
    }

    void run() {
        syslog(LOG_INFO, "Запуск VPN-клиента...");

        m_tun_to_tcp_thread = std::thread([this]() { tun_to_tcp_loop(); });
        m_tcp_to_tun_thread = std::thread([this]() { tcp_to_tun_loop(); });

        syslog(LOG_INFO, "VPN-клиент запущен");

        uint64_t last_sent = 0, last_recv = 0;
        int counter = 0;
        while (m_running) {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            if (!m_running) break;

            if (++counter % 3 == 0) {
                uint64_t s = m_packets_sent.load();
                uint64_t r = m_packets_received.load();
                syslog(LOG_DEBUG, "Статистика: отправлено=%lu (+%lu), получено=%lu (+%lu)",
                       s, s - last_sent, r, r - last_recv);
                last_sent = s;
                last_recv = r;
            }
        }
    }

    void stop() {
        if (!m_running.exchange(false)) return;
        if (m_tcp_fd >= 0) {
            shutdown(m_tcp_fd, SHUT_RDWR);
            ::close(m_tcp_fd);
            m_tcp_fd = -1;
        }
        m_tun.close();
        if (m_tun_to_tcp_thread.joinable()) m_tun_to_tcp_thread.join();
        if (m_tcp_to_tun_thread.joinable()) m_tcp_to_tun_thread.join();
        syslog(LOG_INFO, "VPN-клиент остановлен");
    }

   private:
    void tun_to_tcp_loop() {
        char plain_buffer[BUFFER_SIZE];
        char encrypted_buffer[BUFFER_SIZE + 128];
        int tun_fd = m_tun.get_fd();

        while (m_running) {
            ssize_t n = ::read(tun_fd, plain_buffer, BUFFER_SIZE);
            if (n <= 0) {
                if (n < 0 && errno != EINTR && m_running)
                    syslog(LOG_ERR, "Ошибка чтения из TUN: %s", strerror(errno));
                if (n == 0 || (n < 0 && errno != EINTR)) break;
                continue;
            }

            if (n < (ssize_t)sizeof(struct iphdr)) continue;

            struct iphdr* ip = (struct iphdr*)plain_buffer;
            if ((ip->daddr & htonl(0xFFFFFF00)) == htonl(0xC0A8C800)) continue;

            std::size_t encrypted_size = 0;
            if (!m_crypto.encrypt(plain_buffer, static_cast<std::size_t>(n), encrypted_buffer, encrypted_size)) continue;

            if (!send_packet(m_tcp_fd, encrypted_buffer, encrypted_size)) {
                if (m_running) syslog(LOG_ERR, "Ошибка отправки на сервер: %s", strerror(errno));
                break;
            }
            m_packets_sent.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void tcp_to_tun_loop() {
        char encrypted_buffer[BUFFER_SIZE + 128];
        char plain_buffer[BUFFER_SIZE];
        int tun_fd = m_tun.get_fd();

        while (m_running) {
            size_t enc_size = 0;
            if (!recv_packet(m_tcp_fd, encrypted_buffer, enc_size)) {
                if (m_running) syslog(LOG_ERR, "Соединение с сервером потеряно");
                break;
            }

            std::size_t plain_size = 0;
            if (!m_crypto.decrypt(encrypted_buffer, enc_size, plain_buffer, plain_size)) continue;

            ssize_t written = ::write(tun_fd, plain_buffer, plain_size);
            if (written > 0) {
                m_packets_received.fetch_add(1, std::memory_order_relaxed);
            } else if (written < 0 && errno != EINTR && m_running) {
                syslog(LOG_ERR, "Ошибка записи в TUN: %s", strerror(errno));
            }
        }
    }
};

static VPNClient* g_client = nullptr;
namespace po = boost::program_options;

int main(int argc, char* argv[]) {
    Os().init_syslog("vpn-client", LOG_INFO);
    signal(SIGINT, [](int) {
        syslog(LOG_INFO, "Получен сигнал SIGINT");
        if (g_client) g_client->stop();
        exit(EXIT_SUCCESS);
    });
    signal(SIGTERM, [](int) {
        syslog(LOG_INFO, "Получен сигнал SIGTERM");
        if (g_client) g_client->stop();
        exit(EXIT_SUCCESS);
    });
    signal(SIGPIPE, SIG_IGN);

    if (geteuid() != 0) {
        syslog(LOG_ERR, "Клиент должен быть запущен от имени root");
        return EXIT_FAILURE;
    }

    if (sodium_init() < 0) {
        syslog(LOG_ERR, "Не удалось инициализировать libsodium");
        return EXIT_FAILURE;
    }

    std::string server_ip;
    int port = 0;
    int mtu = 1420;
    std::string tun_name;
    std::string tun_ip;
    std::string key;

    po::options_description desc("Параметры VPN-клиента");
    desc.add_options()("help,h", "показать справку")("server,s", po::value<std::string>(&server_ip)->required(), "IP-адрес VPN-сервера")(
        "port,p", po::value<int>(&port)->required(), "TCP-порт VPN-сервера")("mtu,m", po::value<int>(&mtu)->default_value(1420),
                                                                             "MTU TUN-интерфейса")(
        "tun-name,n", po::value<std::string>(&tun_name)->default_value("tun0"), "имя TUN-интерфейса")(
        "tun-ip,i", po::value<std::string>(&tun_ip)->default_value("192.168.200.2"), "IP-адрес TUN-интерфейса")(
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
        return EXIT_FAILURE;
    }

    syslog(LOG_INFO, "Запуск VPN-клиента: server=%s:%d, mtu=%d, tun=%s/%s",
           server_ip.c_str(), port, mtu, tun_name.c_str(), tun_ip.c_str());

    VPNClient client(server_ip, port, mtu, tun_name, tun_ip, key);
    g_client = &client;

    if (!client.init()) {
        syslog(LOG_ERR, "Не удалось инициализировать клиент");
        return EXIT_FAILURE;
    }
    client.run();

    Os().close_syslog();
    return EXIT_SUCCESS;
}
