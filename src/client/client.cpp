#include <arpa/inet.h>
#include <linux/ip.h>
#include <sys/socket.h>
#include <sys/syslog.h>

#include <atomic>
#include <boost/program_options.hpp>
#include <csignal>
#include <cstring>
#include <iostream>
#include <thread>

#include "../share/device.hpp"
#include "../share/os.hpp"

class VPNClient {
   private:
    int m_udp_fd = -1;
    TunDevice m_tun;
    sockaddr_in m_server_addr{};
    std::atomic<bool> m_running{true};

    std::thread m_tun_to_udp_thread;
    std::thread m_udp_to_tun_thread;
    std::string m_tun_name;
    std::string m_tun_ip;
    std::size_t m_port;
    std::size_t m_mtu;
    std::string m_server_ip;

    std::atomic<uint64_t> m_packets_sent{0};
    std::atomic<uint64_t> m_packets_received{0};

   public:
    VPNClient(std::string_view server_ip, std::size_t port, std::size_t mtu, std::string_view tun_name, std::string_view tun_ip)
        : m_tun_name{tun_name}, m_tun_ip{tun_ip}, m_port{port}, m_mtu{mtu}, m_server_ip{server_ip} {}

    ~VPNClient() { stop(); }

    bool init() {
        // 1. Создаём TUN
        if (!m_tun.open(m_tun_name, m_tun_ip, m_mtu)) {
            syslog(LOG_ERR, "Не удалось создать TUN-устройство");
            return false;
        }

        // 2. Запоминаем интерфейс и шлюз ДО изменения маршрутов
        std::string iface = Os().getDefaultInterface();
        std::string gateway = Os().getDefaultGateway();

        // 3. Добавляем маршрут до сервера через реальный интерфейс
        if (!gateway.empty() && !iface.empty()) {
            std::string cmd = "ip route add " + m_server_ip + " via " + gateway + " dev " + iface + " 2>/dev/null";
            if (system(cmd.c_str()) != 0) {
                syslog(LOG_WARNING, "Не удалось добавить маршрут до сервера");
            } else {
                syslog(LOG_INFO, "Маршрут до сервера %s через %s dev %s", m_server_ip.c_str(), gateway.c_str(), iface.c_str());
            }
        }

        // 4. Маршрут по умолчанию через tun0
        Os().setupClientRoutes();

        // 5. Создаём UDP-сокет
        m_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (m_udp_fd < 0) {
            syslog(LOG_ERR, "Не удалось создать UDP-сокет: %s", strerror(errno));
            return false;
        }

        // 6. Привязываем UDP-сокет к реальному интерфейсу (чтобы он шёл в обход VPN)
        if (!iface.empty()) {
            if (setsockopt(m_udp_fd, SOL_SOCKET, SO_BINDTODEVICE, iface.c_str(), iface.length()) < 0) {
                syslog(LOG_WARNING, "SO_BINDTODEVICE %s: %s", iface.c_str(), strerror(errno));
            } else {
                syslog(LOG_INFO, "UDP-сокет привязан к интерфейсу %s", iface.c_str());
            }
        }

        // 7. Увеличиваем буферы UDP-сокета
        Os().tuneUdpSocket(m_udp_fd);

        // 8. Адрес сервера
        m_server_addr.sin_family = AF_INET;
        m_server_addr.sin_port = htons(m_port);
        if (inet_pton(AF_INET, m_server_ip.c_str(), &m_server_addr.sin_addr) != 1) {
            syslog(LOG_ERR, "Недопустимый IP сервера: %s", m_server_ip.c_str());
            return false;
        }

        syslog(LOG_INFO, "VPN-клиент инициализирован, сервер %s:%zu", m_server_ip.c_str(), m_port);
        return true;
    }

    void run() {
        syslog(LOG_INFO, "Запуск VPN-клиента...");

        // Отправляем первый keep-alive, чтобы сервер узнал наш endpoint
        sendKeepAlive();

        m_tun_to_udp_thread = std::thread([this]() { tunToUdpLoop(); });
        m_udp_to_tun_thread = std::thread([this]() { udpToTunLoop(); });

        syslog(LOG_INFO, "VPN-клиент запущен");

        // Цикл статистики и keep-alive в главном потоке
        uint64_t last_sent = 0, last_recv = 0;
        int counter = 0;
        while (m_running) {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            if (!m_running) break;

            // Keep-alive каждые 10 секунд
            sendKeepAlive();

            // Статистика каждые 30 секунд
            if (++counter % 3 == 0) {
                uint64_t s = m_packets_sent.load();
                uint64_t r = m_packets_received.load();
                syslog(LOG_DEBUG, "Статистика: отправлено=%lu (+%lu), получено=%lu (+%lu)", s, s - last_sent, r, r - last_recv);
                last_sent = s;
                last_recv = r;
            }
        }
    }

    void stop() {
        if (!m_running.exchange(false)) return;
        if (m_udp_fd >= 0) {
            shutdown(m_udp_fd, SHUT_RDWR);
            ::close(m_udp_fd);
            m_udp_fd = -1;
        }
        m_tun.close();
        if (m_tun_to_udp_thread.joinable()) m_tun_to_udp_thread.join();
        if (m_udp_to_tun_thread.joinable()) m_udp_to_tun_thread.join();
        syslog(LOG_INFO, "VPN-клиент остановлен");
    }

   private:
    // Поток №1: TUN -> UDP
    void tunToUdpLoop() {
        char buffer[BUFFER_SIZE];
        int tun_fd = m_tun.getFd();
        while (m_running) {
            ssize_t n = ::read(tun_fd, buffer, BUFFER_SIZE);
            if (n <= 0) {
                if (n < 0 && errno != EINTR && m_running) {
                    syslog(LOG_ERR, "Ошибка чтения из TUN: %s", strerror(errno));
                }
                if (n == 0 || (n < 0 && errno != EINTR)) break;
                continue;
            }
            if (n < (ssize_t)sizeof(struct iphdr)) continue;

            // Проверка: не отправлять пакеты на сам туннель
            struct iphdr* ip = (struct iphdr*)buffer;
            if (ip->daddr == inet_addr("192.168.200.1") || ip->daddr == inet_addr("192.168.200.2")) {
                continue;
            }

            ssize_t sent = ::sendto(m_udp_fd, buffer, n, 0, (sockaddr*)&m_server_addr, sizeof(m_server_addr));
            if (sent > 0) {
                m_packets_sent.fetch_add(1, std::memory_order_relaxed);
            } else if (sent < 0 && errno != EINTR && errno != EAGAIN) {
                if (m_running) syslog(LOG_ERR, "sendto UDP: %s", strerror(errno));
            }
        }
    }

    // Поток №2: UDP -> TUN
    void udpToTunLoop() {
        char buffer[BUFFER_SIZE];
        int tun_fd = m_tun.getFd();
        while (m_running) {
            ssize_t n = ::recv(m_udp_fd, buffer, BUFFER_SIZE, 0);
            if (n <= 0) {
                if (n < 0 && errno != EINTR && m_running) {
                    syslog(LOG_ERR, "Ошибка чтения UDP: %s", strerror(errno));
                }
                if (n == 0 || (n < 0 && errno != EINTR)) break;
                continue;
            }
            if (n == 0) continue; // пустой keep-alive от сервера

            ssize_t written = ::write(tun_fd, buffer, n);
            if (written > 0) {
                m_packets_received.fetch_add(1, std::memory_order_relaxed);
            } else if (written < 0 && errno != EINTR && m_running) {
                syslog(LOG_ERR, "Ошибка записи в TUN: %s", strerror(errno));
            }
        }
    }

    void sendKeepAlive() {
        const char dummy = 0;
        ::sendto(m_udp_fd, &dummy, 0, 0, (sockaddr*)&m_server_addr, sizeof(m_server_addr));
    }
};

static VPNClient* g_client = nullptr;
namespace po = boost::program_options;

int main(int argc, char* argv[]) {
    Os().initSyslog("vpn-client", LOG_INFO);
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

    std::string server_ip;
    int port = 0;
    int mtu = 1420;
    std::string tun_name;
    std::string tun_ip;

    po::options_description desc("Параметры VPN-клиента");
    desc.add_options()("help,h", "показать справку")("server,s", po::value<std::string>(&server_ip)->required(), "IP-адрес VPN-сервера")(
        "port,p", po::value<int>(&port)->required(), "UDP-порт VPN-сервера")("mtu,m", po::value<int>(&mtu)->default_value(1420),
                                                                             "MTU TUN-интерфейса")(
        "tun-name,n", po::value<std::string>(&tun_name)->default_value("tun0"), "имя TUN-интерфейса")(
        "tun-ip,i", po::value<std::string>(&tun_ip)->default_value("192.168.200.2"), "IP-адрес TUN-интерфейса");

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

    syslog(LOG_INFO, "Запуск VPN-клиента: server=%s:%d, mtu=%d, tun=%s/%s", server_ip.c_str(), port, mtu, tun_name.c_str(), tun_ip.c_str());

    VPNClient client(server_ip, port, mtu, tun_name, tun_ip);
    g_client = &client;

    if (!client.init()) {
        syslog(LOG_ERR, "Не удалось инициализировать клиент");
        return EXIT_FAILURE;
    }
    client.run();

    Os().closeSyslog();
    return EXIT_SUCCESS;
}