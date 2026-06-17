#include <boost/asio.hpp>

#include "../common/common.hpp"

class VPNServer {
   private:
    boost::asio::io_context io_context;
    udp::socket udp_socket;
    udp::endpoint remote_endpoint;
    std::unique_ptr<TunDevice> tun_device;
    std::atomic<bool> running;
    std::string m_tun_name;
    std::string m_tun_ip;
    std::size_t m_port;
    std::map<std::string, udp::endpoint> clients;
    std::map<std::string, std::chrono::steady_clock::time_point> client_last_seen;
    std::array<char, BUFFER_SIZE> udp_buffer;

    std::thread io_thread;
    std::thread tun_thread;
    std::string m_external_iface;

   public:
    VPNServer(std::string_view tun_name, std::string_view tun_ip, std::size_t port)
        : io_context(), udp_socket(io_context, udp::endpoint(udp::v4(), port)), running(true), m_tun_name{tun_name}, m_tun_ip{tun_ip}, m_port{port} {
        m_external_iface = getDefaultInterface();
        tun_device = std::make_unique<TunDevice>();
    }

    ~VPNServer() {
        stop();
        closeSyslog();
    }

    bool init() {
        if (!tun_device->open(m_tun_name, m_tun_ip)) {
            syslog(LOG_ERR, "Не удалось создать TUN-устройство");
            return false;
        }
        setupServerRoutes(m_tun_name, m_external_iface, m_port);
        char hostname[256];
        gethostname(hostname, sizeof(hostname));
        syslog(LOG_INFO, "VPN-сервер инициализирован на порту %zu", m_port);
        syslog(LOG_INFO, "Имя хоста: %s, внешний интерфейс: %s", hostname, m_external_iface.c_str());
        return true;
    }

    void run() {
        syslog(LOG_INFO, "Запуск VPN-сервера...");
        tun_thread = std::thread([this]() { tunReadLoop(); });
        startUdpRead();
        startCleanupTimer();
        io_thread = std::thread([this]() { io_context.run(); });
        syslog(LOG_INFO, "VPN-сервер запущен");
    }

    void stop() {
        running = false;
        io_context.stop();
        if (io_thread.joinable()) io_thread.join();
        if (tun_thread.joinable()) tun_thread.join();
        udp_socket.close();
        tun_device->close();
        syslog(LOG_INFO, "VPN-сервер остановлен");
    }

   private:
    void tunReadLoop() {
        char buffer[BUFFER_SIZE];
        while (running) {
            int n = read(tun_device->getFd(), buffer, BUFFER_SIZE);
            if (n > 0) {
                std::vector<char> data(buffer, buffer + n);
                boost::asio::post(io_context, [this, data]() { this->onTunData(data.data(), data.size()); });
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                if (running) syslog(LOG_ERR, "Ошибка чтения из TUN: %s", strerror(errno));
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    void startUdpRead() {
        if (!running) return;
        udp_socket.async_receive_from(boost::asio::buffer(udp_buffer), remote_endpoint, [this](const boost::system::error_code& ec, size_t bytes) {
            if (ec) {
                if (ec != boost::asio::error::operation_aborted) syslog(LOG_ERR, "Ошибка приёма UDP-пакета: %s", ec.message().c_str());
                return;
            }
            if (bytes > 0) {
                syslog(LOG_DEBUG, "Получено UDP-байт: %zu", bytes);
                this->onUdpData(udp_buffer.data(), bytes, remote_endpoint);
            }
            if (running) startUdpRead();
        });
    }

    void startCleanupTimer() {
        auto timer = std::make_shared<boost::asio::steady_timer>(io_context, std::chrono::seconds(10));
        timer->async_wait([this, timer](const boost::system::error_code& ec) {
            if (ec) return;
            this->cleanupClients();
            if (running) {
                timer->expires_after(std::chrono::seconds(10));
                timer->async_wait([this, timer](const boost::system::error_code& ec2) {
                    if (!ec2 && running) {
                        this->cleanupClients();
                        timer->expires_after(std::chrono::seconds(10));
                        this->startCleanupTimer();
                    }
                });
            }
        });
    }

    void onTunData(const char* data, size_t length) {
        if (length < sizeof(struct iphdr)) return;
        struct iphdr* ip_header = (struct iphdr*)data;
        char dest_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_header->daddr, dest_ip, INET_ADDRSTRLEN);
        std::string ip_str(dest_ip);
        auto it = clients.find(ip_str);
        if (it != clients.end()) {
            try {
                udp_socket.send_to(boost::asio::buffer(data, length), it->second);
                syslog(LOG_DEBUG, "Пакет отправлен клиенту %s, размер: %zu байт", dest_ip, length);
            } catch (const std::exception& e) {
                syslog(LOG_ERR, "Не удалось отправить пакет клиенту: %s", e.what());
            }
        } else {
            syslog(LOG_DEBUG, "Пакет для неизвестного клиента: %s", dest_ip);
        }
    }

    void onUdpData(const char* data, size_t length, const udp::endpoint& endpoint) {
        if (length < sizeof(struct iphdr)) return;
        struct iphdr* ip_header = (struct iphdr*)data;
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_header->saddr, src_ip, INET_ADDRSTRLEN);

        if (strncmp(src_ip, "192.168.200.", 12) == 0) {
            std::string client_ip(src_ip);
            if (clients.find(client_ip) == clients.end()) {
                syslog(LOG_INFO, "Подключён новый клиент: %s с адреса %s:%d", client_ip.c_str(), endpoint.address().to_string().c_str(), endpoint.port());
            }
            clients[client_ip] = endpoint;
            client_last_seen[client_ip] = std::chrono::steady_clock::now();
            if (!tun_device->write(data, length)) {
                syslog(LOG_ERR, "Не удалось записать пакет в TUN");
            } else {
                syslog(LOG_DEBUG, "Пакет успешно записан в TUN");
            }
            syslog(LOG_DEBUG, "Пакет от клиента %s обработан, размер: %zu байт", client_ip.c_str(), length);
        } else {
            syslog(LOG_DEBUG, "Пакет с недопустимым исходным IP: %s", src_ip);
        }
    }

    void cleanupClients() {
        auto now = std::chrono::steady_clock::now();
        auto it = client_last_seen.begin();
        while (it != client_last_seen.end()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second);
            if (elapsed.count() > 60) {
                syslog(LOG_WARNING, "Удаление неактивного клиента: %s", it->first.c_str());
                clients.erase(it->first);
                it = client_last_seen.erase(it);
            } else {
                ++it;
            }
        }
    }
};

int main(int argc, char* argv[]) {
    initSyslog("vpn-server");
    signal(SIGINT, [](int) {
        syslog(LOG_INFO, "Получен сигнал SIGINT");
        exit(EXIT_SUCCESS);
    });
    signal(SIGTERM, [](int) {
        syslog(LOG_INFO, "Получен сигнал SIGTERM");
        exit(EXIT_SUCCESS);
    });

    if (geteuid() != 0) {
        syslog(LOG_ERR, "Сервер должен быть запущен от имени root");
        return EXIT_FAILURE;
    }
    if (argc < 2) {
        syslog(LOG_ERR, "Не указан порт для прослушивания. Использование: %s <port>", argv[0]);
        return EXIT_FAILURE;
    }

    std::size_t port = atoll(argv[1]);
    if (port <= 0 || port > 65535) {
        syslog(LOG_ERR, "Недопустимый порт: %s", argv[1]);
        return EXIT_FAILURE;
    }

    syslog(LOG_INFO, "Запуск VPN-сервера на порту %zu", port);
    VPNServer server("tun0", "192.168.200.1", port);
    if (!server.init()) {
        syslog(LOG_ERR, "Не удалось инициализировать сервер");
        closelog();
        return EXIT_FAILURE;
    }
    server.run();
    while (true) std::this_thread::sleep_for(std::chrono::seconds(1));
    closeSyslog();
    return EXIT_SUCCESS;
}