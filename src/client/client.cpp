#include <boost/asio.hpp>

#include "../common/common.hpp"

class VPNClient {
   private:
    boost::asio::io_context io_context;
    udp::socket udp_socket;
    udp::endpoint server_endpoint;
    std::unique_ptr<TunDevice> tun_device;
    std::atomic<bool> running;

    std::array<char, BUFFER_SIZE> udp_buffer;
    std::thread io_thread;
    std::thread tun_thread;

    std::string server_ip;
    int server_port;
    std::chrono::steady_clock::time_point last_keepalive;
    int packets_sent = 0, packets_received = 0;

   public:
    VPNClient(const std::string& server_ip_, int port) : udp_socket(io_context), running(true), server_ip(server_ip_), server_port(port) {
        tun_device = std::make_unique<TunDevice>();
    }

    ~VPNClient() {
        stop();
        closeSyslog();
    }

    bool init() {
        if (!tun_device->open("tun0", "192.168.200.2")) {
            syslog(LOG_ERR, "Не удалось создать TUN-устройство");
            return false;
        }
        setupClientRoutes();

        boost::system::error_code ec;
        auto ep = udp::endpoint(boost::asio::ip::address::from_string(server_ip, ec), server_port);
        if (ec) {
            syslog(LOG_ERR, "Недопустимый IP-адрес сервера: %s", server_ip.c_str());
            return false;
        }
        server_endpoint = ep;

        udp_socket.open(udp::v4());

        syslog(LOG_INFO, "VPN-клиент инициализирован, сервер: %s:%d", server_ip.c_str(), server_port);
        return true;
    }

    void run() {
        syslog(LOG_INFO, "Запуск VPN-клиента...");
        last_keepalive = std::chrono::steady_clock::now();

        tun_thread = std::thread([this]() { tunReadLoop(); });
        startUdpRead();
        startKeepAliveTimer();
        startStatsTimer();

        io_thread = std::thread([this]() { io_context.run(); });
        syslog(LOG_INFO, "VPN-клиент запущен");
    }

    void stop() {
        running = false;
        io_context.stop();
        if (io_thread.joinable()) io_thread.join();
        if (tun_thread.joinable()) tun_thread.join();
        udp_socket.close();
        tun_device->close();
        syslog(LOG_INFO, "VPN-клиент остановлен");
    }

   private:
    void tunReadLoop() {
        char buffer[BUFFER_SIZE];
        while (running) {
            int n = read(tun_device->getFd(), buffer, BUFFER_SIZE);
            if (n > 0) {
                std::vector<char> data(buffer, buffer + n);
                boost::asio::post(io_context, [this, data]() { this->onTunData(data.data(), data.size()); });
                syslog(LOG_DEBUG, "Прочитано из TUN байт: %d", n);
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                if (running) syslog(LOG_ERR, "Ошибка чтения из TUN: %s", strerror(errno));
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    void startUdpRead() {
        if (!running) return;
        udp_socket.async_receive(boost::asio::buffer(udp_buffer), [this](const boost::system::error_code& ec, size_t bytes) {
            if (ec) {
                if (ec != boost::asio::error::operation_aborted) syslog(LOG_ERR, "Ошибка приёма UDP-пакета: %s", ec.message().c_str());
                return;
            }
            if (bytes > 0) {
                this->onUdpData(udp_buffer.data(), bytes);
            }
            if (running) startUdpRead();
        });
    }

    void startKeepAliveTimer() {
        auto timer = std::make_shared<boost::asio::steady_timer>(io_context, std::chrono::seconds(10));
        timer->async_wait([this, timer](const boost::system::error_code& ec) {
            if (ec) return;
            this->sendKeepAlive();
            if (running) {
                timer->expires_after(std::chrono::seconds(10));
                timer->async_wait([this, timer](const boost::system::error_code& ec2) {
                    if (!ec2 && running) {
                        this->sendKeepAlive();
                        timer->expires_after(std::chrono::seconds(10));
                        this->startKeepAliveTimer();
                    }
                });
            }
        });
    }

    void startStatsTimer() {
        auto timer = std::make_shared<boost::asio::steady_timer>(io_context, std::chrono::seconds(30));
        timer->async_wait([this, timer](const boost::system::error_code& ec) {
            if (ec) return;
            this->printStats();
            if (running) {
                timer->expires_after(std::chrono::seconds(30));
                timer->async_wait([this, timer](const boost::system::error_code& ec2) {
                    if (!ec2 && running) {
                        this->printStats();
                        timer->expires_after(std::chrono::seconds(30));
                        this->startStatsTimer();
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

        // Не отправляем пакеты, направленные на наш туннельный шлюз или на нас самих
        if (strcmp(dest_ip, "192.168.200.1") != 0 && strcmp(dest_ip, "192.168.200.2") != 0) {
            try {
                auto sent_bytes = udp_socket.send_to(boost::asio::buffer(data, length), server_endpoint);
                packets_sent++;
                syslog(LOG_DEBUG, "Отправлено серверу байт: %zu", sent_bytes);
            } catch (const std::exception& e) {
                syslog(LOG_ERR, "Не удалось отправить пакет серверу: %s", e.what());
            }
        } else {
            syslog(LOG_DEBUG, "Отброшен пакет на локальный туннельный адрес: %s", dest_ip);
        }
    }

    void onUdpData(const char* data, size_t length) {
        if (length > 0) {
            tun_device->write(data, length);
            packets_received++;
            syslog(LOG_DEBUG, "Получено от сервера байт: %zu", length);
        }
    }

    void sendKeepAlive() {
        try {
            udp_socket.send_to(boost::asio::buffer("", 0), server_endpoint);
            last_keepalive = std::chrono::steady_clock::now();
        } catch (const std::exception& e) {
            syslog(LOG_ERR, "Ошибка отправки keep-alive: %s", e.what());
        }
    }

    void printStats() { syslog(LOG_INFO, "Статистика: отправлено=%d, получено=%d", packets_sent, packets_received); }
};

int main(int argc, char* argv[]) {
    initSyslog("vpn-client", LOG_INFO);
    signal(SIGINT, [](int) {
        syslog(LOG_INFO, "Получен сигнал SIGINT");
        exit(EXIT_SUCCESS);
    });
    signal(SIGTERM, [](int) {
        syslog(LOG_INFO, "Получен сигнал SIGTERM");
        exit(EXIT_SUCCESS);
    });

    if (geteuid() != 0) {
        syslog(LOG_ERR, "Клиент должен быть запущен от имени root");
        closelog();
        return EXIT_FAILURE;
    }

    if (argc < 2) {
        syslog(LOG_ERR, "Не указан IP-адрес сервера. Использование: %s <server_ip> [port]", argv[0]);
        closelog();
        return EXIT_FAILURE;
    }

    std::string server_ip = argv[1];
    int port;
    port = atoi(argv[2]);
    if (port <= 0 || port > 65535) {
        syslog(LOG_ERR, "Недопустимый порт: %s", argv[2]);
        closelog();
        return EXIT_FAILURE;
    }

    syslog(LOG_INFO, "Запуск VPN-клиента, подключение к %s:%d", server_ip.c_str(), port);

    VPNClient client(server_ip, port);
    if (!client.init()) {
        syslog(LOG_ERR, "Не удалось инициализировать клиент");
        closelog();
        return EXIT_FAILURE;
    }

    client.run();
    while (true) std::this_thread::sleep_for(std::chrono::seconds(1));
    closeSyslog();
    return EXIT_SUCCESS;
}