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
        // initSyslog("vpn-client");
        tun_device = std::make_unique<TunDevice>();
    }

    ~VPNClient() {
        stop();
        closeSyslog();
    }

    bool init() {
        if (!tun_device->open("tun0", "192.168.200.2")) {
            syslog(LOG_ERR, "Failed to create TUN device");
            return false;
        }
        // Устанавливаем маршруты (пока не добавляем default, а только добавляем маршрут к серверу через реальный интерфейс)
        // Но сначала нам нужно получить шлюз и интерфейс по умолчанию.
        std::string iface = getDefaultInterface();
        std::string gateway = getDefaultGateway();
        if (!gateway.empty() && !iface.empty()) {
            std::string cmd = "ip route add " + server_ip + " via " + gateway + " dev " + iface + " 2>/dev/null";
            system(cmd.c_str());
        }
        // Теперь добавляем default через tun0
        setupClientRoutes(); // это добавляет default через tun0

        boost::system::error_code ec;
        auto ep = udp::endpoint(boost::asio::ip::address::from_string(server_ip, ec), server_port);
        if (ec) {
            syslog(LOG_ERR, "Invalid server IP: %s", server_ip.c_str());
            return false;
        }
        server_endpoint = ep;

        udp_socket.open(udp::v4());

        // Привязываем сокет к интерфейсу по умолчанию, чтобы пакеты не уходили в туннель
        if (!iface.empty()) {
            if (setsockopt(udp_socket.native_handle(), SOL_SOCKET, SO_BINDTODEVICE, iface.c_str(), iface.length()) < 0) {
                syslog(LOG_WARNING, "Failed to bind UDP socket to interface %s: %s", iface.c_str(), strerror(errno));
            } else {
                syslog(LOG_INFO, "UDP socket bound to interface %s", iface.c_str());
            }
        }

        syslog(LOG_INFO, "VPN Client initialized, server: %s:%d", server_ip.c_str(), server_port);
        return true;
    }

    void run() {
        syslog(LOG_INFO, "VPN Client starting...");
        last_keepalive = std::chrono::steady_clock::now();

        tun_thread = std::thread([this]() { tunReadLoop(); });
        startUdpRead();
        startKeepAliveTimer();
        startStatsTimer();

        io_thread = std::thread([this]() { io_context.run(); });
        syslog(LOG_INFO, "VPN Client running");
    }

    void stop() {
        running = false;
        io_context.stop();
        if (io_thread.joinable()) io_thread.join();
        if (tun_thread.joinable()) tun_thread.join();
        udp_socket.close();
        tun_device->close();
        syslog(LOG_INFO, "VPN Client stopped");
    }

   private:
    void tunReadLoop() {
        char buffer[BUFFER_SIZE];
        while (running) {
            int n = read(tun_device->getFd(), buffer, BUFFER_SIZE);
            if (n > 0) {
                std::vector<char> data(buffer, buffer + n);
                boost::asio::post(io_context, [this, data]() { this->onTunData(data.data(), data.size()); });
                syslog(LOG_DEBUG, "TUN read bytes: %d", n);
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                if (running) syslog(LOG_ERR, "TUN read error: %s", strerror(errno));
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    void startUdpRead() {
        if (!running) return;
        udp_socket.async_receive(boost::asio::buffer(udp_buffer), [this](const boost::system::error_code& ec, size_t bytes) {
            if (ec) {
                if (ec != boost::asio::error::operation_aborted) syslog(LOG_ERR, "UDP receive error: %s", ec.message().c_str());
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
                syslog(LOG_DEBUG, "Sent %zu bytes to server", sent_bytes);
            } catch (const std::exception& e) {
                syslog(LOG_ERR, "Failed to send to server: %s", e.what());
            }
        } else {
            syslog(LOG_DEBUG, "Dropped packet to local tunnel address: %s", dest_ip);
        }
    }

    void onUdpData(const char* data, size_t length) {
        if (length > 0) {
            tun_device->write(data, length);
            packets_received++;
            syslog(LOG_DEBUG, "Received %zu bytes from server", length);
        }
    }

    void sendKeepAlive() {
        try {
            udp_socket.send_to(boost::asio::buffer("", 0), server_endpoint);
            last_keepalive = std::chrono::steady_clock::now();
        } catch (const std::exception& e) {
            syslog(LOG_ERR, "Keep-alive failed: %s", e.what());
        }
    }

    void printStats() { syslog(LOG_INFO, "Stats: sent=%d, received=%d", packets_sent, packets_received); }
};

int main(int argc, char* argv[]) {
    initSyslog("vpn-client-main", LOG_DEBUG);
    signal(SIGINT, [](int) {
        syslog(LOG_INFO, "Received SIGINT");
        exit(0);
    });
    signal(SIGTERM, [](int) {
        syslog(LOG_INFO, "Received SIGTERM");
        exit(0);
    });

    if (geteuid() != 0) {
        syslog(LOG_ERR, "Must be run as root");
        closelog();
        return 1;
    }

    if (argc < 2) {
        syslog(LOG_ERR, "Usage: %s <server_ip> [port]", argv[0]);
        closelog();
        return 1;
    }

    std::string server_ip = argv[1];
    int port;
    port = atoi(argv[2]);
    if (port <= 0 || port > 65535) {
        syslog(LOG_ERR, "Invalid port: %s", argv[2]);
        closelog();
        return 1;
    }

    syslog(LOG_INFO, "Starting VPN Client connecting to %s:%d", server_ip.c_str(), port);

    VPNClient client(server_ip, port);
    if (!client.init()) {
        syslog(LOG_ERR, "Failed to initialize client");
        closelog();
        return 1;
    }

    client.run();
    while (true) std::this_thread::sleep_for(std::chrono::seconds(1));
    closeSyslog();
    return 0;
}