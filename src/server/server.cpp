#include "../common/common.hpp"
#include <boost/asio.hpp>

class VPNServer {
private:
    boost::asio::io_context io_context;
    udp::socket udp_socket;
    udp::endpoint remote_endpoint;
    std::unique_ptr<TunDevice> tun_device;
    std::atomic<bool> running;

    std::map<std::string, udp::endpoint> clients;
    std::map<std::string, std::chrono::steady_clock::time_point> client_last_seen;
    std::array<char, BUFFER_SIZE> udp_buffer;

    std::thread io_thread;
    std::thread tun_thread;
    std::string external_iface;

public:
    VPNServer()
        : io_context(),
          udp_socket(io_context, udp::endpoint(udp::v4(), VPN_PORT)),
          running(true) {
        // initSyslog("vpn-server");
        external_iface = getDefaultInterface();
        tun_device = std::make_unique<TunDevice>();
    }

    ~VPNServer() { stop(); closeSyslog(); }

    bool init() {
        if (!tun_device->open("tun0", "192.168.200.1")) {
            syslog(LOG_ERR, "Failed to create TUN device");
            return false;
        }
        setupServerRoutes();
        char hostname[256];
        gethostname(hostname, sizeof(hostname));
        syslog(LOG_INFO, "VPN Server initialized on port %d", VPN_PORT);
        syslog(LOG_INFO, "Hostname: %s, Interface: %s", hostname, external_iface.c_str());
        return true;
    }

    void run() {
        syslog(LOG_INFO, "VPN Server starting...");
        tun_thread = std::thread([this]() { tunReadLoop(); });
        startUdpRead();
        startCleanupTimer();
        io_thread = std::thread([this]() { io_context.run(); });
        syslog(LOG_INFO, "VPN Server running");
    }

    void stop() {
        running = false;
        io_context.stop();
        if (io_thread.joinable()) io_thread.join();
        if (tun_thread.joinable()) tun_thread.join();
        udp_socket.close();
        tun_device->close();
        syslog(LOG_INFO, "VPN Server stopped");
    }

private:
    void tunReadLoop() {
        char buffer[BUFFER_SIZE];
        while (running) {
            int n = read(tun_device->getFd(), buffer, BUFFER_SIZE);
            if (n > 0) {
                std::vector<char> data(buffer, buffer + n);
                boost::asio::post(io_context, [this, data]() {
                    this->onTunData(data.data(), data.size());
                });
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                if (running) syslog(LOG_ERR, "TUN read error: %s", strerror(errno));
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    void startUdpRead() {
        if (!running) return;
        udp_socket.async_receive_from(
            boost::asio::buffer(udp_buffer),
            remote_endpoint,
            [this](const boost::system::error_code& ec, size_t bytes) {
                if (ec) {
                    if (ec != boost::asio::error::operation_aborted)
                        syslog(LOG_ERR, "UDP receive error: %s", ec.message().c_str());
                    return;
                }
                if (bytes > 0) {
                    syslog(LOG_ERR, "UDP receive bytes: %lu", bytes);
                    this->onUdpData(udp_buffer.data(), bytes, remote_endpoint);
                }
                if (running) startUdpRead();
            }
        );
    }

    void startCleanupTimer() {
        auto timer = std::make_shared<boost::asio::steady_timer>(
            io_context, std::chrono::seconds(10));
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
                syslog(LOG_DEBUG, "Forwarded packet to client %s (%zu bytes)", dest_ip, length);
            } catch (const std::exception& e) {
                syslog(LOG_ERR, "Failed to send to client: %s", e.what());
            }
        } else {
            syslog(LOG_DEBUG, "Packet for unknown client: %s", dest_ip);
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
                syslog(LOG_INFO, "New client connected: %s from %s:%d",
                       client_ip.c_str(),
                       endpoint.address().to_string().c_str(),
                       endpoint.port());
            }
            clients[client_ip] = endpoint;
            client_last_seen[client_ip] = std::chrono::steady_clock::now();
            if (!tun_device->write(data, length)) {
                syslog(LOG_ERR, "Failed to write packet to TUN");
            } else {
                syslog(LOG_DEBUG, "Successfully wrote to TUN");
            }
            syslog(LOG_DEBUG, "Forwarded packet from client %s (%zu bytes)", client_ip.c_str(), length);
        } else {
            syslog(LOG_DEBUG, "Packet from invalid source IP: %s", src_ip);
        }
    }

    void cleanupClients() {
        auto now = std::chrono::steady_clock::now();
        auto it = client_last_seen.begin();
        while (it != client_last_seen.end()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second);
            if (elapsed.count() > 60) {
                syslog(LOG_INFO, "Removing inactive client: %s", it->first.c_str());
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
    signal(SIGINT, [](int) { syslog(LOG_INFO, "Received SIGINT"); exit(0); });
    signal(SIGTERM, [](int) { syslog(LOG_INFO, "Received SIGTERM"); exit(0); });

    if (geteuid() != 0) {
        syslog(LOG_ERR, "Must be run as root");
        closelog();
        return 1;
    }

    int port = VPN_PORT;
    if (argc > 1) {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            syslog(LOG_ERR, "Invalid port: %s", argv[1]);
            closelog();
            return 1;
        }
    }

    syslog(LOG_INFO, "Starting VPN Server on port %d", port);
    VPNServer server;
    if (!server.init()) {
        syslog(LOG_ERR, "Failed to initialize server");
        closelog();
        return 1;
    }
    server.run();
    while (true) std::this_thread::sleep_for(std::chrono::seconds(1));
    closeSyslog();
    return 0;
}