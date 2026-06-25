#pragma once

#include <arpa/inet.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>

#include "../share/crypto.hpp"
#include "../share/device.hpp"

class VPNServer {
   public:
    VPNServer(std::string_view tun_name, std::string_view tun_ip, std::size_t port, std::size_t mtu, std::string_view key);
    ~VPNServer();

    bool init();
    void run();
    void stop();

   private:
    struct ClientInfo {
        sockaddr_in addr;
        std::chrono::steady_clock::time_point last_seen;
    };

    void tun_to_udp_loop();
    void udp_to_tun_loop();
    void cleanup_loop();

    std::unordered_map<uint32_t, ClientInfo> m_clients;
    std::mutex m_clients_mutex;

    std::thread m_tun_to_udp_thread;
    std::thread m_udp_to_tun_thread;
    std::thread m_cleanup_thread;

    std::atomic<uint64_t> m_packets_to_clients{0};
    std::atomic<uint64_t> m_packets_from_clients{0};
    std::atomic<bool> m_running{true};

    Crypto m_crypto;
    TunDevice m_tun;

    std::string m_tun_name;
    std::string m_tun_ip;
    std::string m_external_iface;

    std::size_t m_port;
    std::size_t m_mtu;

    int m_udp_fd = -1;
};
