#pragma once

#include <arpa/inet.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

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
        int fd;
        sockaddr_in addr;
        std::chrono::steady_clock::time_point last_seen;
    };

    void tun_to_tcp_loop();
    void accept_loop();
    void client_reader_loop(int client_fd, sockaddr_in peer);
    void cleanup_loop();

    std::unordered_map<uint32_t, ClientInfo> m_clients;
    std::mutex m_clients_mutex;

    std::set<int> m_client_fds;
    std::mutex m_client_fds_mutex;

    std::vector<std::thread> m_client_threads;
    std::mutex m_client_threads_mutex;

    std::thread m_tun_to_tcp_thread;
    std::thread m_accept_thread;
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

    int m_tcp_fd = -1;
};
