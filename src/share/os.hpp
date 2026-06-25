#pragma once
#include <string>

#define BUFFER_SIZE 65536
#define UDP_SOCKET_BUF_SIZE (8 * 1024 * 1024)

class Os {
   public:
    Os() = default;
    void tune_udp_socket(int fd, int size = UDP_SOCKET_BUF_SIZE);
    void setup_client_routes(std::string_view tun_name = "tun0");
    void setup_server_routes(std::string_view tun_name, std::string_view external_iface, std::size_t vpn_port);
    std::string get_default_interface();
    std::string get_default_gateway();
    void init_syslog(const char* ident, int log_level);
    void close_syslog();
};