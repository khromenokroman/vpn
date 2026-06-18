#pragma once
#include <string>

#define BUFFER_SIZE 65536
#define UDP_SOCKET_BUF_SIZE (8 * 1024 * 1024)

class Os {
   public:
    Os() = default;
    void tuneUdpSocket(int fd, int size = UDP_SOCKET_BUF_SIZE);
    void setupClientRoutes(std::string_view tun_name = "tun0");
    void setupServerRoutes(std::string_view tun_name, std::string_view external_iface, std::size_t vpn_port);
    std::string getDefaultInterface();
    std::string getDefaultGateway();
    void initSyslog(const char* ident, int log_level);
    void closeSyslog();
};