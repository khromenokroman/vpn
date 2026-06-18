#pragma once
#include <string_view>

class TunDevice {
   public:
    TunDevice();

    bool open(std::string_view name, std::string_view ip, size_t mtu);
    void close();
    int getFd() const;
    bool isOpen() const;
    int createTunDevice(std::string_view name, std::string_view ip, size_t mtu);

   private:
    std::size_t m_mtu = 1400;
    std::string_view m_tun_device{"/dev/net/tun"};
    int m_fd;
};