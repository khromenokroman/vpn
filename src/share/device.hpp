#pragma once
#include <string_view>

class TunDevice {
   public:
    TunDevice();

    bool open(std::string_view name, std::string_view ip, size_t mtu);
    void close();
    int get_fd() const;
    bool is_open() const;
    int create_tun_device(std::string_view name, std::string_view ip, size_t mtu);

   private:
    std::string_view m_tun_device{"/dev/net/tun"};
    int m_fd;
};