#pragma once

#include <cstddef>
#include <string>

/**
 * @brief TUN-интерфейс (/dev/net/tun, без заголовка PI).
 *
 * Владеет дескриптором, не копируется.
 */
class TunDevice {
   public:
    TunDevice() = default;
    ~TunDevice();

    TunDevice(const TunDevice&) = delete;
    TunDevice& operator=(const TunDevice&) = delete;

    /**
     * @brief Создаёт интерфейс, назначает адрес /24 и MTU, поднимает его.
     * @param name имя интерфейса, короче IFNAMSIZ (15 символов)
     * @param ip IPv4-адрес интерфейса
     * @param mtu MTU интерфейса
     * @return false при ошибке (причина в syslog)
     */
    bool open(const std::string& name, const std::string& ip, std::size_t mtu);

    /** @brief Закрывает дескриптор; повторный вызов безопасен. */
    void close() noexcept;

    /** @brief Дескриптор или -1. */
    int get_fd() const noexcept { return m_fd; }

    /** @brief Открыт ли интерфейс. */
    bool is_open() const noexcept { return m_fd >= 0; }

   private:
    int m_fd = -1;
};
