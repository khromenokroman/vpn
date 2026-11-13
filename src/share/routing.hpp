#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "net.hpp"

/** @brief Команда: программа и аргументы. */
using Argv = std::vector<std::string>;

/**
 * @brief Правило iptables без операции (-A/-I/-D).
 */
struct IptablesRule {
    std::string table; ///< таблица; пустая - filter
    std::string chain; ///< цепочка
    bool insert_first; ///< добавлять в начало цепочки (-I 1), иначе в конец (-A)
    Argv spec;         ///< условия и цель

    /** @brief Команда добавления. */
    Argv add_argv() const;
    /** @brief Команда удаления. */
    Argv delete_argv() const;
};

/**
 * @brief Правила NAT сервера.
 *
 * MASQUERADE подсети туннеля на внешнем интерфейсе, пропуск из туннеля наружу, обратно - только ответы
 * (conntrack RELATED,ESTABLISHED), приём UDP на порт VPN.
 *
 * @param tun имя TUN-интерфейса
 * @param external внешний интерфейс
 * @param subnet подсеть туннеля, "a.b.c.0/24"
 * @param port UDP-порт сервера
 */
std::vector<IptablesRule> server_nat_rules(const std::string& tun, const std::string& external, const std::string& subnet, std::uint16_t port);

/**
 * @brief Правила iptables сервера: добавляет при apply(), удаляет добавленные в деструкторе.
 */
class NatRules {
   public:
    explicit NatRules(std::vector<IptablesRule> rules) : m_rules(std::move(rules)) {}
    ~NatRules() { remove(); }

    NatRules(const NatRules&) = delete;
    NatRules& operator=(const NatRules&) = delete;

    /**
     * @brief Убирает такие же правила от прошлого запуска (например, после SIGKILL) и добавляет свои.
     * @return false, если правило не добавилось; уже добавленные удалит деструктор
     */
    bool apply();

    /** @brief Удаляет добавленные правила; повторный вызов безопасен. */
    void remove() noexcept;

   private:
    std::vector<IptablesRule> m_rules;
    std::size_t m_applied = 0;
};

/**
 * @brief Маршруты клиента для заданного шлюза.
 *
 * Маршрут до сервера через исходный шлюз и два маршрута 0.0.0.0/1 и 128.0.0.0/1 через TUN. Они точнее
 * маршрута по умолчанию и перехватывают весь трафик, не трогая сам default: при аварийном завершении
 * ядро удаляет их вместе с TUN-интерфейсом, и прежний маршрут снова работает.
 *
 * @param server_ip адрес сервера
 * @param route маршрут по умолчанию до запуска VPN
 * @param tun имя TUN-интерфейса
 * @return команды добавления
 */
std::vector<Argv> client_route_add_cmds(const std::string& server_ip, const DefaultRoute& route, const std::string& tun);

/** @brief Команды удаления маршрутов из client_route_add_cmds в обратном порядке. */
std::vector<Argv> client_route_del_cmds(const std::string& server_ip, const std::string& tun);

/**
 * @brief Маршруты клиента: добавляет при apply(), удаляет в деструкторе.
 */
class ClientRoutes {
   public:
    ClientRoutes(std::string server_ip, DefaultRoute route, std::string tun)
        : m_server_ip(std::move(server_ip)), m_tun(std::move(tun)), m_route(std::move(route)) {}
    ~ClientRoutes() { remove(); }

    ClientRoutes(const ClientRoutes&) = delete;
    ClientRoutes& operator=(const ClientRoutes&) = delete;

    /** @return false, если маршрут не добавился; уже добавленные удалит деструктор */
    bool apply();

    /** @brief Удаляет добавленные маршруты; повторный вызов безопасен. */
    void remove() noexcept;

   private:
    std::string m_server_ip;
    std::string m_tun;
    DefaultRoute m_route;
    bool m_applied = false;
};
