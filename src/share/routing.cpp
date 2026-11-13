#include "routing.hpp"

#include <syslog.h>

#include "command.hpp"
#include "log.hpp"

namespace {

/** @brief Предел удалений одного правила: защита от бесконечного цикла, если -D не удаляет. */
constexpr int MAX_STALE_RULES = 16;

Argv iptables_base(const IptablesRule& rule) {
    // -w: ждать блокировку xtables, если её держит другой процесс (firewalld, docker)
    Argv argv{"iptables", "-w"};
    if (!rule.table.empty()) {
        argv.insert(argv.end(), {"-t", rule.table});
    }
    return argv;
}

} // namespace

Argv IptablesRule::add_argv() const {
    Argv argv = iptables_base(*this);
    if (insert_first) {
        argv.insert(argv.end(), {"-I", chain, "1"});
    } else {
        argv.insert(argv.end(), {"-A", chain});
    }
    argv.insert(argv.end(), spec.begin(), spec.end());
    return argv;
}

Argv IptablesRule::delete_argv() const {
    Argv argv = iptables_base(*this);
    argv.insert(argv.end(), {"-D", chain});
    argv.insert(argv.end(), spec.begin(), spec.end());
    return argv;
}

std::vector<IptablesRule> server_nat_rules(const std::string& tun, const std::string& external, const std::string& subnet, std::uint16_t port) {
    return {
        {"nat", "POSTROUTING", false, {"-s", subnet, "-o", external, "-j", "MASQUERADE"}},
        {"", "FORWARD", false, {"-i", tun, "-o", external, "-j", "ACCEPT"}},
        {"", "FORWARD", false, {"-i", external, "-o", tun, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}},
        {"", "INPUT", true, {"-p", "udp", "--dport", std::to_string(port), "-j", "ACCEPT"}},
    };
}

bool NatRules::apply() {
    for (const auto& rule : m_rules) {
        for (int i = 0; i < MAX_STALE_RULES && run_command(rule.delete_argv(), true) == 0; ++i) {
            log_msg(LOG_INFO, "Удалено правило прошлого запуска: {}", command_to_string(rule.delete_argv()));
        }
    }
    for (const auto& rule : m_rules) {
        if (run_command(rule.add_argv()) != 0) {
            log_msg(LOG_ERR, "Не удалось добавить правило iptables: {}", command_to_string(rule.add_argv()));
            return false;
        }
        ++m_applied;
    }
    return true;
}

void NatRules::remove() noexcept {
    try {
        while (m_applied > 0) {
            --m_applied;
            const auto& rule = m_rules[m_applied];
            if (run_command(rule.delete_argv(), true) != 0) {
                log_msg(LOG_WARNING, "Не удалось удалить правило iptables: {}", command_to_string(rule.delete_argv()));
            }
        }
    } catch (...) {
        // деструктор не должен бросать; bad_alloc при выходе ничего не меняет
    }
}

std::vector<Argv> client_route_add_cmds(const std::string& server_ip, const DefaultRoute& route, const std::string& tun) {
    Argv to_server{"ip", "route", "replace", server_ip + "/32"};
    if (!route.gateway.empty()) {
        to_server.insert(to_server.end(), {"via", route.gateway});
    }
    to_server.insert(to_server.end(), {"dev", route.iface});
    return {
        to_server,
        {"ip", "route", "replace", "0.0.0.0/1", "dev", tun},
        {"ip", "route", "replace", "128.0.0.0/1", "dev", tun},
    };
}

std::vector<Argv> client_route_del_cmds(const std::string& server_ip, const std::string& tun) {
    return {
        {"ip", "route", "del", "128.0.0.0/1", "dev", tun},
        {"ip", "route", "del", "0.0.0.0/1", "dev", tun},
        {"ip", "route", "del", server_ip + "/32"},
    };
}

bool ClientRoutes::apply() {
    m_applied = true;
    for (const auto& cmd : client_route_add_cmds(m_server_ip, m_route, m_tun)) {
        if (run_command(cmd) != 0) return false;
    }
    log_msg(LOG_INFO, "Весь трафик идёт через {}, сервер {} через {}{}", m_tun, m_server_ip, m_route.iface,
            m_route.gateway.empty() ? std::string{} : " via " + m_route.gateway);
    return true;
}

void ClientRoutes::remove() noexcept {
    if (!m_applied) return;
    m_applied = false;
    try {
        // маршруты через TUN ядро удалит вместе с интерфейсом, ошибки удаления не важны
        for (const auto& cmd : client_route_del_cmds(m_server_ip, m_tun)) {
            run_command(cmd, true);
        }
        log_msg(LOG_INFO, "Маршруты VPN удалены");
    } catch (...) {
    }
}
