#include "command.hpp"

#include <fcntl.h>
#include <spawn.h>
#include <sys/wait.h>

#include <cerrno>
#include <csignal>

#include "log.hpp"

extern char** environ;

namespace {

/**
 * @brief Атрибуты posix_spawn с освобождением в деструкторе.
 */
class SpawnAttrs {
   public:
    SpawnAttrs() {
        posix_spawnattr_init(&m_attr);
        posix_spawn_file_actions_init(&m_actions);
    }
    ~SpawnAttrs() {
        posix_spawn_file_actions_destroy(&m_actions);
        posix_spawnattr_destroy(&m_attr);
    }
    SpawnAttrs(const SpawnAttrs&) = delete;
    SpawnAttrs& operator=(const SpawnAttrs&) = delete;

    posix_spawn_file_actions_t m_actions;
    posix_spawnattr_t m_attr;
};

} // namespace

std::string command_to_string(const std::vector<std::string>& argv) {
    std::string out;
    for (const auto& a : argv) {
        if (!out.empty()) out += ' ';
        out += a;
    }
    return out;
}

int run_command(const std::vector<std::string>& argv, bool quiet) {
    if (argv.empty()) return -1;

    std::vector<char*> args;
    args.reserve(argv.size() + 1);
    for (const auto& a : argv) {
        args.push_back(const_cast<char*>(a.c_str()));
    }
    args.push_back(nullptr);

    SpawnAttrs sa;
    // маска наследуется через exec: без сброса ip/iptables не реагировали бы на SIGINT/SIGTERM
    sigset_t empty;
    sigemptyset(&empty);
    posix_spawnattr_setsigmask(&sa.m_attr, &empty);
    posix_spawnattr_setflags(&sa.m_attr, POSIX_SPAWN_SETSIGMASK);
    if (quiet) {
        posix_spawn_file_actions_addopen(&sa.m_actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
        posix_spawn_file_actions_addopen(&sa.m_actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    }

    pid_t pid = -1;
    int rc = ::posix_spawnp(&pid, args[0], &sa.m_actions, &sa.m_attr, args.data(), environ);
    if (rc != 0) {
        log_msg(LOG_ERR, "Не удалось запустить \"{}\": {}", command_to_string(argv), errno_str(rc));
        return -1;
    }

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            log_msg(LOG_ERR, "waitpid \"{}\": {}", command_to_string(argv), errno_str(errno));
            return -1;
        }
    }
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    if (code != 0 && !quiet) {
        log_msg(LOG_ERR, "Команда \"{}\" завершилась с кодом {}", command_to_string(argv), code);
    }
    return code;
}
